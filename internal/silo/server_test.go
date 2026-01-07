package silo

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// newTestServer creates a Server backed by temporary filesystem and SQLite DB.
func newTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()

	dataDir := t.TempDir()

	srv, err := NewServer(Config{DataDir: dataDir})
	require.NoError(t, err, "NewServer error")

	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { _ = srv.Close() })
	t.Cleanup(httpSrv.Close)

	return srv, httpSrv
}

func TestCreateAndListBuckets(t *testing.T) {
	t.Parallel()

	_, httpSrv := newTestServer(t)

	client := httpSrv.Client()

	for _, b := range []string{"bucket1", "bucket2"} {
		req, err := http.NewRequest(http.MethodPut, httpSrv.URL+"/"+b, nil)
		require.NoError(t, err, "creating PUT request")
		resp, err := client.Do(req)
		require.NoErrorf(t, err, "PUT bucket %s error", b)
		resp.Body.Close()
		require.Equalf(t, http.StatusOK, resp.StatusCode, "PUT bucket %s status", b)
	}

	// List buckets
	resp, err := client.Get(httpSrv.URL + "/")
	require.NoError(t, err, "GET / error")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET / status")

	var listResp ListAllMyBucketsResult
	require.NoError(t, xml.NewDecoder(resp.Body).Decode(&listResp), "decoding ListAllMyBucketsResult")

	found := map[string]bool{}
	for _, b := range listResp.Buckets {
		found[b.Name] = true
	}
	for _, want := range []string{"bucket1", "bucket2"} {
		require.Truef(t, found[want], "expected bucket %q in ListAllMyBucketsResult", want)
	}
}

func TestInvalidBucketNames(t *testing.T) {
	t.Parallel()
	_, httpSrv := newTestServer(t)
	client := httpSrv.Client()

	tests := []struct {
		name   string
		bucket string
	}{
		{name: "too short", bucket: "ab"},
		{name: "too long", bucket: strings.Repeat("a", 64)},
		{name: "uppercase", bucket: "BadBucket"},
		{name: "ip address", bucket: "192.168.0.1"},
		{name: "leading dash", bucket: "-bucket"},
	}

	for _, tc := range tests {
		// capture range variable
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPut, httpSrv.URL+"/"+tc.bucket, nil)
			require.NoError(t, err, "creating PUT request")

			resp, err := client.Do(req)
			require.NoError(t, err, "PUT bucket error")
			defer resp.Body.Close()

			require.Equal(t, http.StatusBadRequest, resp.StatusCode, "status code")

			var s3Err struct {
				Code string `xml:"Code"`
			}
			require.NoError(t, xml.NewDecoder(resp.Body).Decode(&s3Err), "decoding S3 error XML")
			require.Equal(t, "InvalidBucketName", s3Err.Code, "S3 error code")
		})
	}
}

func TestPutGetHeadDeleteObject(t *testing.T) {
	t.Parallel()

	_, httpSrv := newTestServer(t)
	client := httpSrv.Client()

	bucket := "test-bucket"
	key := "dir1/object.txt"
	body := []byte("hello world")

	// PUT object (this will auto-create the bucket).
	req, err := http.NewRequest(http.MethodPut, httpSrv.URL+"/"+bucket+"/"+key, io.NopCloser(bytes.NewReader(body)))
	require.NoError(t, err, "creating PUT object request")
	req.Header.Set("Content-Type", "text/plain")

	resp, err := client.Do(req)
	require.NoError(t, err, "PUT object error")
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT object status")

	require.NotEmpty(t, resp.Header.Get("ETag"), "expected ETag header on PUT response")

	// GET object
	resp, err = client.Get(httpSrv.URL + "/" + bucket + "/" + key)
	require.NoError(t, err, "GET object error")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET object status")

	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "reading GET body")
	require.Equal(t, string(body), string(data), "GET object body")

	// HEAD object
	headReq, err := http.NewRequest(http.MethodHead, httpSrv.URL+"/"+bucket+"/"+key, nil)
	require.NoError(t, err, "creating HEAD request")
	headResp, err := client.Do(headReq)
	require.NoError(t, err, "HEAD object error")
	headResp.Body.Close()
	require.Equal(t, http.StatusOK, headResp.StatusCode, "HEAD object status")
	require.Equal(t, "text/plain", headResp.Header.Get("Content-Type"), "HEAD Content-Type")
	require.Equal(t, "11", headResp.Header.Get("Content-Length"), "HEAD Content-Length")

	// DELETE object
	delReq, err := http.NewRequest(http.MethodDelete, httpSrv.URL+"/"+bucket+"/"+key, nil)
	require.NoError(t, err, "creating DELETE request")
	delResp, err := client.Do(delReq)
	require.NoError(t, err, "DELETE object error")
	delResp.Body.Close()
	require.Equal(t, http.StatusNoContent, delResp.StatusCode, "DELETE object status")

	// GET after delete should return 404.
	resp, err = client.Get(httpSrv.URL + "/" + bucket + "/" + key)
	require.NoError(t, err, "GET deleted object error")
	resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode, "GET deleted object status")
}

func TestObjectStoredBySHA256Path(t *testing.T) {
	srv, httpSrv := newTestServer(t)
	client := httpSrv.Client()

	bucket := "sha-bucket"
	key := "file.bin"
	body := []byte("abc123")

	// PUT object
	req, err := http.NewRequest(http.MethodPut, httpSrv.URL+"/"+bucket+"/"+key, io.NopCloser(bytes.NewReader(body)))
	require.NoError(t, err, "creating PUT request")
	resp, err := client.Do(req)
	require.NoError(t, err, "PUT object error")
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT object status")

	// Compute expected SHA-256-based path.
	sum := sha256.Sum256(body)
	hashHex := hex.EncodeToString(sum[:])
	subdir := hashHex[:2]
	objPath := filepath.Join(srv.cfg.DataDir, bucket, subdir, hashHex)

	_, err = os.Stat(objPath)
	require.NoErrorf(t, err, "expected object file at %s", objPath)
}

func TestListObjects(t *testing.T) {
	t.Parallel()

	_, httpSrv := newTestServer(t)
	client := httpSrv.Client()

	bucket := "list-bucket"

	// Create the bucket first.
	req, err := http.NewRequest(http.MethodPut, httpSrv.URL+"/"+bucket, nil)
	require.NoError(t, err, "creating PUT bucket request")
	resp, err := client.Do(req)
	require.NoError(t, err, "PUT bucket error")
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT bucket status")

	// Upload objects with and without the prefix.
	keys := []string{"dir/a.txt", "dir/b.txt", "other.txt"}
	for _, key := range keys {
		putReq, err := http.NewRequest(http.MethodPut, httpSrv.URL+"/"+bucket+"/"+key, io.NopCloser(bytes.NewReader([]byte(key))))
		require.NoError(t, err, "creating PUT object request")
		putResp, err := client.Do(putReq)
		require.NoError(t, err, "PUT object error")
		putResp.Body.Close()
		require.Equal(t, http.StatusOK, putResp.StatusCode, "PUT object status")
	}

	// List without prefix should see all objects.
	resp, err = client.Get(httpSrv.URL + "/" + bucket)
	require.NoError(t, err, "GET bucket error")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET bucket status")

	var listResp ListBucketResult
	require.NoError(t, xml.NewDecoder(resp.Body).Decode(&listResp), "decoding ListBucketResult")
	require.Len(t, listResp.Contents, 3, "expected all objects without prefix filter")

	// List with prefix should only return the two prefixed keys.
	resp, err = client.Get(httpSrv.URL + "/" + bucket + "?prefix=dir/")
	require.NoError(t, err, "GET bucket with prefix error")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET bucket with prefix status")

	var listRespWithPrefix ListBucketResult
	require.NoError(t, xml.NewDecoder(resp.Body).Decode(&listRespWithPrefix), "decoding ListBucketResult with prefix")
	require.Len(t, listRespWithPrefix.Contents, 2, "expected only prefixed objects")
	require.Equal(t, "dir/a.txt", listRespWithPrefix.Contents[0].Key, "first key with prefix")
	require.Equal(t, "dir/b.txt", listRespWithPrefix.Contents[1].Key, "second key with prefix")
}

func TestGetBucketLocation(t *testing.T) {
	t.Parallel()

	_, httpSrv := newTestServer(t)
	client := httpSrv.Client()

	bucket := "location-bucket"

	// Create the bucket first.
	req, err := http.NewRequest(http.MethodPut, httpSrv.URL+"/"+bucket, nil)
	require.NoError(t, err, "creating PUT bucket request")
	resp, err := client.Do(req)
	require.NoError(t, err, "PUT bucket error")
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT bucket status")

	// Now fetch its location.
	resp, err = client.Get(httpSrv.URL + "/" + bucket + "?location")
	require.NoError(t, err, "GET bucket location error")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET bucket location status")

	var loc struct {
		Region string `xml:",chardata"`
	}
	require.NoError(t, xml.NewDecoder(resp.Body).Decode(&loc), "decoding LocationConstraint")
	require.Equal(t, "us-east-1", strings.TrimSpace(loc.Region), "bucket region")
}

func TestCopyObjectWithinBucket(t *testing.T) {
	t.Parallel()

	srv, httpSrv := newTestServer(t)
	client := httpSrv.Client()

	bucket := "copy-bucket"
	srcKey := "src.txt"
	dstKey := "dst.txt"
	body := []byte("copy-me")

	// PUT source object (auto-creates bucket).
	req, err := http.NewRequest(http.MethodPut, httpSrv.URL+"/"+bucket+"/"+srcKey, io.NopCloser(bytes.NewReader(body)))
	require.NoError(t, err, "creating PUT source request")
	resp, err := client.Do(req)
	require.NoError(t, err, "PUT source error")
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT source status")

	// Copy within the same bucket using x-amz-copy-source.
	copyReq, err := http.NewRequest(http.MethodPut, httpSrv.URL+"/"+bucket+"/"+dstKey, nil)
	require.NoError(t, err, "creating CopyObject request")
	copyReq.Header.Set("x-amz-copy-source", "/"+bucket+"/"+srcKey)
	copyResp, err := client.Do(copyReq)
	require.NoError(t, err, "CopyObject error")
	copyResp.Body.Close()
	require.Equal(t, http.StatusOK, copyResp.StatusCode, "CopyObject status")

	// GET destination should return the same payload.
	getResp, err := client.Get(httpSrv.URL + "/" + bucket + "/" + dstKey)
	require.NoError(t, err, "GET copied object error")
	defer getResp.Body.Close()
	require.Equal(t, http.StatusOK, getResp.StatusCode, "GET copied object status")

	data, err := io.ReadAll(getResp.Body)
	require.NoError(t, err, "reading copied object body")
	require.Equal(t, body, data, "copied payload mismatch")

	// Verify that the payload file exists in the expected location for this bucket.
	sum := sha256.Sum256(body)
	hashHex := hex.EncodeToString(sum[:])
	subdir := hashHex[:2]
	path := filepath.Join(srv.cfg.DataDir, bucket, subdir, hashHex)

	info, err := os.Stat(path)
	require.NoError(t, err, "expected payload file to exist")
	require.False(t, info.IsDir(), "payload path should be a file")
}

func TestCopyObjectAcrossBucketsCreatesHardLink(t *testing.T) {
	t.Parallel()

	srv, httpSrv := newTestServer(t)
	client := httpSrv.Client()

	srcBucket := "src-bucket"
	dstBucket := "dst-bucket"
	key := "file.bin"
	body := []byte("shared-copy-payload")

	// PUT source object into src bucket.
	req, err := http.NewRequest(http.MethodPut, httpSrv.URL+"/"+srcBucket+"/"+key, io.NopCloser(bytes.NewReader(body)))
	require.NoError(t, err, "creating PUT source request")
	resp, err := client.Do(req)
	require.NoError(t, err, "PUT source error")
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT source status")

	// Copy to destination bucket.
	copyReq, err := http.NewRequest(http.MethodPut, httpSrv.URL+"/"+dstBucket+"/"+key, nil)
	require.NoError(t, err, "creating CopyObject request")
	copyReq.Header.Set("x-amz-copy-source", "/"+srcBucket+"/"+key)
	copyResp, err := client.Do(copyReq)
	require.NoError(t, err, "CopyObject error")
	copyResp.Body.Close()
	require.Equal(t, http.StatusOK, copyResp.StatusCode, "CopyObject status")

	// Both buckets should reference hard-linked files on disk.
	sum := sha256.Sum256(body)
	hashHex := hex.EncodeToString(sum[:])
	subdir := hashHex[:2]
	pathSrc := filepath.Join(srv.cfg.DataDir, srcBucket, subdir, hashHex)
	pathDst := filepath.Join(srv.cfg.DataDir, dstBucket, subdir, hashHex)

	infoSrc, err := os.Stat(pathSrc)
	require.NoError(t, err, "expected source payload file")
	infoDst, err := os.Stat(pathDst)
	require.NoError(t, err, "expected dest payload file")

	require.Equal(t, infoSrc.Size(), infoDst.Size(), "sizes should match for hard-linked files")
	require.True(t, os.SameFile(infoSrc, infoDst), "files should be hard-linked (same inode)")
}

func TestGetObjectMissingPayloadReturnsInternalError(t *testing.T) {
	t.Parallel()

	srv, httpSrv := newTestServer(t)
	client := httpSrv.Client()

	bucket := "missing-payload-bucket"
	key := "file.bin"
	body := []byte("payload-to-delete")

	// PUT object (auto-creates bucket and metadata).
	req, err := http.NewRequest(http.MethodPut, httpSrv.URL+"/"+bucket+"/"+key, io.NopCloser(bytes.NewReader(body)))
	require.NoError(t, err, "creating PUT request")
	resp, err := client.Do(req)
	require.NoError(t, err, "PUT object error")
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT object status")

	// Delete the underlying payload file from disk while leaving metadata.
	sum := sha256.Sum256(body)
	hashHex := hex.EncodeToString(sum[:])
	subdir := hashHex[:2]
	objPath := filepath.Join(srv.cfg.DataDir, bucket, subdir, hashHex)
	require.NoError(t, os.Remove(objPath), "removing payload file")

	// GET should now fail with 500 Internal Server Error due to missing payload.
	getResp, err := client.Get(httpSrv.URL + "/" + bucket + "/" + key)
	require.NoError(t, err, "GET object error")
	defer getResp.Body.Close()
	require.Equal(t, http.StatusInternalServerError, getResp.StatusCode, "GET status for missing payload")
}

func TestCopyObjectMissingSourceObjectReturnsNoSuchKey(t *testing.T) {
	t.Parallel()

	_, httpSrv := newTestServer(t)
	client := httpSrv.Client()

	srcBucket := "src-bucket-missing"
	dstBucket := "dst-bucket-missing"
	key := "file.bin"

	// Do not PUT any source object; CopyObject should fail with NoSuchKey.
	copyReq, err := http.NewRequest(http.MethodPut, httpSrv.URL+"/"+dstBucket+"/"+key, nil)
	require.NoError(t, err, "creating CopyObject request")
	copyReq.Header.Set("x-amz-copy-source", "/"+srcBucket+"/"+key)

	copyResp, err := client.Do(copyReq)
	require.NoError(t, err, "CopyObject error")
	defer copyResp.Body.Close()

	require.Equal(t, http.StatusNotFound, copyResp.StatusCode, "CopyObject status for missing source")

	var s3Err struct {
		Code string `xml:"Code"`
	}
	require.NoError(t, xml.NewDecoder(copyResp.Body).Decode(&s3Err), "decoding S3 error XML")
	require.Equal(t, "NoSuchKey", s3Err.Code, "expected NoSuchKey error code")
}

func TestCopyObjectWithInvalidSourceHeaderReturnsInvalidRequest(t *testing.T) {
	t.Parallel()

	_, httpSrv := newTestServer(t)
	client := httpSrv.Client()

	dstBucket := "dst-bucket-invalid-source"
	key := "file.bin"

	copyReq, err := http.NewRequest(http.MethodPut, httpSrv.URL+"/"+dstBucket+"/"+key, nil)
	require.NoError(t, err, "creating CopyObject request")
	// Missing bucket/key separator; handler should consider this invalid.
	copyReq.Header.Set("x-amz-copy-source", "invalid-source")

	copyResp, err := client.Do(copyReq)
	require.NoError(t, err, "CopyObject error")
	defer copyResp.Body.Close()

	require.Equal(t, http.StatusBadRequest, copyResp.StatusCode, "CopyObject status for invalid source header")

	var s3Err struct {
		Code string `xml:"Code"`
	}
	require.NoError(t, xml.NewDecoder(copyResp.Body).Decode(&s3Err), "decoding S3 error XML")
	require.Equal(t, "InvalidRequest", s3Err.Code, "expected InvalidRequest error code")
}

func TestCopyObjectMissingPayloadOnSourceReturnsInternalError(t *testing.T) {
	t.Parallel()

	srv, httpSrv := newTestServer(t)
	client := httpSrv.Client()

	srcBucket := "src-bucket-missing-payload"
	dstBucket := "dst-bucket-missing-payload"
	key := "file.bin"
	body := []byte("payload-to-delete-for-copy")

	// PUT source object.
	req, err := http.NewRequest(http.MethodPut, httpSrv.URL+"/"+srcBucket+"/"+key, io.NopCloser(bytes.NewReader(body)))
	require.NoError(t, err, "creating PUT source request")
	resp, err := client.Do(req)
	require.NoError(t, err, "PUT source error")
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT source status")

	// Delete the underlying payload file for the source object.
	sum := sha256.Sum256(body)
	hashHex := hex.EncodeToString(sum[:])
	subdir := hashHex[:2]
	srcPath := filepath.Join(srv.cfg.DataDir, srcBucket, subdir, hashHex)
	require.NoError(t, os.Remove(srcPath), "removing source payload file")

	// Attempt to CopyObject; metadata exists but payload is gone.
	copyReq, err := http.NewRequest(http.MethodPut, httpSrv.URL+"/"+dstBucket+"/"+key, nil)
	require.NoError(t, err, "creating CopyObject request")
	copyReq.Header.Set("x-amz-copy-source", "/"+srcBucket+"/"+key)

	copyResp, err := client.Do(copyReq)
	require.NoError(t, err, "CopyObject error")
	defer copyResp.Body.Close()

	require.Equal(t, http.StatusInternalServerError, copyResp.StatusCode, "CopyObject status for missing payload on source")
}

func TestListObjectsV2Pagination(t *testing.T) {
	t.Parallel()

	_, httpSrv := newTestServer(t)
	client := httpSrv.Client()

	bucket := "listv2-bucket"

	// Create the bucket first.
	req, err := http.NewRequest(http.MethodPut, httpSrv.URL+"/"+bucket, nil)
	require.NoError(t, err, "creating PUT bucket request")
	resp, err := client.Do(req)
	require.NoError(t, err, "PUT bucket error")
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT bucket status")

	// Upload three objects.
	keys := []string{"a.txt", "b.txt", "c.txt"}
	for _, key := range keys {
		putReq, err := http.NewRequest(http.MethodPut, httpSrv.URL+"/"+bucket+"/"+key, io.NopCloser(bytes.NewReader([]byte(key))))
		require.NoError(t, err, "creating PUT object request")
		putResp, err := client.Do(putReq)
		require.NoError(t, err, "PUT object error")
		putResp.Body.Close()
		require.Equal(t, http.StatusOK, putResp.StatusCode, "PUT object status")
	}

	// First page: max-keys=2
	listURL, err := url.Parse(httpSrv.URL + "/" + bucket)
	require.NoError(t, err, "parsing list URL")
	q := listURL.Query()
	q.Set("list-type", "2")
	q.Set("max-keys", "2")
	listURL.RawQuery = q.Encode()

	resp, err = client.Get(listURL.String())
	require.NoError(t, err, "GET ListObjectsV2 page 1 error")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "ListObjectsV2 page 1 status")

	var v2Resp ListBucketResultV2
	require.NoError(t, xml.NewDecoder(resp.Body).Decode(&v2Resp), "decoding ListBucketResultV2 page 1")
	require.Equal(t, 2, v2Resp.KeyCount, "KeyCount page 1")
	require.True(t, v2Resp.IsTruncated, "IsTruncated page 1")
	require.Len(t, v2Resp.Contents, 2, "Contents length page 1")
	require.Equal(t, "a.txt", v2Resp.Contents[0].Key, "first key page 1")
	require.Equal(t, "b.txt", v2Resp.Contents[1].Key, "second key page 1")
	require.NotEmpty(t, v2Resp.NextContinuationToken, "NextContinuationToken page 1")

	// Second page using continuation-token
	listURL2, err := url.Parse(httpSrv.URL + "/" + bucket)
	require.NoError(t, err, "parsing list URL 2")
	q2 := listURL2.Query()
	q2.Set("list-type", "2")
	q2.Set("continuation-token", v2Resp.NextContinuationToken)
	listURL2.RawQuery = q2.Encode()

	resp2, err := client.Get(listURL2.String())
	require.NoError(t, err, "GET ListObjectsV2 page 2 error")
	defer resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode, "ListObjectsV2 page 2 status")

	var v2Resp2 ListBucketResultV2
	require.NoError(t, xml.NewDecoder(resp2.Body).Decode(&v2Resp2), "decoding ListBucketResultV2 page 2")
	require.Equal(t, 1, v2Resp2.KeyCount, "KeyCount page 2")
	require.False(t, v2Resp2.IsTruncated, "IsTruncated page 2")
	require.Len(t, v2Resp2.Contents, 1, "Contents length page 2")
	require.Equal(t, "c.txt", v2Resp2.Contents[0].Key, "first key page 2")
}

func TestListObjectsV2PrefixAndStartAfter(t *testing.T) {
	t.Parallel()

	_, httpSrv := newTestServer(t)
	client := httpSrv.Client()

	bucket := "listv2-prefix-bucket"

	// Create the bucket first.
	req, err := http.NewRequest(http.MethodPut, httpSrv.URL+"/"+bucket, nil)
	require.NoError(t, err, "creating PUT bucket request")
	resp, err := client.Do(req)
	require.NoError(t, err, "PUT bucket error")
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT bucket status")

	// Upload objects with and without the prefix.
	keys := []string{"dir/a.txt", "dir/b.txt", "other.txt"}
	for _, key := range keys {
		putReq, err := http.NewRequest(http.MethodPut, httpSrv.URL+"/"+bucket+"/"+key, io.NopCloser(bytes.NewReader([]byte(key))))
		require.NoError(t, err, "creating PUT object request")
		putResp, err := client.Do(putReq)
		require.NoError(t, err, "PUT object error")
		putResp.Body.Close()
		require.Equal(t, http.StatusOK, putResp.StatusCode, "PUT object status")
	}

	// List with prefix=dir/ should only return the two prefixed keys.
	listURL, err := url.Parse(httpSrv.URL + "/" + bucket)
	require.NoError(t, err, "parsing list URL")
	q := listURL.Query()
	q.Set("list-type", "2")
	q.Set("prefix", "dir/")
	q.Set("max-keys", "10")
	listURL.RawQuery = q.Encode()

	resp, err = client.Get(listURL.String())
	require.NoError(t, err, "GET ListObjectsV2 with prefix error")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "ListObjectsV2 with prefix status")

	var v2Resp ListBucketResultV2
	require.NoError(t, xml.NewDecoder(resp.Body).Decode(&v2Resp), "decoding ListBucketResultV2 with prefix")
	require.Equal(t, 2, v2Resp.KeyCount, "KeyCount with prefix")
	require.False(t, v2Resp.IsTruncated, "IsTruncated with prefix")
	require.Len(t, v2Resp.Contents, 2, "Contents length with prefix")
	require.Equal(t, "dir/a.txt", v2Resp.Contents[0].Key, "first key with prefix")
	require.Equal(t, "dir/b.txt", v2Resp.Contents[1].Key, "second key with prefix")

	// Now use start-after within the same prefix to skip the first key.
	listURL2, err := url.Parse(httpSrv.URL + "/" + bucket)
	require.NoError(t, err, "parsing list URL 2")
	q2 := listURL2.Query()
	q2.Set("list-type", "2")
	q2.Set("prefix", "dir/")
	q2.Set("start-after", "dir/a.txt")
	q2.Set("max-keys", "10")
	listURL2.RawQuery = q2.Encode()

	resp2, err := client.Get(listURL2.String())
	require.NoError(t, err, "GET ListObjectsV2 with start-after error")
	defer resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode, "ListObjectsV2 with start-after status")

	var v2Resp2 ListBucketResultV2
	require.NoError(t, xml.NewDecoder(resp2.Body).Decode(&v2Resp2), "decoding ListBucketResultV2 with start-after")
	require.Equal(t, 1, v2Resp2.KeyCount, "KeyCount with start-after")
	require.False(t, v2Resp2.IsTruncated, "IsTruncated with start-after")
	require.Len(t, v2Resp2.Contents, 1, "Contents length with start-after")
	require.Equal(t, "dir/b.txt", v2Resp2.Contents[0].Key, "first key with start-after")
}

func TestErrorResponsesTableDriven(t *testing.T) {
	t.Parallel()

	_, httpSrv := newTestServer(t)
	client := httpSrv.Client()

	tests := []struct {
		name           string
		method         string
		path           string
		wantStatusCode int
		wantErrorCode  string
		expectBody     bool
	}{
		{
			name:           "NoSuchBucket on HeadBucket",
			method:         http.MethodHead,
			path:           "/nonexistent-bucket",
			wantStatusCode: http.StatusNotFound,
			wantErrorCode:  "NoSuchBucket",
			expectBody:     false,
		},
		{
			name:           "NoSuchBucket on ListObjects",
			method:         http.MethodGet,
			path:           "/nonexistent-bucket",
			wantStatusCode: http.StatusNotFound,
			wantErrorCode:  "NoSuchBucket",
			expectBody:     true,
		},
		{
			name:           "NoSuchKey on GET object",
			method:         http.MethodGet,
			path:           "/some-bucket/missing-key",
			wantStatusCode: http.StatusNotFound,
			wantErrorCode:  "NoSuchKey",
			expectBody:     true,
		},
		{
			name:           "NoSuchKey on HEAD object",
			method:         http.MethodHead,
			path:           "/some-bucket/missing-key",
			wantStatusCode: http.StatusNotFound,
			wantErrorCode:  "NoSuchKey",
			expectBody:     false,
		},
	}

	for _, tc := range tests {
		// capture range variable
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, httpSrv.URL+tc.path, nil)
			require.NoError(t, err, "creating request")

			resp, err := client.Do(req)
			require.NoError(t, err, "performing request")
			defer resp.Body.Close()

			require.Equal(t, tc.wantStatusCode, resp.StatusCode, "status code")
			if !tc.expectBody {
				return
			}

			var s3Err struct {
				Code string `xml:"Code"`
			}
			require.NoError(t, xml.NewDecoder(resp.Body).Decode(&s3Err), "decoding S3 error XML")
			require.Equal(t, tc.wantErrorCode, s3Err.Code, "S3 error code")
		})
	}
}

// TestUnknownRoutes ensures that requests which use unsupported HTTP methods
// for otherwise valid paths return 405 Method Not Allowed from the standard
// library router.
func TestUnknownRoutes(t *testing.T) {
	t.Parallel()

	_, httpSrv := newTestServer(t)
	client := httpSrv.Client()

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{
			name:   "POST root",
			method: http.MethodPost,
			path:   "/",
		},
		{
			name:   "PATCH bucket",
			method: http.MethodPatch,
			path:   "/some-bucket",
		},
		{
			name:   "PATCH object",
			method: http.MethodPatch,
			path:   "/some-bucket/some-key",
		},
	}

	for _, tc := range tests {
		// capture range variable
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, httpSrv.URL+tc.path, nil)
			require.NoError(t, err, "creating request")

			resp, err := client.Do(req)
			require.NoError(t, err, "performing request")
			defer resp.Body.Close()

			require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode, "status code")
		})
	}
}

// TestNotImplementedRoutes exercises a representative set of S3-style
// operations that are currently stubbed and should return NotImplemented.
func TestNotImplementedRoutes(t *testing.T) {
	t.Parallel()

	_, httpSrv := newTestServer(t)
	client := httpSrv.Client()

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{
			name:   "PutBucketTagging",
			method: http.MethodPut,
			path:   "/bucket?tagging",
		},
		{
			name:   "DeleteBucketReplication",
			method: http.MethodDelete,
			path:   "/bucket?replication",
		},
		{
			name:   "DeleteObjects",
			method: http.MethodPost,
			path:   "/bucket?delete",
		},
		{
			name:   "UploadPart",
			method: http.MethodPut,
			path:   "/bucket/object?uploadId=123&partNumber=1",
		},
		{
			name:   "GetObjectTagging",
			method: http.MethodGet,
			path:   "/bucket/object?tagging",
		},
		{
			name:   "ListMultipartUploads",
			method: http.MethodGet,
			path:   "/bucket?uploads",
		},
		{
			name:   "AbortMultipartUpload",
			method: http.MethodDelete,
			path:   "/bucket/object?uploadId=123",
		},
		{
			name:   "CompleteMultipartUpload",
			method: http.MethodPost,
			path:   "/bucket/object?uploadId=123",
		},
	}

	for _, tc := range tests {
		// capture range variable
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, httpSrv.URL+tc.path, nil)
			if tc.name == "UploadPart" {
				// Trigger copy-specific branches
				req.Header.Set("x-amz-copy-source", "/src-bucket/src-object")
			}
			require.NoError(t, err, "creating request")

			resp, err := client.Do(req)
			require.NoError(t, err, "performing request")
			defer resp.Body.Close()

			require.Equal(t, http.StatusNotImplemented, resp.StatusCode, "status code")

			var s3Err struct {
				Code string `xml:"Code"`
			}
			require.NoError(t, xml.NewDecoder(resp.Body).Decode(&s3Err), "decoding S3 error XML")
			require.Equal(t, "NotImplemented", s3Err.Code, "S3 error code")
		})
	}
}

func TestDeleteBucketRemovesMetadataAndFiles(t *testing.T) {
	t.Parallel()

	srv, httpSrv := newTestServer(t)
	client := httpSrv.Client()

	bucket := "delete-bucket"
	key := "obj.txt"
	body := []byte("to-be-deleted")

	// PUT object (auto-creates bucket and metadata).
	req, err := http.NewRequest(http.MethodPut, httpSrv.URL+"/"+bucket+"/"+key, io.NopCloser(bytes.NewReader(body)))
	require.NoError(t, err, "creating PUT request")
	resp, err := client.Do(req)
	require.NoError(t, err, "PUT object error")
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT object status")

	// Ensure bucket metadata exists.
	var name string
	err = srv.db.QueryRow(`SELECT name FROM buckets WHERE name = ?`, bucket).Scan(&name)
	require.NoError(t, err, "expected bucket metadata to exist before delete")
	require.Equal(t, bucket, name, "bucket name in metadata")

	// Ensure bucket directory exists on disk.
	bucketPath := filepath.Join(srv.cfg.DataDir, bucket)
	info, err := os.Stat(bucketPath)
	require.NoError(t, err, "expected bucket directory to exist before delete")
	require.True(t, info.IsDir(), "bucket path should be a directory")

	// DELETE the bucket.
	delReq, err := http.NewRequest(http.MethodDelete, httpSrv.URL+"/"+bucket, nil)
	require.NoError(t, err, "creating DELETE bucket request")
	delResp, err := client.Do(delReq)
	require.NoError(t, err, "DELETE bucket error")
	delResp.Body.Close()
	require.Equal(t, http.StatusNoContent, delResp.StatusCode, "DELETE bucket status")

	// Bucket metadata should be gone.
	err = srv.db.QueryRow(`SELECT name FROM buckets WHERE name = ?`, bucket).Scan(&name)
	require.Error(t, err, "expected bucket metadata to be removed")
	require.ErrorIs(t, err, sql.ErrNoRows, "expected ErrNoRows for deleted bucket")

	// Bucket directory should be removed from disk.
	_, err = os.Stat(bucketPath)
	require.Error(t, err, "expected bucket directory to be removed")
	require.True(t, os.IsNotExist(err), "expected bucket path to not exist")
}

func TestDeleteNonexistentBucketReturnsNoSuchBucket(t *testing.T) {
	t.Parallel()

	_, httpSrv := newTestServer(t)
	client := httpSrv.Client()

	bucket := "missing-bucket"

	req, err := http.NewRequest(http.MethodDelete, httpSrv.URL+"/"+bucket, nil)
	require.NoError(t, err, "creating DELETE bucket request")

	resp, err := client.Do(req)
	require.NoError(t, err, "DELETE bucket error")
	defer resp.Body.Close()

	require.Equal(t, http.StatusNotFound, resp.StatusCode, "DELETE bucket status")

	var s3Err struct {
		Code string `xml:"Code"`
	}
	require.NoError(t, xml.NewDecoder(resp.Body).Decode(&s3Err), "decoding S3 error XML")
	require.Equal(t, "NoSuchBucket", s3Err.Code, "expected NoSuchBucket error code")
}

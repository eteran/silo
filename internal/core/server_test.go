package core_test

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eteran/silo/internal/core"
	"github.com/eteran/silo/internal/storage"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/stretchr/testify/require"
)

const (
	AccessKeyID     = "siloadmin"
	SecretAccessKey = "siloadmin"
)

// NewTestServer creates a Server backed by temporary filesystem and SQLite DB
// and returns it along with an httptest.Server wrapping its handler.
func NewTestServer(t *testing.T) (*core.Server, *httptest.Server) {
	t.Helper()

	dataDir := t.TempDir()

	srv, err := core.NewServer(t.Context(), core.Config{DataDir: dataDir})
	require.NoError(t, err, "NewServer error")

	httpSrv := httptest.NewServer(srv.Handler())

	t.Cleanup(func() { _ = srv.Close() })
	t.Cleanup(httpSrv.Close)

	return srv, httpSrv
}

type RequestOption func(*http.Request)

func WithContentType(contentType string) func(*http.Request) {
	return func(req *http.Request) {
		req.Header.Set("Content-Type", contentType)
	}
}

func WithContent(body []byte) func(*http.Request) {
	return func(req *http.Request) {
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/octet-stream")
		}
	}
}

func WithHeader(key string, value string) func(*http.Request) {
	return func(req *http.Request) {
		req.Header.Set(key, value)
	}
}

func DoMethod(t *testing.T, method string, url string, opts ...RequestOption) *http.Response {
	t.Helper()
	client := http.DefaultClient
	req, err := http.NewRequestWithContext(t.Context(), method, url, nil)
	require.NoError(t, err, "creating "+method+" request")
	for _, opt := range opts {
		opt(req)
	}
	req.SetBasicAuth(AccessKeyID, SecretAccessKey)
	resp, err := client.Do(req)
	require.NoErrorf(t, err, "%s %s error", method, url)
	return resp
}

func DoPut(t *testing.T, url string, opts ...RequestOption) *http.Response {
	return DoMethod(t, http.MethodPut, url, opts...)
}

func DoGet(t *testing.T, url string, opts ...RequestOption) *http.Response {
	return DoMethod(t, http.MethodGet, url, opts...)
}

func DoHead(t *testing.T, url string, opts ...RequestOption) *http.Response {
	return DoMethod(t, http.MethodHead, url, opts...)
}

func DoDelete(t *testing.T, url string, opts ...RequestOption) *http.Response {
	return DoMethod(t, http.MethodDelete, url, opts...)
}

// WithXMLBody encodes v as XML and attaches it as the request body with
// Content-Type set to application/xml.
func WithXMLBody(t *testing.T, v any) RequestOption {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, xml.NewEncoder(&buf).Encode(v), "encoding XML body")
	body := buf.Bytes()
	return func(req *http.Request) {
		WithContent(body)(req)
		WithContentType("application/xml")(req)
	}
}

// DecodeS3Error decodes a minimal S3 error response and returns its Code.
func DecodeS3Error(t *testing.T, r io.Reader) string {
	t.Helper()
	var s3Err struct {
		Code string `xml:"Code"`
	}
	require.NoError(t, xml.NewDecoder(r).Decode(&s3Err), "decoding S3 error XML")
	return s3Err.Code
}

func TestCreateAndListBuckets(t *testing.T) {
	t.Parallel()

	_, httpSrv := NewTestServer(t)

	for _, b := range []string{"bucket1", "bucket2"} {
		resp := DoPut(t, httpSrv.URL+"/"+b)
		defer resp.Body.Close()
		require.Equalf(t, http.StatusOK, resp.StatusCode, "PUT bucket %s status", b)
	}

	// List buckets
	resp := DoGet(t, httpSrv.URL+"/")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET / status")

	var listResp core.ListAllMyBucketsResult
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
	_, httpSrv := NewTestServer(t)

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
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resp := DoPut(t, httpSrv.URL+"/"+tc.bucket)
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

	_, httpSrv := NewTestServer(t)

	const (
		bucket = "test-bucket"
		key    = "dir1/object.txt"
	)
	body := []byte("hello world")

	// Explicitly create the bucket first.
	resp := DoPut(t, httpSrv.URL+"/"+bucket)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT bucket status")

	// PUT object into existing bucket.
	resp = DoPut(t, httpSrv.URL+"/"+bucket+"/"+key, WithContent(body), WithContentType("text/plain"))
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT object status")
	require.NotEmpty(t, resp.Header.Get("ETag"), "expected ETag header on PUT response")

	// GET object
	resp = DoGet(t, httpSrv.URL+"/"+bucket+"/"+key)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET object status")
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "reading GET body")
	require.Equal(t, string(body), string(data), "GET object body")

	// HEAD object
	headResp := DoHead(t, httpSrv.URL+"/"+bucket+"/"+key)
	defer headResp.Body.Close()
	require.Equal(t, http.StatusOK, headResp.StatusCode, "HEAD object status")
	require.Equal(t, "text/plain", headResp.Header.Get("Content-Type"), "HEAD Content-Type")
	require.Equal(t, "11", headResp.Header.Get("Content-Length"), "HEAD Content-Length")

	// DELETE object
	delResp := DoDelete(t, httpSrv.URL+"/"+bucket+"/"+key)
	defer delResp.Body.Close()
	require.Equal(t, http.StatusNoContent, delResp.StatusCode, "DELETE object status")

	// GET after delete should return 404.
	resp = DoGet(t, httpSrv.URL+"/"+bucket+"/"+key)
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode, "GET deleted object status")
}

func TestObjectStoredBySHA256Path(t *testing.T) {
	t.Parallel()

	srv, httpSrv := NewTestServer(t)

	const (
		bucket = "sha-bucket"
		key    = "file.bin"
	)
	body := []byte("abc123")

	// Create the bucket first.
	resp := DoPut(t, httpSrv.URL+"/"+bucket)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT bucket status")

	// PUT object into existing bucket.
	resp = DoPut(t, httpSrv.URL+"/"+bucket+"/"+key, WithContent(body))
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT object status")

	// Compute expected SHA-256-based path.
	sum := sha256.Sum256(body)
	hashHex := hex.EncodeToString(sum[:])

	objPath, err := storage.ObjectPath(srv.Config.DataDir, hashHex)
	require.NoErrorf(t, err, "computing object path for %s", hashHex)

	_, err = os.Stat(objPath)
	require.NoErrorf(t, err, "expected object file at %s", objPath)
}

func TestListObjects(t *testing.T) {
	t.Parallel()

	_, httpSrv := NewTestServer(t)

	const bucket = "list-bucket"

	// Create the bucket first.
	resp := DoPut(t, httpSrv.URL+"/"+bucket)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT bucket status")

	// Upload objects with and without the prefix.
	keys := []string{"dir/a.txt", "dir/b.txt", "other.txt"}
	for _, key := range keys {
		resp := DoPut(t, httpSrv.URL+"/"+bucket+"/"+key, WithContent([]byte(key)), WithContentType("text/plain"))
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode, "PUT object status")
	}

	// List without prefix should see all objects.
	resp = DoGet(t, httpSrv.URL+"/"+bucket)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET bucket status")

	var listResp core.ListBucketResultV1
	require.NoError(t, xml.NewDecoder(resp.Body).Decode(&listResp), "decoding ListBucketResult")
	require.Len(t, listResp.Contents, 3, "expected all objects without prefix filter")

	// List with prefix should only return the two prefixed keys.
	resp = DoGet(t, httpSrv.URL+"/"+bucket+"?prefix=dir/")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET bucket with prefix status")

	var listRespWithPrefix core.ListBucketResultV1
	require.NoError(t, xml.NewDecoder(resp.Body).Decode(&listRespWithPrefix), "decoding ListBucketResult with prefix")
	require.Len(t, listRespWithPrefix.Contents, 2, "expected only prefixed objects")
	require.Equal(t, "dir/a.txt", listRespWithPrefix.Contents[0].Key, "first key with prefix")
	require.Equal(t, "dir/b.txt", listRespWithPrefix.Contents[1].Key, "second key with prefix")
}

func TestGetBucketLocation(t *testing.T) {
	t.Parallel()

	_, httpSrv := NewTestServer(t)

	const bucket = "location-bucket"

	// Create the bucket first.
	resp := DoPut(t, httpSrv.URL+"/"+bucket)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT bucket status")

	// Now fetch its location.
	resp = DoGet(t, httpSrv.URL+"/"+bucket+"?location")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET bucket location status")

	var loc struct {
		Region string `xml:",chardata"`
	}
	require.NoError(t, xml.NewDecoder(resp.Body).Decode(&loc), "decoding LocationConstraint")
	require.Equal(t, "us-east-1", strings.TrimSpace(loc.Region), "bucket region")
}

func TestPutAndGetBucketTagging(t *testing.T) {
	t.Parallel()

	_, httpSrv := NewTestServer(t)

	const bucket = "tag-bucket"

	// Create the bucket first.
	resp := DoPut(t, httpSrv.URL+"/"+bucket)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT bucket status")

	// PUT bucket tagging.
	tagging := core.Tagging{
		XMLNS: core.S3XMLNamespace,
		TagSet: []core.Tag{
			{Key: "env", Value: "dev"},
			{Key: "owner", Value: "alice"},
		},
	}
	putResp := DoPut(t, httpSrv.URL+"/"+bucket+"?tagging", WithXMLBody(t, tagging))

	defer putResp.Body.Close()
	require.Equal(t, http.StatusOK, putResp.StatusCode, "PUT bucket tagging status")

	// GET bucket tagging and verify round-trip.
	getResp := DoGet(t, httpSrv.URL+"/"+bucket+"?tagging")
	defer getResp.Body.Close()
	require.Equal(t, http.StatusOK, getResp.StatusCode, "GET bucket tagging status")

	var got core.Tagging
	require.NoError(t, xml.NewDecoder(getResp.Body).Decode(&got), "decoding BucketTagging")
	require.Len(t, got.TagSet, 2, "expected two tags")

	values := map[string]string{}
	for _, tag := range got.TagSet {
		values[tag.Key] = tag.Value
	}
	require.Equal(t, "dev", values["env"], "env tag value")
	require.Equal(t, "alice", values["owner"], "owner tag value")
}

func TestGetBucketTaggingNoSuchBucket(t *testing.T) {
	t.Parallel()

	_, httpSrv := NewTestServer(t)

	resp := DoGet(t, httpSrv.URL+"/nonexistent-bucket?tagging")
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode, "GET bucket tagging status for missing bucket")
	require.Equal(t, "NoSuchBucket", DecodeS3Error(t, resp.Body), "expected NoSuchBucket error code")
}

func TestGetBucketTaggingNoTagSet(t *testing.T) {
	t.Parallel()

	_, httpSrv := NewTestServer(t)

	const bucket = "empty-tag-bucket"

	// Create the bucket without tags.
	resp := DoPut(t, httpSrv.URL+"/"+bucket)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT bucket status")

	// GET tagging should return NoSuchTagSet.
	getResp := DoGet(t, httpSrv.URL+"/"+bucket+"?tagging")
	defer getResp.Body.Close()
	require.Equal(t, http.StatusNotFound, getResp.StatusCode, "GET bucket tagging status for empty tag set")
	require.Equal(t, "NoSuchTagSet", DecodeS3Error(t, getResp.Body), "expected NoSuchTagSet error code")
}

func TestPutBucketTaggingNoSuchBucket(t *testing.T) {
	t.Parallel()

	_, httpSrv := NewTestServer(t)

	tagging := core.Tagging{
		XMLNS:  core.S3XMLNamespace,
		TagSet: []core.Tag{{Key: "env", Value: "dev"}},
	}
	putResp := DoPut(t, httpSrv.URL+"/nonexistent-bucket?tagging", WithXMLBody(t, tagging))
	defer putResp.Body.Close()
	require.Equal(t, http.StatusNotFound, putResp.StatusCode, "PUT bucket tagging status for missing bucket")
	require.Equal(t, "NoSuchBucket", DecodeS3Error(t, putResp.Body), "expected NoSuchBucket error code")
}

func TestPutAndGetObjectTagging(t *testing.T) {
	t.Parallel()

	_, httpSrv := NewTestServer(t)

	const (
		bucket = "obj-tag-bucket"
		key    = "obj.txt"
	)
	body := []byte("payload")

	// Create the bucket first.
	createResp := DoPut(t, httpSrv.URL+"/"+bucket)
	defer createResp.Body.Close()
	require.Equal(t, http.StatusOK, createResp.StatusCode, "PUT bucket status")

	// PUT object into existing bucket.
	putObjResp := DoPut(t, httpSrv.URL+"/"+bucket+"/"+key, WithContent(body))
	defer putObjResp.Body.Close()
	require.Equal(t, http.StatusOK, putObjResp.StatusCode, "PUT object status")

	// PUT object tagging.
	tagging := core.Tagging{
		XMLNS: core.S3XMLNamespace,
		TagSet: []core.Tag{
			{Key: "env", Value: "dev"},
			{Key: "owner", Value: "bob"},
		},
	}
	putResp := DoPut(t, httpSrv.URL+"/"+bucket+"/"+key+"?tagging", WithXMLBody(t, tagging))
	defer putResp.Body.Close()
	require.Equal(t, http.StatusOK, putResp.StatusCode, "PUT object tagging status")

	// GET object tagging and verify round-trip.
	getResp := DoGet(t, httpSrv.URL+"/"+bucket+"/"+key+"?tagging")
	defer getResp.Body.Close()
	require.Equal(t, http.StatusOK, getResp.StatusCode, "GET object tagging status")

	var got core.Tagging
	require.NoError(t, xml.NewDecoder(getResp.Body).Decode(&got), "decoding object BucketTagging")
	require.Len(t, got.TagSet, 2, "expected two object tags")

	values := map[string]string{}
	for _, tag := range got.TagSet {
		values[tag.Key] = tag.Value
	}
	require.Equal(t, "dev", values["env"], "env tag value")
	require.Equal(t, "bob", values["owner"], "owner tag value")
}

func TestGetObjectTaggingNoSuchKey(t *testing.T) {
	t.Parallel()

	_, httpSrv := NewTestServer(t)

	resp := DoGet(t, httpSrv.URL+"/bucket/missing-key?tagging")
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode, "GET object tagging status for missing key")
	require.Equal(t, "NoSuchKey", DecodeS3Error(t, resp.Body), "expected NoSuchKey error code")
}

func TestGetObjectTaggingNoTagSet(t *testing.T) {
	t.Parallel()

	_, httpSrv := NewTestServer(t)

	const (
		bucket = "obj-empty-tag-bucket"
		key    = "obj.txt"
	)
	body := []byte("payload")

	// Create the bucket first.
	createResp := DoPut(t, httpSrv.URL+"/"+bucket)
	defer createResp.Body.Close()
	require.Equal(t, http.StatusOK, createResp.StatusCode, "PUT bucket status")

	// PUT object into existing bucket without tags.
	putObjResp := DoPut(t, httpSrv.URL+"/"+bucket+"/"+key, WithContent(body))
	defer putObjResp.Body.Close()
	require.Equal(t, http.StatusOK, putObjResp.StatusCode, "PUT object status")

	// GET tagging should return NoSuchTagSet.
	getResp := DoGet(t, httpSrv.URL+"/"+bucket+"/"+key+"?tagging")
	defer getResp.Body.Close()
	require.Equal(t, http.StatusNotFound, getResp.StatusCode, "GET object tagging status for empty tag set")
	require.Equal(t, "NoSuchTagSet", DecodeS3Error(t, getResp.Body), "expected NoSuchTagSet error code")
}

func TestDeleteObjectTaggingRemovesTags(t *testing.T) {
	t.Parallel()

	_, httpSrv := NewTestServer(t)

	const (
		bucket = "obj-delete-tag-bucket"
		key    = "obj.txt"
	)
	body := []byte("payload")

	// Create the bucket first.
	createResp := DoPut(t, httpSrv.URL+"/"+bucket)
	defer createResp.Body.Close()
	require.Equal(t, http.StatusOK, createResp.StatusCode, "PUT bucket status")

	// PUT object into existing bucket.
	putObjResp := DoPut(t, httpSrv.URL+"/"+bucket+"/"+key, WithContent(body))
	defer putObjResp.Body.Close()
	require.Equal(t, http.StatusOK, putObjResp.StatusCode, "PUT object status")

	// Add tags.
	tagging := core.Tagging{
		XMLNS:  core.S3XMLNamespace,
		TagSet: []core.Tag{{Key: "env", Value: "prod"}},
	}
	putResp := DoPut(t, httpSrv.URL+"/"+bucket+"/"+key+"?tagging", WithXMLBody(t, tagging))
	defer putResp.Body.Close()
	require.Equal(t, http.StatusOK, putResp.StatusCode, "PUT object tagging status")

	// Delete tags.
	delResp := DoDelete(t, httpSrv.URL+"/"+bucket+"/"+key+"?tagging")
	defer delResp.Body.Close()
	require.Equal(t, http.StatusNoContent, delResp.StatusCode, "DELETE object tagging status")

	// Subsequent GET should return NoSuchTagSet.
	getResp := DoGet(t, httpSrv.URL+"/"+bucket+"/"+key+"?tagging")
	defer getResp.Body.Close()
	require.Equal(t, http.StatusNotFound, getResp.StatusCode, "GET object tagging status after delete")
	require.Equal(t, "NoSuchTagSet", DecodeS3Error(t, getResp.Body), "expected NoSuchTagSet after delete")
}

func TestDeleteBucketTaggingRemovesTags(t *testing.T) {
	t.Parallel()

	_, httpSrv := NewTestServer(t)

	const bucket = "delete-tag-bucket"

	// Create the bucket.
	resp := DoPut(t, httpSrv.URL+"/"+bucket)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT bucket status")

	// Add tags.
	tagging := core.Tagging{
		XMLNS: core.S3XMLNamespace,
		TagSet: []core.Tag{
			{Key: "env", Value: "prod"},
		},
	}
	putResp := DoPut(t, httpSrv.URL+"/"+bucket+"?tagging", WithXMLBody(t, tagging))
	defer putResp.Body.Close()
	require.Equal(t, http.StatusOK, putResp.StatusCode, "PUT bucket tagging status")

	// Delete tags.
	delResp := DoDelete(t, httpSrv.URL+"/"+bucket+"?tagging")
	defer delResp.Body.Close()
	require.Equal(t, http.StatusNoContent, delResp.StatusCode, "DELETE bucket tagging status")

	// Subsequent GET should return NoSuchTagSet.
	getResp := DoGet(t, httpSrv.URL+"/"+bucket+"?tagging")
	defer getResp.Body.Close()
	require.Equal(t, http.StatusNotFound, getResp.StatusCode, "GET bucket tagging status after delete")
	require.Equal(t, "NoSuchTagSet", DecodeS3Error(t, getResp.Body), "expected NoSuchTagSet after delete")
}

func TestDeleteBucketTaggingNoSuchBucket(t *testing.T) {
	t.Parallel()

	_, httpSrv := NewTestServer(t)

	delResp := DoDelete(t, httpSrv.URL+"/nonexistent-bucket?tagging")
	defer delResp.Body.Close()
	require.Equal(t, http.StatusNotFound, delResp.StatusCode, "DELETE bucket tagging status for missing bucket")
	require.Equal(t, "NoSuchBucket", DecodeS3Error(t, delResp.Body), "expected NoSuchBucket error code")
}

func TestCopyObjectWithinBucket(t *testing.T) {
	t.Parallel()

	srv, httpSrv := NewTestServer(t)

	const (
		bucket = "copy-bucket"
		srcKey = "src.txt"
		dstKey = "dst.txt"
	)
	body := []byte("copy-me")

	// Create the bucket first.
	resp := DoPut(t, httpSrv.URL+"/"+bucket)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT bucket status")

	// PUT source object into existing bucket.
	resp = DoPut(t, httpSrv.URL+"/"+bucket+"/"+srcKey, WithContent(body))
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT source status")

	// Copy within the same bucket using x-amz-copy-source.
	copyResp := DoPut(t, httpSrv.URL+"/"+bucket+"/"+dstKey,
		WithHeader("x-amz-copy-source", "/"+bucket+"/"+srcKey))
	defer copyResp.Body.Close()
	require.Equal(t, http.StatusOK, copyResp.StatusCode, "CopyObject status")

	// GET destination should return the same payload.
	getResp := DoGet(t, httpSrv.URL+"/"+bucket+"/"+dstKey)
	defer getResp.Body.Close()
	require.Equal(t, http.StatusOK, getResp.StatusCode, "GET copied object status")

	data, err := io.ReadAll(getResp.Body)
	require.NoError(t, err, "reading copied object body")
	require.Equal(t, body, data, "copied payload mismatch")

	// Verify that the payload file exists in the expected location for this bucket.
	sum := sha256.Sum256(body)
	hashHex := hex.EncodeToString(sum[:])
	path, err := storage.ObjectPath(srv.Config.DataDir, hashHex)
	require.NoErrorf(t, err, "computing object path for %s", hashHex)

	info, err := os.Stat(path)
	require.NoError(t, err, "expected payload file to exist")
	require.False(t, info.IsDir(), "payload path should be a file")
}

func TestGetObjectMissingPayloadReturnsInternalError(t *testing.T) {
	t.Parallel()

	srv, httpSrv := NewTestServer(t)

	const (
		bucket = "missing-payload-bucket"
		key    = "file.bin"
	)
	body := []byte("payload-to-delete")

	// Create the bucket first.
	resp := DoPut(t, httpSrv.URL+"/"+bucket)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT bucket status")

	// PUT object into existing bucket (creates metadata).
	resp = DoPut(t, httpSrv.URL+"/"+bucket+"/"+key, WithContent(body))
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT object status")

	// Delete the underlying payload file from disk while leaving metadata.
	sum := sha256.Sum256(body)
	hashHex := hex.EncodeToString(sum[:])
	objPath, err := storage.ObjectPath(srv.Config.DataDir, hashHex)
	require.NoErrorf(t, err, "computing object path for %s", hashHex)
	require.NoError(t, os.Remove(objPath), "removing payload file")

	// GET should now fail with 500 Internal Server Error due to missing payload.
	getResp := DoGet(t, httpSrv.URL+"/"+bucket+"/"+key)
	defer getResp.Body.Close()
	require.Equal(t, http.StatusInternalServerError, getResp.StatusCode, "GET status for missing payload")
}

func TestCopyObjectMissingSourceObjectReturnsNoSuchKey(t *testing.T) {
	t.Parallel()

	_, httpSrv := NewTestServer(t)

	const (
		srcBucket = "src-bucket-missing"
		dstBucket = "dst-bucket-missing"
		key       = "file.bin"
	)

	// Create the destination bucket so CopyObject can validate the source.
	createResp := DoPut(t, httpSrv.URL+"/"+dstBucket)
	defer createResp.Body.Close()
	require.Equal(t, http.StatusOK, createResp.StatusCode, "PUT dest bucket status")

	// Do not PUT any source object; CopyObject should fail with NoSuchKey.
	copyResp := DoPut(t, httpSrv.URL+"/"+dstBucket+"/"+key,
		WithHeader("x-amz-copy-source", "/"+srcBucket+"/"+key))
	defer copyResp.Body.Close()

	require.Equal(t, http.StatusNotFound, copyResp.StatusCode, "CopyObject status for missing source")

	require.Equal(t, "NoSuchKey", DecodeS3Error(t, copyResp.Body), "expected NoSuchKey error code")
}

func TestCopyObjectWithInvalidSourceHeaderReturnsInvalidRequest(t *testing.T) {
	t.Parallel()

	_, httpSrv := NewTestServer(t)

	const (
		dstBucket = "dst-bucket-invalid-source"
		key       = "file.bin"
	)

	copyResp := DoPut(t, httpSrv.URL+"/"+dstBucket+"/"+key,
		WithHeader("x-amz-copy-source", "invalid-source"))
	defer copyResp.Body.Close()

	require.Equal(t, http.StatusBadRequest, copyResp.StatusCode, "CopyObject status for invalid source header")

	require.Equal(t, "InvalidRequest", DecodeS3Error(t, copyResp.Body), "expected InvalidRequest error code")
}

func TestCopyObjectMissingPayloadOnSourceIgnoresError(t *testing.T) {
	t.Parallel()

	srv, httpSrv := NewTestServer(t)

	const (
		srcBucket = "src-bucket-missing-payload"
		dstBucket = "dst-bucket-missing-payload"
		key       = "file.bin"
	)
	body := []byte("payload-to-delete-for-copy")

	// Create both source and destination buckets first.
	srcCreateResp := DoPut(t, httpSrv.URL+"/"+srcBucket)
	defer srcCreateResp.Body.Close()
	require.Equal(t, http.StatusOK, srcCreateResp.StatusCode, "PUT src bucket status")

	dstCreateResp := DoPut(t, httpSrv.URL+"/"+dstBucket)
	defer dstCreateResp.Body.Close()
	require.Equal(t, http.StatusOK, dstCreateResp.StatusCode, "PUT dst bucket status")

	// PUT source object into existing source bucket.
	resp := DoPut(t, httpSrv.URL+"/"+srcBucket+"/"+key, WithContent(body))
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT source status")

	// Delete the underlying payload file for the source object.
	sum := sha256.Sum256(body)
	hashHex := hex.EncodeToString(sum[:])

	srcPath, err := storage.ObjectPath(srv.Config.DataDir, hashHex)
	require.NoErrorf(t, err, "computing object path for %s", hashHex)
	require.NoError(t, os.Remove(srcPath), "removing source payload file")

	// Attempt to CopyObject; metadata exists but payload is gone.
	copyResp := DoPut(t, httpSrv.URL+"/"+dstBucket+"/"+key,
		WithHeader("x-amz-copy-source", "/"+srcBucket+"/"+key))
	defer copyResp.Body.Close()

	// NOTE(eteran): CopyObject only copies meta-data, so it should succeed
	// even if the source payload is missing.
	require.Equal(t, http.StatusOK, copyResp.StatusCode, "CopyObject status for missing payload on source")
}

func TestListObjectsV2Pagination(t *testing.T) {
	t.Parallel()

	_, httpSrv := NewTestServer(t)

	const bucket = "listv2-bucket"

	// Create the bucket first.
	resp := DoPut(t, httpSrv.URL+"/"+bucket)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT bucket status")

	// Upload three objects.
	keys := []string{"a.txt", "b.txt", "c.txt"}
	for _, key := range keys {
		putResp := DoPut(t, httpSrv.URL+"/"+bucket+"/"+key, WithContent([]byte(key)), WithContentType("text/plain"))
		defer putResp.Body.Close()
		require.Equal(t, http.StatusOK, putResp.StatusCode, "PUT object status")
	}

	// First page: max-keys=2
	listURL, err := url.Parse(httpSrv.URL + "/" + bucket)
	require.NoError(t, err, "parsing list URL")
	q := listURL.Query()
	q.Set("list-type", "2")
	q.Set("max-keys", "2")
	listURL.RawQuery = q.Encode()

	resp = DoGet(t, listURL.String())
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "ListObjectsV2 page 1 status")

	var v2Resp core.ListBucketResultV2
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

	resp2 := DoGet(t, listURL2.String())
	defer resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode, "ListObjectsV2 page 2 status")

	var v2Resp2 core.ListBucketResultV2
	require.NoError(t, xml.NewDecoder(resp2.Body).Decode(&v2Resp2), "decoding ListBucketResultV2 page 2")
	require.Equal(t, 1, v2Resp2.KeyCount, "KeyCount page 2")
	require.False(t, v2Resp2.IsTruncated, "IsTruncated page 2")
	require.Len(t, v2Resp2.Contents, 1, "Contents length page 2")
	require.Equal(t, "c.txt", v2Resp2.Contents[0].Key, "first key page 2")
}

func TestListObjectsV2PrefixAndStartAfter(t *testing.T) {
	t.Parallel()

	_, httpSrv := NewTestServer(t)

	const bucket = "listv2-prefix-bucket"

	// Create the bucket first.
	resp := DoPut(t, httpSrv.URL+"/"+bucket)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT bucket status")

	// Upload objects with and without the prefix.
	keys := []string{"dir/a.txt", "dir/b.txt", "other.txt"}
	for _, key := range keys {
		putResp := DoPut(t, httpSrv.URL+"/"+bucket+"/"+key, WithContent([]byte(key)), WithContentType("text/plain"))
		defer putResp.Body.Close()
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

	resp = DoGet(t, listURL.String())
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "ListObjectsV2 with prefix status")

	var v2Resp core.ListBucketResultV2
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

	resp2 := DoGet(t, listURL2.String())
	defer resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode, "ListObjectsV2 with start-after status")

	var v2Resp2 core.ListBucketResultV2
	require.NoError(t, xml.NewDecoder(resp2.Body).Decode(&v2Resp2), "decoding ListBucketResultV2 with start-after")
	require.Equal(t, 1, v2Resp2.KeyCount, "KeyCount with start-after")
	require.False(t, v2Resp2.IsTruncated, "IsTruncated with start-after")
	require.Len(t, v2Resp2.Contents, 1, "Contents length with start-after")
	require.Equal(t, "dir/b.txt", v2Resp2.Contents[0].Key, "first key with start-after")
}

func TestErrorResponsesTableDriven(t *testing.T) {
	t.Parallel()

	_, httpSrv := NewTestServer(t)

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
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resp := DoMethod(t, tc.method, httpSrv.URL+tc.path)
			defer resp.Body.Close()

			require.Equal(t, tc.wantStatusCode, resp.StatusCode, "status code")
			if !tc.expectBody {
				return
			}

			require.Equal(t, tc.wantErrorCode, DecodeS3Error(t, resp.Body), "S3 error code")
		})
	}
}

func TestPutObjectNoSuchBucket(t *testing.T) {
	t.Parallel()

	_, httpSrv := NewTestServer(t)

	// PUT object into a bucket that does not exist should return NoSuchBucket.
	resp := DoPut(t, httpSrv.URL+"/missing-bucket/object.txt", WithContent([]byte("data")))
	defer resp.Body.Close()

	require.Equal(t, http.StatusNotFound, resp.StatusCode, "PUT object status for missing bucket")
	require.Equal(t, "NoSuchBucket", DecodeS3Error(t, resp.Body), "expected NoSuchBucket error code")
}

func TestCopyObjectNoSuchBucketOnDestination(t *testing.T) {
	t.Parallel()

	_, httpSrv := NewTestServer(t)

	const (
		srcBucket = "src-bucket-for-dst-nosuchbucket"
		srcKey    = "file.bin"
		dstBucket = "missing-dst-bucket"
	)

	// Create the source bucket and upload source object.
	createResp := DoPut(t, httpSrv.URL+"/"+srcBucket)
	defer createResp.Body.Close()
	require.Equal(t, http.StatusOK, createResp.StatusCode, "PUT src bucket status")

	putResp := DoPut(t, httpSrv.URL+"/"+srcBucket+"/"+srcKey, WithContent([]byte("payload")))
	defer putResp.Body.Close()
	require.Equal(t, http.StatusOK, putResp.StatusCode, "PUT src object status")

	// Attempt to copy into a non-existent destination bucket.
	copyResp := DoPut(t, httpSrv.URL+"/"+dstBucket+"/"+srcKey,
		WithHeader("x-amz-copy-source", "/"+srcBucket+"/"+srcKey))
	defer copyResp.Body.Close()

	require.Equal(t, http.StatusNotFound, copyResp.StatusCode, "CopyObject status for missing destination bucket")
	require.Equal(t, "NoSuchBucket", DecodeS3Error(t, copyResp.Body), "expected NoSuchBucket error code for destination bucket")
}

// TestUnknownRoutes ensures that requests which use unsupported HTTP methods
// for otherwise valid paths return 405 Method Not Allowed from the standard
// library router.
func TestUnknownRoutes(t *testing.T) {
	t.Parallel()

	_, httpSrv := NewTestServer(t)

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
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resp := DoMethod(t, tc.method, httpSrv.URL+tc.path)
			defer resp.Body.Close()

			require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode, "status code")
		})
	}
}

// TestNotImplementedRoutes exercises a representative set of S3-style
// operations that are currently stubbed and should return NotImplemented.
func TestNotImplementedRoutes(t *testing.T) {
	t.Parallel()

	_, httpSrv := NewTestServer(t)

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{
			name:   "DeleteBucketReplication",
			method: http.MethodDelete,
			path:   "/bucket?replication",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resp := DoMethod(t, tc.method, httpSrv.URL+tc.path)

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

// TestListMultipartUploads verifies that in-progress multipart uploads for a
// bucket are returned by GET /bucket?uploads.
func TestListMultipartUploads(t *testing.T) {
	t.Parallel()

	_, httpSrv := NewTestServer(t)

	const (
		bucket = "list-multipart-bucket"
		key    = "multipart-object.bin"
	)

	// Create the bucket.
	resp := DoPut(t, httpSrv.URL+"/"+bucket)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT bucket status")

	// Initiate a multipart upload.
	initResp := DoMethod(t, http.MethodPost, httpSrv.URL+"/"+bucket+"/"+key+"?uploads")
	defer initResp.Body.Close()
	require.Equal(t, http.StatusOK, initResp.StatusCode, "CreateMultipartUpload status")

	var initResult core.InitiateMultipartUploadResult
	require.NoError(t, xml.NewDecoder(initResp.Body).Decode(&initResult), "decoding CreateMultipartUploadResult")
	require.Equal(t, bucket, initResult.Bucket, "CreateMultipartUpload bucket")
	require.Equal(t, key, initResult.Key, "CreateMultipartUpload key")
	require.NotEmpty(t, initResult.UploadID, "CreateMultipartUpload upload ID")

	// List multipart uploads for the bucket.
	listResp := DoGet(t, httpSrv.URL+"/"+bucket+"?uploads")
	defer listResp.Body.Close()
	require.Equal(t, http.StatusOK, listResp.StatusCode, "ListMultipartUploads status")

	var listResult core.ListMultipartUploadsResult
	require.NoError(t, xml.NewDecoder(listResp.Body).Decode(&listResult), "decoding ListMultipartUploadsResult")
	require.Equal(t, bucket, listResult.Bucket, "ListMultipartUploads bucket")
	require.Len(t, listResult.Uploads, 1, "expected exactly one in-progress upload")

	u := listResult.Uploads[0]
	require.Equal(t, key, u.Key, "upload key")
	require.Equal(t, initResult.UploadID, u.UploadID, "upload ID")
}

// TestDeleteObjectsMultiDelete verifies that POST /bucket?delete removes
// multiple objects in a single request and returns them in the DeleteResult
// response.
func TestDeleteObjectsMultiDelete(t *testing.T) {
	t.Parallel()

	_, httpSrv := NewTestServer(t)

	const (
		bucket = "multi-delete-bucket"
		key1   = "obj-1.txt"
		key2   = "obj-2.txt"
	)

	// Create bucket and two objects.
	resp := DoPut(t, httpSrv.URL+"/"+bucket)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT bucket status")

	body1 := []byte("first")
	body2 := []byte("second")

	put1 := DoPut(t, httpSrv.URL+"/"+bucket+"/"+key1, WithContent(body1))
	defer put1.Body.Close()
	require.Equal(t, http.StatusOK, put1.StatusCode, "PUT object 1 status")

	put2 := DoPut(t, httpSrv.URL+"/"+bucket+"/"+key2, WithContent(body2))
	defer put2.Body.Close()
	require.Equal(t, http.StatusOK, put2.StatusCode, "PUT object 2 status")

	// Issue multi-delete request.
	deleteReq := core.DeleteObjectsRequest{
		Objects: []core.DeleteObject{
			{Key: key1},
			{Key: key2},
		},
	}

	delResp := DoMethod(t, http.MethodPost, httpSrv.URL+"/"+bucket+"?delete", WithXMLBody(t, deleteReq))
	defer delResp.Body.Close()
	require.Equal(t, http.StatusOK, delResp.StatusCode, "DeleteObjects status")

	var delResult core.DeleteResult
	require.NoError(t, xml.NewDecoder(delResp.Body).Decode(&delResult), "decoding DeleteResult")

	deletedKeys := map[string]bool{}
	for _, d := range delResult.Deleted {
		deletedKeys[d.Key] = true
	}
	require.True(t, deletedKeys[key1], "expected key1 in DeleteResult")
	require.True(t, deletedKeys[key2], "expected key2 in DeleteResult")

	// Subsequent GETs should return NoSuchKey.
	get1 := DoGet(t, httpSrv.URL+"/"+bucket+"/"+key1)
	defer get1.Body.Close()
	require.Equal(t, http.StatusNotFound, get1.StatusCode, "GET deleted object 1 status")

	get2 := DoGet(t, httpSrv.URL+"/"+bucket+"/"+key2)
	defer get2.Body.Close()
	require.Equal(t, http.StatusNotFound, get2.StatusCode, "GET deleted object 2 status")
}

func TestDeleteBucketRemovesMetadata(t *testing.T) {
	t.Parallel()

	srv, httpSrv := NewTestServer(t)

	const (
		bucket = "delete-bucket"
		key    = "obj.txt"
	)
	body := []byte("to-be-deleted")

	// Create the bucket first.
	resp := DoPut(t, httpSrv.URL+"/"+bucket)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT bucket status")

	// PUT object into existing bucket (creates metadata).
	resp = DoPut(t, httpSrv.URL+"/"+bucket+"/"+key, WithContent(body))
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "PUT object status")

	// Ensure bucket metadata exists.
	var name string
	err := srv.Db.QueryRowContext(t.Context(), `SELECT name FROM buckets WHERE name = ?`, bucket).Scan(&name)
	require.NoError(t, err, "expected bucket metadata to exist before delete")
	require.Equal(t, bucket, name, "bucket name in metadata")

	// DELETE the bucket.
	delResp := DoDelete(t, httpSrv.URL+"/"+bucket)
	defer delResp.Body.Close()
	require.Equal(t, http.StatusNoContent, delResp.StatusCode, "DELETE bucket status")

	// Bucket metadata should be gone.
	err = srv.Db.QueryRowContext(t.Context(), `SELECT name FROM buckets WHERE name = ?`, bucket).Scan(&name)
	require.Error(t, err, "expected bucket metadata to be removed")
	require.ErrorIs(t, err, sql.ErrNoRows, "expected ErrNoRows for deleted bucket")
}

func TestDeleteNonexistentBucketReturnsNoSuchBucket(t *testing.T) {
	t.Parallel()

	_, httpSrv := NewTestServer(t)

	const bucket = "missing-bucket"

	resp := DoDelete(t, httpSrv.URL+"/"+bucket)
	defer resp.Body.Close()

	require.Equal(t, http.StatusNotFound, resp.StatusCode, "DELETE bucket status")

	require.Equal(t, "NoSuchBucket", DecodeS3Error(t, resp.Body), "expected NoSuchBucket error code")
}

// newMinioClient creates a MinIO client configured to talk to the in-memory
// test server using path-style bucket lookup and the default credentials.
func newMinioClient(t *testing.T, httpSrv *httptest.Server) *minio.Client {
	t.Helper()

	u, err := url.Parse(httpSrv.URL)
	require.NoError(t, err, "parsing test server URL")

	client, err := minio.New(u.Host, &minio.Options{
		Creds:  credentials.NewStaticV4(AccessKeyID, SecretAccessKey, ""),
		Secure: u.Scheme == "https",
		// The core server expects path-style requests: /bucket/object.
		BucketLookup: minio.BucketLookupPath,
	})
	require.NoError(t, err, "creating MinIO client")

	return client
}

// TestMultipartUploadUsingMinioClient verifies that a large object uploaded
// via the MinIO Go client uses multipart upload successfully and that the
// resulting object can be read back intact.
func TestMultipartUploadUsingMinioClient(t *testing.T) {
	t.Parallel()

	_, httpSrv := NewTestServer(t)
	client := newMinioClient(t, httpSrv)
	ctx := t.Context()

	const (
		bucket = "minio-multipart-bucket"
		object = "large-object.bin"
	)

	// Create bucket via MinIO client.
	err := client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{Region: "us-east-1"})
	require.NoError(t, err, "MakeBucket via MinIO client")

	// Prepare a payload large enough to trigger multipart upload in
	// minio-go (threshold is 16MiB).
	size := int64(20 * 1024 * 1024) // 20 MiB
	data := bytes.Repeat([]byte("0123456789abcdef"), int(size/16))
	require.Equal(t, size, int64(len(data)), "test payload size")

	putInfo, err := client.PutObject(ctx, bucket, object, bytes.NewReader(data), size, minio.PutObjectOptions{
		ContentType: "application/octet-stream",
	})
	require.NoError(t, err, "PutObject via MinIO client")
	require.Equal(t, size, putInfo.Size, "uploaded size")
	require.NotEmpty(t, putInfo.ETag, "uploaded ETag")

	// Read the object back and verify its content.
	obj, err := client.GetObject(ctx, bucket, object, minio.GetObjectOptions{})
	require.NoError(t, err, "GetObject via MinIO client")
	defer obj.Close()

	got, err := io.ReadAll(obj)
	require.NoError(t, err, "reading object data")
	require.Equal(t, data, got, "round-trip multipart payload mismatch")
}

// TestAbortMultipartUploadUsingMinioCore verifies that aborting a multipart
// upload via the MinIO Core API triggers deletion of the temporary uploads
// directory for that upload ID.
func TestAbortMultipartUploadUsingMinioCore(t *testing.T) {
	t.Parallel()

	srv, httpSrv := NewTestServer(t)
	ctx := t.Context()

	u, err := url.Parse(httpSrv.URL)
	require.NoError(t, err, "parsing test server URL")

	coreClient, err := minio.NewCore(u.Host, &minio.Options{
		Creds:        credentials.NewStaticV4(AccessKeyID, SecretAccessKey, ""),
		Secure:       u.Scheme == "https",
		BucketLookup: minio.BucketLookupPath,
	})
	require.NoError(t, err, "creating MinIO Core client")

	const (
		bucket = "minio-abort-multipart-bucket"
		object = "multipart-object.bin"
	)

	// Create bucket using high-level client built on the same endpoint.
	client := newMinioClient(t, httpSrv)
	require.NoError(t, client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{Region: "us-east-1"}), "MakeBucket via MinIO client")

	// Initiate a multipart upload via Core API.
	uploadID, err := coreClient.NewMultipartUpload(ctx, bucket, object, minio.PutObjectOptions{ContentType: "application/octet-stream"})
	require.NoError(t, err, "NewMultipartUpload via MinIO Core")
	require.NotEmpty(t, uploadID, "uploadID should not be empty")

	uploadDir := filepath.Join(srv.Config.DataDir, "uploads", uploadID)

	// Give a brief moment for the directory to be created on slow filesystems.
	time.Sleep(10 * time.Millisecond)

	if _, err := os.Stat(uploadDir); err != nil {
		// Even if the stat fails, continue with abort to ensure idempotency.
		_ = err
	}

	// Abort the multipart upload; this should delete the temporary directory.
	require.NoError(t, coreClient.AbortMultipartUpload(ctx, bucket, object, uploadID), "AbortMultipartUpload via MinIO Core")

	// Allow the server a brief moment to process and remove the directory.
	time.Sleep(10 * time.Millisecond)

	_, err = os.Stat(uploadDir)
	require.Error(t, err, "expected upload directory to be removed after abort")
	require.True(t, os.IsNotExist(err), "expected upload directory to not exist after abort")
}

// TestExplicitMultipartUploadUsingMinioCore performs a full multipart
// upload sequence using the MinIO Core API: initiate, upload parts,
// complete, and then verifies the final object contents via a regular
// GET request to the server.
func TestExplicitMultipartUploadUsingMinioCore(t *testing.T) {
	t.Parallel()

	_, httpSrv := NewTestServer(t)
	ctx := t.Context()

	u, err := url.Parse(httpSrv.URL)
	require.NoError(t, err, "parsing test server URL")

	coreClient, err := minio.NewCore(u.Host, &minio.Options{
		Creds:        credentials.NewStaticV4(AccessKeyID, SecretAccessKey, ""),
		Secure:       u.Scheme == "https",
		BucketLookup: minio.BucketLookupPath,
	})
	require.NoError(t, err, "creating MinIO Core client")

	const (
		bucket = "minio-core-multipart-bucket"
		object = "core-multipart-object.bin"
	)

	// Create the bucket using the high-level MinIO client.
	client := newMinioClient(t, httpSrv)
	require.NoError(t, client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{Region: "us-east-1"}), "MakeBucket via MinIO client")

	// Initiate multipart upload.
	uploadID, err := coreClient.NewMultipartUpload(ctx, bucket, object, minio.PutObjectOptions{ContentType: "application/octet-stream"})
	require.NoError(t, err, "NewMultipartUpload via MinIO Core")
	require.NotEmpty(t, uploadID, "uploadID should not be empty")

	// Prepare three distinct parts and remember their combined payload.
	partData := [][]byte{
		bytes.Repeat([]byte("AAAA"), 256*1024), // ~1 MiB
		bytes.Repeat([]byte("BBBB"), 256*1024),
		bytes.Repeat([]byte("CCCC"), 128*1024), // smaller last part
	}

	var full bytes.Buffer
	parts := make([]minio.CompletePart, 0, len(partData))

	for i, data := range partData {
		partNumber := i + 1
		full.Write(data)

		objPart, err := coreClient.PutObjectPart(ctx, bucket, object, uploadID, partNumber, bytes.NewReader(data), int64(len(data)), minio.PutObjectPartOptions{})
		require.NoErrorf(t, err, "PutObjectPart via MinIO Core for part %d", partNumber)

		parts = append(parts, minio.CompletePart{
			PartNumber: partNumber,
			ETag:       objPart.ETag,
		})
	}

	// Complete the multipart upload.
	_, err = coreClient.CompleteMultipartUpload(ctx, bucket, object, uploadID, parts, minio.PutObjectOptions{ContentType: "application/octet-stream"})
	require.NoError(t, err, "CompleteMultipartUpload via MinIO Core")

	// Fetch the final object via the regular HTTP GET helper and
	// verify its contents match the concatenated parts.
	resp := DoGet(t, httpSrv.URL+"/"+bucket+"/"+object)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET completed multipart object status")

	got, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "reading completed multipart object")
	require.Equal(t, full.Bytes(), got, "completed multipart object payload mismatch")
}

// TestListObjectPartsUsingMinioCore verifies that the ListParts API is
// correctly implemented by exercising it via the MinIO Core
// ListObjectParts helper, including basic pagination behavior.
func TestListObjectPartsUsingMinioCore(t *testing.T) {
	t.Parallel()

	_, httpSrv := NewTestServer(t)
	ctx := t.Context()

	u, err := url.Parse(httpSrv.URL)
	require.NoError(t, err, "parsing test server URL")

	coreClient, err := minio.NewCore(u.Host, &minio.Options{
		Creds:        credentials.NewStaticV4(AccessKeyID, SecretAccessKey, ""),
		Secure:       u.Scheme == "https",
		BucketLookup: minio.BucketLookupPath,
	})
	require.NoError(t, err, "creating MinIO Core client")

	const (
		bucket = "minio-core-list-parts-bucket"
		object = "core-list-parts-object.bin"
	)

	client := newMinioClient(t, httpSrv)
	require.NoError(t, client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{Region: "us-east-1"}), "MakeBucket via MinIO client")

	// Initiate multipart upload and upload three parts.
	uploadID, err := coreClient.NewMultipartUpload(ctx, bucket, object, minio.PutObjectOptions{ContentType: "application/octet-stream"})
	require.NoError(t, err, "NewMultipartUpload via MinIO Core")
	require.NotEmpty(t, uploadID, "uploadID should not be empty")

	partData := [][]byte{
		bytes.Repeat([]byte("AAA"), 256*1024),
		bytes.Repeat([]byte("BBB"), 256*1024),
		bytes.Repeat([]byte("CCC"), 128*1024),
	}

	for i, data := range partData {
		partNumber := i + 1
		_, err := coreClient.PutObjectPart(ctx, bucket, object, uploadID, partNumber, bytes.NewReader(data), int64(len(data)), minio.PutObjectPartOptions{})
		require.NoErrorf(t, err, "PutObjectPart via MinIO Core for part %d", partNumber)
	}

	// List all parts without a marker; expect three entries.
	res, err := coreClient.ListObjectParts(ctx, bucket, object, uploadID, 0, 1000)
	require.NoError(t, err, "ListObjectParts via MinIO Core")
	require.Len(t, res.ObjectParts, 3, "expected three parts listed")
	require.False(t, res.IsTruncated, "expected listing to not be truncated")

	for i, p := range res.ObjectParts {
		require.Equal(t, i+1, p.PartNumber, "part number ordering")
	}

	// Now test pagination: request max-parts=2, then resume from marker.
	resPage1, err := coreClient.ListObjectParts(ctx, bucket, object, uploadID, 0, 2)
	require.NoError(t, err, "ListObjectParts page 1 via MinIO Core")
	require.Len(t, resPage1.ObjectParts, 2, "expected two parts on page 1")
	require.True(t, resPage1.IsTruncated, "expected page 1 to be truncated")
	require.Equal(t, 2, resPage1.NextPartNumberMarker, "expected next marker after page 1 to be 2")

	resPage2, err := coreClient.ListObjectParts(ctx, bucket, object, uploadID, resPage1.NextPartNumberMarker, 2)
	require.NoError(t, err, "ListObjectParts page 2 via MinIO Core")
	require.Len(t, resPage2.ObjectParts, 1, "expected one part on page 2")
	require.False(t, resPage2.IsTruncated, "expected page 2 to not be truncated")
	require.Equal(t, 3, resPage2.ObjectParts[0].PartNumber, "expected part number 3 on page 2")
}

// TestCompleteMultipartUploadWithNoPartsUsingMinioCore verifies that
// attempting to complete a multipart upload with no parts specified
// results in an InvalidRequest error from the server.
func TestCompleteMultipartUploadWithNoPartsUsingMinioCore(t *testing.T) {
	t.Parallel()

	_, httpSrv := NewTestServer(t)
	ctx := t.Context()

	u, err := url.Parse(httpSrv.URL)
	require.NoError(t, err, "parsing test server URL")

	coreClient, err := minio.NewCore(u.Host, &minio.Options{
		Creds:        credentials.NewStaticV4(AccessKeyID, SecretAccessKey, ""),
		Secure:       u.Scheme == "https",
		BucketLookup: minio.BucketLookupPath,
	})
	require.NoError(t, err, "creating MinIO Core client")

	const (
		bucket = "minio-core-multipart-empty-parts-bucket"
		object = "core-multipart-empty-parts-object.bin"
	)

	client := newMinioClient(t, httpSrv)
	require.NoError(t, client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{Region: "us-east-1"}), "MakeBucket via MinIO client")

	uploadID, err := coreClient.NewMultipartUpload(ctx, bucket, object, minio.PutObjectOptions{ContentType: "application/octet-stream"})
	require.NoError(t, err, "NewMultipartUpload via MinIO Core")
	require.NotEmpty(t, uploadID, "uploadID should not be empty")

	// Attempt to complete with no parts.
	_, err = coreClient.CompleteMultipartUpload(ctx, bucket, object, uploadID, nil, minio.PutObjectOptions{ContentType: "application/octet-stream"})
	require.Error(t, err, "expected error when completing with no parts")

	errResp := minio.ToErrorResponse(err)
	require.Equal(t, "InvalidRequest", errResp.Code, "expected InvalidRequest from server for empty parts list")
}

// TestCompleteMultipartUploadMissingPartUsingMinioCore verifies that if a
// part file is missing on disk when completing the upload, the server
// returns an InvalidPart error.
func TestCompleteMultipartUploadMissingPartUsingMinioCore(t *testing.T) {
	t.Parallel()

	srv, httpSrv := NewTestServer(t)
	ctx := t.Context()

	u, err := url.Parse(httpSrv.URL)
	require.NoError(t, err, "parsing test server URL")

	coreClient, err := minio.NewCore(u.Host, &minio.Options{
		Creds:        credentials.NewStaticV4(AccessKeyID, SecretAccessKey, ""),
		Secure:       u.Scheme == "https",
		BucketLookup: minio.BucketLookupPath,
	})
	require.NoError(t, err, "creating MinIO Core client")

	const (
		bucket = "minio-core-multipart-missing-part-bucket"
		object = "core-multipart-missing-part-object.bin"
	)

	client := newMinioClient(t, httpSrv)
	require.NoError(t, client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{Region: "us-east-1"}), "MakeBucket via MinIO client")

	uploadID, err := coreClient.NewMultipartUpload(ctx, bucket, object, minio.PutObjectOptions{ContentType: "application/octet-stream"})
	require.NoError(t, err, "NewMultipartUpload via MinIO Core")
	require.NotEmpty(t, uploadID, "uploadID should not be empty")

	// Upload a single part.
	data := bytes.Repeat([]byte("PART"), 256*1024) // ~1 MiB
	objPart, err := coreClient.PutObjectPart(ctx, bucket, object, uploadID, 1, bytes.NewReader(data), int64(len(data)), minio.PutObjectPartOptions{})
	require.NoError(t, err, "PutObjectPart via MinIO Core")

	parts := []minio.CompletePart{{
		PartNumber: 1,
		ETag:       objPart.ETag,
	}}

	// Remove the underlying part file from disk to simulate corruption.
	partFilename := fmt.Sprintf("part-%06d", 1)
	partPath := filepath.Join(srv.Config.DataDir, "uploads", uploadID, partFilename)
	require.NoError(t, os.Remove(partPath), "removing part file to simulate missing part")

	_, err = coreClient.CompleteMultipartUpload(ctx, bucket, object, uploadID, parts, minio.PutObjectOptions{ContentType: "application/octet-stream"})
	require.Error(t, err, "expected error when completing with missing part file")

	errResp := minio.ToErrorResponse(err)
	require.Equal(t, "InvalidPart", errResp.Code, "expected InvalidPart from server for missing part file")
}

// TestCompleteMultipartUploadAfterAbortUsingMinioCore verifies that trying
// to complete a multipart upload after it has been aborted results in a
// NoSuchUpload error.
func TestCompleteMultipartUploadAfterAbortUsingMinioCore(t *testing.T) {
	t.Parallel()

	_, httpSrv := NewTestServer(t)
	ctx := t.Context()

	u, err := url.Parse(httpSrv.URL)
	require.NoError(t, err, "parsing test server URL")

	coreClient, err := minio.NewCore(u.Host, &minio.Options{
		Creds:        credentials.NewStaticV4(AccessKeyID, SecretAccessKey, ""),
		Secure:       u.Scheme == "https",
		BucketLookup: minio.BucketLookupPath,
	})
	require.NoError(t, err, "creating MinIO Core client")

	const (
		bucket = "minio-core-multipart-abort-complete-bucket"
		object = "core-multipart-abort-complete-object.bin"
	)

	client := newMinioClient(t, httpSrv)
	require.NoError(t, client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{Region: "us-east-1"}), "MakeBucket via MinIO client")

	uploadID, err := coreClient.NewMultipartUpload(ctx, bucket, object, minio.PutObjectOptions{ContentType: "application/octet-stream"})
	require.NoError(t, err, "NewMultipartUpload via MinIO Core")
	require.NotEmpty(t, uploadID, "uploadID should not be empty")

	// Upload a small part so there is something to complete.
	data := []byte("hello-multipart")
	objPart, err := coreClient.PutObjectPart(ctx, bucket, object, uploadID, 1, bytes.NewReader(data), int64(len(data)), minio.PutObjectPartOptions{})
	require.NoError(t, err, "PutObjectPart via MinIO Core")

	parts := []minio.CompletePart{{
		PartNumber: 1,
		ETag:       objPart.ETag,
	}}

	// Abort the multipart upload first.
	require.NoError(t, coreClient.AbortMultipartUpload(ctx, bucket, object, uploadID), "AbortMultipartUpload via MinIO Core")

	// Attempt to complete after abort should fail with NoSuchUpload.
	_, err = coreClient.CompleteMultipartUpload(ctx, bucket, object, uploadID, parts, minio.PutObjectOptions{ContentType: "application/octet-stream"})
	require.Error(t, err, "expected error when completing after abort")

	errResp := minio.ToErrorResponse(err)
	require.Equal(t, "NoSuchUpload", errResp.Code, "expected NoSuchUpload from server after abort")
}

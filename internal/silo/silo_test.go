package silo

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
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
	dbPath := filepath.Join(dataDir, "test.sqlite")

	srv, err := NewServer(Config{DataDir: dataDir, DBPath: dbPath})
	require.NoError(t, err, "NewServer error")

	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	return srv, httpSrv
}

func TestCreateAndListBuckets(t *testing.T) {
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

func TestPutGetHeadDeleteObject(t *testing.T) {
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
	objPath := filepath.Join(srv.cfg.DataDir, subdir, hashHex)

	_, err = os.Stat(objPath)
	require.NoErrorf(t, err, "expected object file at %s", objPath)
}

func TestListObjects(t *testing.T) {
	_, httpSrv := newTestServer(t)
	client := httpSrv.Client()

	bucket := "list-bucket"

	// PUT several objects.
	objects := map[string]string{
		"a.txt":      "aaa",
		"dir/b.txt":  "bbb",
		"dir/c.log":  "ccc",
		"other/file": "ddd",
	}

	for key, body := range objects {
		req, err := http.NewRequest(http.MethodPut, httpSrv.URL+"/"+bucket+"/"+key, io.NopCloser(bytes.NewReader([]byte(body))))
		require.NoErrorf(t, err, "creating PUT request for %s", key)
		resp, err := client.Do(req)
		require.NoErrorf(t, err, "PUT object %s error", key)
		resp.Body.Close()
		require.Equalf(t, http.StatusOK, resp.StatusCode, "PUT object %s status", key)
	}

	// List all objects in bucket.
	resp, err := client.Get(httpSrv.URL + "/" + bucket)
	require.NoError(t, err, "GET bucket error")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET bucket status")

	var listResp ListBucketResult
	require.NoError(t, xml.NewDecoder(resp.Body).Decode(&listResp), "decoding ListBucketResult")

	seen := map[string]bool{}
	for _, c := range listResp.Contents {
		seen[c.Key] = true
	}
	for key := range objects {
		require.Truef(t, seen[key], "expected key %q in ListBucketResult", key)
	}

	// List with prefix
	resp, err = client.Get(httpSrv.URL + "/" + bucket + "?prefix=dir/")
	require.NoError(t, err, "GET bucket with prefix error")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET bucket with prefix status")

	listResp = ListBucketResult{}
	require.NoError(t, xml.NewDecoder(resp.Body).Decode(&listResp), "decoding ListBucketResult with prefix")

	for _, c := range listResp.Contents {
		require.Truef(t, strings.HasPrefix(c.Key, "dir/"), "expected key with prefix 'dir/'; got %q", c.Key)
	}
}

func TestErrorResponsesTableDriven(t *testing.T) {
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

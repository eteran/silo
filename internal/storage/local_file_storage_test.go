package storage_test

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"silo/internal/storage"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLocalFileStoragePutAndGet(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	engine := storage.NewLocalFileStorage(dataDir)
	const bucket = "example"

	payload := []byte("hello local storage")
	sum := sha256.Sum256(payload)
	hashHex := hex.EncodeToString(sum[:])

	// Put should succeed and create the expected path on disk.
	require.NoError(t, engine.PutObject(bucket, hashHex, payload), "PutObject error")

	objPath, err := storage.ObjectPath(dataDir, hashHex)
	require.NoError(t, err, "ObjectPath error")

	info, err := os.Stat(objPath)
	require.NoError(t, err, "expected object file to exist")
	require.False(t, info.IsDir(), "object path should be a file")

	// Get should return the same payload.
	got, err := engine.GetObject(bucket, hashHex)
	require.NoError(t, err, "GetObject error")
	require.Equal(t, payload, got, "payload mismatch")
}

func TestLocalFileStorageInvalidHash(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	engine := storage.NewLocalFileStorage(dataDir)
	const bucket = "example"

	// Hash shorter than 2 characters should be rejected by objectPath.
	err := engine.PutObject(bucket, "a", []byte("data"))
	require.Error(t, err, "expected error for too-short hash")

	_, err = engine.GetObject(bucket, "a")
	require.Error(t, err, "expected error for too-short hash on GetObject")
}

func TestLocalFileStorageDeleteIsNoop(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	engine := storage.NewLocalFileStorage(dataDir)
	const bucket = "example"

	// DeleteObject is currently defined as a no-op and should never error,
	// even for unknown hashes.
	err := engine.DeleteObject(bucket, "deadbeef")
	require.NoError(t, err, "DeleteObject should be a no-op without error")
}

func TestLocalFileStorageHardLinksAcrossBuckets(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	engine := storage.NewLocalFileStorage(dataDir)

	payload := []byte("shared payload")
	sum := sha256.Sum256(payload)
	hashHex := hex.EncodeToString(sum[:])

	const bucket1 = "bucket1"
	const bucket2 = "bucket2"

	require.NoError(t, engine.PutObject(bucket1, hashHex, payload), "PutObject bucket1 error")
	require.NoError(t, engine.PutObject(bucket2, hashHex, payload), "PutObject bucket2 error")

	objPath, err := storage.ObjectPath(dataDir, hashHex)
	require.NoError(t, err, "ObjectPath error")

	info, err := os.Stat(objPath)
	require.NoError(t, err, "expected single object file for shared payload")
	require.False(t, info.IsDir(), "object path should be a file")
}

func TestLocalFileStorageWithGzipPutAndGet(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	engine := storage.NewLocalFileStorageWithGzip(dataDir)
	const bucket = "example-gzip"

	payload := []byte("hello local storage with gzip")
	sum := sha256.Sum256(payload)
	hashHex := hex.EncodeToString(sum[:])

	require.NoError(t, engine.PutObject(bucket, hashHex, payload), "PutObject error")

	objPath, err := storage.ObjectPath(dataDir, hashHex)
	require.NoError(t, err, "ObjectPath error")

	// On disk, the payload should be gzip-compressed and prefixed with the
	// magic header, while GetObject should transparently return the original
	// bytes.
	raw, err := os.ReadFile(objPath)
	require.NoError(t, err, "reading stored object")
	require.Greater(t, len(raw), len(payload), "compressed representation should include header and gzip wrapper")
	require.True(t, bytes.HasPrefix(raw, []byte("SILO_GZ1\n")), "stored object should have gzip magic header")

	// Strip the magic header and ensure the remainder is valid gzip.
	gr, err := gzip.NewReader(bytes.NewReader(raw[len("SILO_GZ1\n"):]))
	require.NoError(t, err, "expected valid gzip data after magic header")
	defer gr.Close()

	uncompressed, err := io.ReadAll(gr)
	require.NoError(t, err, "decompressing stored object")
	require.Equal(t, payload, uncompressed, "decompressed payload mismatch")

	got, err := engine.GetObject(bucket, hashHex)
	require.NoError(t, err, "GetObject error")
	require.Equal(t, payload, got, "payload mismatch after gzip round-trip")
}

func TestLocalFileStorageWithGzipReadsLegacyUncompressed(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	engine := storage.NewLocalFileStorageWithGzip(dataDir)
	const bucket = "legacy-bucket"

	payload := []byte("legacy uncompressed payload")
	sum := sha256.Sum256(payload)
	hashHex := hex.EncodeToString(sum[:])

	objPath, err := storage.ObjectPath(dataDir, hashHex)
	require.NoError(t, err, "ObjectPath error")

	require.NoError(t, os.MkdirAll(filepath.Dir(objPath), 0o755))
	require.NoError(t, os.WriteFile(objPath, payload, 0o644))

	got, err := engine.GetObject(bucket, hashHex)
	require.NoError(t, err, "GetObject error for legacy object")
	require.Equal(t, payload, got, "legacy uncompressed payload mismatch")
}

// TestLocalFileStorageConcurrentPutObject verifies that concurrent PutObject
// calls for the same hash do not race or corrupt the stored file when using
// the file-based locking mechanism.
func TestLocalFileStorageConcurrentPutObject(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	engine := storage.NewLocalFileStorage(dataDir)
	const bucket = "concurrent-bucket"

	payload := bytes.Repeat([]byte("0123456789abcdef"), 1024) // 16 KiB
	sum := sha256.Sum256(payload)
	hashHex := hex.EncodeToString(sum[:])

	var wg sync.WaitGroup
	concurrency := 8
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each goroutine attempts to write the same object; all should
			// succeed without data corruption.
			require.NoError(t, engine.PutObject(bucket, hashHex, payload))
		}()
	}
	wg.Wait()

	objPath, err := storage.ObjectPath(dataDir, hashHex)
	require.NoError(t, err, "ObjectPath error")

	data, err := os.ReadFile(objPath)
	require.NoError(t, err, "reading stored object")
	require.Equal(t, payload, data, "concurrent writes should not corrupt payload")
}

// TestLocalFileStorageConcurrentPutObjectFromFile verifies that concurrent
// PutObjectFromFile calls for the same hash do not race in a way that
// corrupts the final stored file.
func TestLocalFileStorageConcurrentPutObjectFromFile(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	engine := storage.NewLocalFileStorage(dataDir)
	const bucket = "concurrent-file-bucket"

	payload := bytes.Repeat([]byte("abcdef0123456789"), 1024) // 16 KiB
	sum := sha256.Sum256(payload)
	hashHex := hex.EncodeToString(sum[:])

	tempRoot := filepath.Join(dataDir, "tmp")
	require.NoError(t, os.MkdirAll(tempRoot, 0o755))

	var wg sync.WaitGroup
	concurrency := 4
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			tempPath := filepath.Join(tempRoot, fmt.Sprintf("upload-%d.tmp", idx))
			require.NoError(t, os.WriteFile(tempPath, payload, 0o644))

			// Size is not currently used by PutObjectFromFile, but pass the
			// actual payload length for clarity.
			require.NoError(t, engine.PutObjectFromFile(bucket, hashHex, tempPath, int64(len(payload))))
		}(i)
	}
	wg.Wait()

	objPath, err := storage.ObjectPath(dataDir, hashHex)
	require.NoError(t, err, "ObjectPath error")

	data, err := os.ReadFile(objPath)
	require.NoError(t, err, "reading stored object")
	require.Equal(t, payload, data, "concurrent PutObjectFromFile writes should not corrupt payload")
}

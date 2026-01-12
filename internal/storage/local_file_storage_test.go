package storage_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"silo/internal/storage"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLocalFileStoragePutAndGet(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	engine := storage.NewLocalFileStorage(dataDir)
	bucket := "example"

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
	bucket := "bucket"

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
	bucket := "bucket"

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

	bucket1 := "bucket1"
	bucket2 := "bucket2"

	require.NoError(t, engine.PutObject(bucket1, hashHex, payload), "PutObject bucket1 error")
	require.NoError(t, engine.PutObject(bucket2, hashHex, payload), "PutObject bucket2 error")

	objPath, err := storage.ObjectPath(dataDir, hashHex)
	require.NoError(t, err, "ObjectPath error")

	info, err := os.Stat(objPath)
	require.NoError(t, err, "expected single object file for shared payload")
	require.False(t, info.IsDir(), "object path should be a file")

	// With the new layout, data is stored globally by hash, not per-bucket.
	// There should be no per-bucket subdirectories created under dataDir.
	_, err = os.Stat(filepath.Join(dataDir, bucket1))
	require.Error(t, err, "no per-bucket directory should exist for bucket1")
	_, err = os.Stat(filepath.Join(dataDir, bucket2))
	require.Error(t, err, "no per-bucket directory should exist for bucket2")
}

package silo

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLocalFileStoragePutAndGet(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	engine := NewLocalFileStorage(dataDir)
	bucket := "example"

	payload := []byte("hello local storage")
	sum := sha256.Sum256(payload)
	hashHex := hex.EncodeToString(sum[:])

	// Put should succeed and create the expected path on disk.
	require.NoError(t, engine.PutObject(bucket, hashHex, payload), "PutObject error")

	subdir := hashHex[:2]
	objPath := filepath.Join(dataDir, bucket, subdir, hashHex)

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
	engine := NewLocalFileStorage(dataDir)
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
	engine := NewLocalFileStorage(dataDir)
	bucket := "bucket"

	// DeleteObject is currently defined as a no-op and should never error,
	// even for unknown hashes.
	err := engine.DeleteObject(bucket, "deadbeef")
	require.NoError(t, err, "DeleteObject should be a no-op without error")
}

func TestLocalFileStorageHardLinksAcrossBuckets(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	engine := NewLocalFileStorage(dataDir)

	payload := []byte("shared payload")
	sum := sha256.Sum256(payload)
	hashHex := hex.EncodeToString(sum[:])

	bucket1 := "bucket1"
	bucket2 := "bucket2"

	require.NoError(t, engine.PutObject(bucket1, hashHex, payload), "PutObject bucket1 error")
	require.NoError(t, engine.PutObject(bucket2, hashHex, payload), "PutObject bucket2 error")

	subdir := hashHex[:2]
	path1 := filepath.Join(dataDir, bucket1, subdir, hashHex)
	path2 := filepath.Join(dataDir, bucket2, subdir, hashHex)

	info1, err := os.Stat(path1)
	require.NoError(t, err, "expected object file for bucket1")
	info2, err := os.Stat(path2)
	require.NoError(t, err, "expected object file for bucket2")

	require.Equal(t, info1.Size(), info2.Size(), "sizes should match")
	require.True(t, os.SameFile(info1, info2), "files should be hard-linked (same inode)")
}

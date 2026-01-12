package storage_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"silo/internal/storage"
	"strings"
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
	engine := storage.NewLocalFileStorage(dataDir)
	bucket := "bucket"

	// Hash shorter than 2 characters should be rejected by objectPath.
	err := engine.PutObject(bucket, "a", []byte("data"))
	require.Error(t, err, "expected error for too-short hash")

	_, err = engine.GetObject(bucket, "a")
	require.Error(t, err, "expected error for too-short hash on GetObject")
}

func TestLocalFileStorageCopyObjectInvalidHash(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	engine := storage.NewLocalFileStorage(dataDir)

	err := engine.CopyObject("src", "a", "dest")
	require.Error(t, err, "expected error for too-short hash on CopyObject")
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

func TestLocalFileStorageCopyObjectAcrossBuckets(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	engine := storage.NewLocalFileStorage(dataDir)

	payload := []byte("copied payload")
	sum := sha256.Sum256(payload)
	hashHex := hex.EncodeToString(sum[:])

	srcBucket := "src-bucket"
	destBucket := "dest-bucket"

	require.NoError(t, engine.PutObject(srcBucket, hashHex, payload), "PutObject srcBucket error")

	require.NoError(t, engine.CopyObject(srcBucket, hashHex, destBucket), "CopyObject error")

	subdir := hashHex[:2]
	srcPath := filepath.Join(dataDir, srcBucket, subdir, hashHex)
	destPath := filepath.Join(dataDir, destBucket, subdir, hashHex)

	infoSrc, err := os.Stat(srcPath)
	require.NoError(t, err, "expected source object file")
	infoDst, err := os.Stat(destPath)
	require.NoError(t, err, "expected dest object file")

	require.True(t, os.SameFile(infoSrc, infoDst), "files should be hard-linked after CopyObject")
}

func TestLocalFileStorageCopyObjectMissingSource(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	engine := storage.NewLocalFileStorage(dataDir)

	err := engine.CopyObject("missing-bucket", strings.Repeat("0", 64), "dest-bucket")
	require.Error(t, err, "expected error when source object file is missing")
}

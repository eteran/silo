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
	dataDir := t.TempDir()
	engine := NewLocalFileStorage(dataDir)

	payload := []byte("hello local storage")
	sum := sha256.Sum256(payload)
	hashHex := hex.EncodeToString(sum[:])

	// Put should succeed and create the expected path on disk.
	require.NoError(t, engine.PutObject(hashHex, payload), "PutObject error")

	subdir := hashHex[:2]
	objPath := filepath.Join(dataDir, subdir, hashHex)

	info, err := os.Stat(objPath)
	require.NoError(t, err, "expected object file to exist")
	require.False(t, info.IsDir(), "object path should be a file")

	// Get should return the same payload.
	got, err := engine.GetObject(hashHex)
	require.NoError(t, err, "GetObject error")
	require.Equal(t, payload, got, "payload mismatch")
}

func TestLocalFileStorageInvalidHash(t *testing.T) {
	dataDir := t.TempDir()
	engine := NewLocalFileStorage(dataDir)

	// Hash shorter than 2 characters should be rejected by objectPath.
	err := engine.PutObject("a", []byte("data"))
	require.Error(t, err, "expected error for too-short hash")

	_, err = engine.GetObject("a")
	require.Error(t, err, "expected error for too-short hash on GetObject")
}

func TestLocalFileStorageDeleteIsNoop(t *testing.T) {
	dataDir := t.TempDir()
	engine := NewLocalFileStorage(dataDir)

	// DeleteObject is currently defined as a no-op and should never error,
	// even for unknown hashes.
	err := engine.DeleteObject("deadbeef")
	require.NoError(t, err, "DeleteObject should be a no-op without error")
}

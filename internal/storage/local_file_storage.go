package storage

import (
	"fmt"
	"os"
	"path/filepath"
)

// LocalFileStorage is a StorageEngine implementation that stores object
// payloads on the local filesystem under a content-addressed layout rooted at
// dataDir. Objects are addressed globally by their full SHA-256 hexadecimal
// hash, with the first two characters used as a subdirectory prefix. Buckets
// are tracked in metadata only and do not affect the on-disk layout.
type LocalFileStorage struct {
	dataDir string
}

// NewLocalFileStorage creates a new LocalFileStorage rooted at dataDir.
func NewLocalFileStorage(dataDir string) *LocalFileStorage {
	return &LocalFileStorage{dataDir: dataDir}
}

// ObjectPath computes the full filesystem path for the object identified by
// hashHex
func ObjectPath(directory string, hashHex string) (string, error) {
	if len(hashHex) < 2 {
		return "", fmt.Errorf("invalid hash length: %d", len(hashHex))
	}
	subdir := hashHex[:2]
	return filepath.Join(directory, "objects", subdir, hashHex), nil
}

// PutObject stores the given data as the object identified by hashHex.
func (s *LocalFileStorage) PutObject(bucket string, hashHex string, data []byte) error {
	objPath, err := ObjectPath(s.dataDir, hashHex)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(objPath), 0o755); err != nil {
		return err
	}

	return os.WriteFile(objPath, data, 0o644)
}

// PutObjectFromFile stores an object whose payload already exists on disk at
// tempPath. It uses the same content-addressed layout a as PutObject,
// but avoids loading the entire payload into memory.
func (s *LocalFileStorage) PutObjectFromFile(bucket string, hashHex string, tempPath string, size int64) error {
	objPath, err := ObjectPath(s.dataDir, hashHex)
	if err != nil {
		return err
	}

	// No existing compatible payload; move/copy the temp file into place.
	if err := os.MkdirAll(filepath.Dir(objPath), 0o755); err != nil {
		return err
	}

	if err := os.Rename(tempPath, objPath); err != nil {
		return err
	}

	return nil
}

// GetObject retrieves the object payload identified by hashHex.
func (s *LocalFileStorage) GetObject(bucket string, hashHex string) ([]byte, error) {
	objPath, err := ObjectPath(s.dataDir, hashHex)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(objPath)
}

func (s *LocalFileStorage) DeleteObject(bucket string, hashHex string) error {
	// Intentionally a no-op for now; garbage collection of unreferenced
	// payloads can be implemented separately.
	_ = bucket
	_ = hashHex
	return nil
}

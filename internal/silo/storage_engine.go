package silo

import (
	"fmt"
	"os"
	"path/filepath"
)

type StorageEngine interface {
	// PutObject stores the raw object payload identified by its SHA-256
	// hexadecimal hash. The caller is responsible for computing the hash and
	// ensuring it is stable for a given payload.
	PutObject(hashHex string, data []byte) error

	// GetObject retrieves the raw object payload previously stored under the
	// given SHA-256 hexadecimal hash.
	GetObject(hashHex string) ([]byte, error)

	// DeleteObject removes the payload associated with the given hash. The
	// current implementation of LocalFileStorage keeps this as a no-op so that
	// unreferenced payloads can be garbage-collected separately.
	DeleteObject(hashHex string) error
}

// LocalFileStorage is a StorageEngine implementation that stores object
// payloads on the local filesystem under a content-addressed layout rooted at
// dataDir. Objects are addressed by their full SHA-256 hexadecimal hash, with
// the first two characters used as a subdirectory prefix.
type LocalFileStorage struct {
	dataDir string
}

// NewLocalFileStorage creates a new LocalFileStorage rooted at dataDir.
func NewLocalFileStorage(dataDir string) *LocalFileStorage {
	return &LocalFileStorage{dataDir: dataDir}
}

func (s *LocalFileStorage) objectPath(hashHex string) (string, error) {
	if len(hashHex) < 2 {
		return "", fmt.Errorf("invalid hash length: %d", len(hashHex))
	}
	subdir := hashHex[:2]
	storeDir := filepath.Join(s.dataDir, subdir)
	return filepath.Join(storeDir, hashHex), nil
}

func (s *LocalFileStorage) PutObject(hashHex string, data []byte) error {
	objPath, err := s.objectPath(hashHex)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(objPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(objPath, data, 0o644)
}

func (s *LocalFileStorage) GetObject(hashHex string) ([]byte, error) {
	objPath, err := s.objectPath(hashHex)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(objPath)
}

func (s *LocalFileStorage) DeleteObject(hashHex string) error {
	// Intentionally a no-op for now; garbage collection of unreferenced
	// payloads can be implemented separately.
	_ = hashHex
	return nil
}

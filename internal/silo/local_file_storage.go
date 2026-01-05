package silo

import (
	"fmt"
	"os"
	"path/filepath"
)

// LocalFileStorage is a StorageEngine implementation that stores object
// payloads on the local filesystem under a content-addressed layout rooted at
// dataDir. Each bucket gets its own subdirectory, and within each bucket
// objects are addressed by their full SHA-256 hexadecimal hash, with the
// first two characters used as a subdirectory prefix.
type LocalFileStorage struct {
	dataDir string
}

// NewLocalFileStorage creates a new LocalFileStorage rooted at dataDir.
func NewLocalFileStorage(dataDir string) *LocalFileStorage {
	return &LocalFileStorage{dataDir: dataDir}
}

func (s *LocalFileStorage) objectPath(bucket, hashHex string) (string, error) {
	if len(hashHex) < 2 {
		return "", fmt.Errorf("invalid hash length: %d", len(hashHex))
	}
	subdir := hashHex[:2]
	bucketDir := filepath.Join(s.dataDir, bucket)
	storeDir := filepath.Join(bucketDir, subdir)
	return filepath.Join(storeDir, hashHex), nil
}

func (s *LocalFileStorage) PutObject(bucket string, hashHex string, data []byte) error {
	objPath, err := s.objectPath(bucket, hashHex)
	if err != nil {
		return err
	}

	// If an object with the same hash and size already exists in any bucket,
	// create a hard link instead of writing a new copy.
	subdir := hashHex[:2]
	pattern := filepath.Join(s.dataDir, "*", subdir, hashHex)
	matches, _ := filepath.Glob(pattern)
	for _, existing := range matches {
		if existing == objPath {
			continue
		}
		info, err := os.Stat(existing)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if info.Size() != int64(len(data)) {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(objPath), 0o755); err != nil {
			return err
		}
		if err := os.Link(existing, objPath); err == nil {
			return nil
		}
	}

	if err := os.MkdirAll(filepath.Dir(objPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(objPath, data, 0o644)
}

func (s *LocalFileStorage) GetObject(bucket string, hashHex string) ([]byte, error) {
	objPath, err := s.objectPath(bucket, hashHex)
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

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

// PutObjectFromFile stores an object whose payload already exists on disk at
// tempPath. It uses the same content-addressed layout and cross-bucket
// deduplication strategy as PutObject, but avoids loading the entire payload
// into memory.
func (s *LocalFileStorage) PutObjectFromFile(bucket string, hashHex string, tempPath string, size int64) error {
	objPath, err := s.objectPath(bucket, hashHex)
	if err != nil {
		return err
	}

	// If an object with the same hash and size already exists in any bucket,
	// create a hard link instead of moving or copying the temp file.
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
		if info.Size() != size {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(objPath), 0o755); err != nil {
			return err
		}
		if err := os.Link(existing, objPath); err == nil {
			return nil
		}
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

// CopyObject ensures that the payload identified by hashHex is present in the
// destination bucket. When possible, it creates a hard link from an existing
// copy of the payload instead of reading and rewriting the data.
func (s *LocalFileStorage) CopyObject(srcBucket, hashHex, destBucket string) error {
	srcPath, err := s.objectPath(srcBucket, hashHex)
	if err != nil {
		return err
	}

	destPath, err := s.objectPath(destBucket, hashHex)
	if err != nil {
		return err
	}

	// If source and destination paths are identical, nothing to do.
	if srcPath == destPath {
		return nil
	}

	// Ensure the source exists before attempting to link.
	info, err := os.Stat(srcPath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("source is not a regular file: %s", srcPath)
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return err
	}

	// Attempt to create a hard link from src to dest. If a file already exists
	// at destPath, leave it as-is.
	if _, err := os.Stat(destPath); err == nil {
		return nil
	}

	return os.Link(srcPath, destPath)
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

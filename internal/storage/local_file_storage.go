package storage

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

// ObjectPath computes the full filesystem path for the object identified by
// hashHex within the given bucket.
func ObjectPath(directory string, bucket string, hashHex string) (string, error) {
	if len(hashHex) < 2 {
		return "", fmt.Errorf("invalid hash length: %d", len(hashHex))
	}
	subdir := hashHex[:2]
	return filepath.Join(directory, bucket, subdir, hashHex), nil
}

func LocateExistingObject(directory string, targetObject string, hashHex string, size int64) []string {
	// If an object with the same hash and size already exists in any bucket,
	// create a hard link instead of writing a new copy.
	subdir := hashHex[:2]
	pattern := filepath.Join(directory, "*", subdir, hashHex)
	matches, _ := filepath.Glob(pattern)

	results := make([]string, 0)
	for _, existing := range matches {
		if existing == targetObject {
			continue
		}

		info, err := os.Stat(existing)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}

		if info.Size() != size {
			continue
		}

		results = append(results, existing)
	}

	return results
}

func (s *LocalFileStorage) PutObject(bucket string, hashHex string, data []byte) error {
	objPath, err := ObjectPath(s.dataDir, bucket, hashHex)
	if err != nil {
		return err
	}

	// If an object with the same hash and size already exists in any bucket,
	// create a hard link instead of writing a new copy.
	matches := LocateExistingObject(s.dataDir, objPath, hashHex, int64(len(data)))
	for _, existing := range matches {
		if err := os.MkdirAll(filepath.Dir(objPath), 0o755); err != nil {
			return err
		}
		if err := CopyOrLinkFile(existing, objPath); err == nil {
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
	objPath, err := ObjectPath(s.dataDir, bucket, hashHex)
	if err != nil {
		return err
	}

	// If an object with the same hash and size already exists in any bucket,
	// create a hard link instead of writing a new copy.
	matches := LocateExistingObject(s.dataDir, objPath, hashHex, size)
	for _, existing := range matches {
		if err := os.MkdirAll(filepath.Dir(objPath), 0o755); err != nil {
			return err
		}
		if err := CopyOrLinkFile(existing, objPath); err == nil {
			return nil
		}
	}

	// No existing compatible payload; move/copy the temp file into place.
	if err := os.MkdirAll(filepath.Dir(objPath), 0o755); err != nil {
		return err
	}

	if err := MoveFile(tempPath, objPath); err != nil {
		return err
	}

	return nil
}

// CopyObject ensures that the payload identified by hashHex is present in the
// destination bucket. When possible, it creates a hard link from an existing
// copy of the payload instead of reading and rewriting the data.
func (s *LocalFileStorage) CopyObject(srcBucket, hashHex, destBucket string) error {
	srcPath, err := ObjectPath(s.dataDir, srcBucket, hashHex)
	if err != nil {
		return err
	}

	destPath, err := ObjectPath(s.dataDir, destBucket, hashHex)
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

	return CopyOrLinkFile(srcPath, destPath)
}

func (s *LocalFileStorage) GetObject(bucket string, hashHex string) ([]byte, error) {
	objPath, err := ObjectPath(s.dataDir, bucket, hashHex)
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

// DeleteBucket removes all on-disk payloads for the given bucket by
// recursively deleting the bucket's directory under the storage root.
func (s *LocalFileStorage) DeleteBucket(bucket string) error {
	bucketPath := filepath.Join(s.dataDir, bucket)
	return os.RemoveAll(bucketPath)
}

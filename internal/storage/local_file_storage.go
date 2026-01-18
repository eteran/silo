package storage

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// LocalFileStorage is a StorageEngine implementation that stores object
// payloads on the local filesystem under a content-addressed layout rooted at
// dataDir. Objects are addressed globally by their full SHA-256 hexadecimal
// hash, with the first two characters used as a subdirectory prefix. Buckets
// are tracked in metadata only and do not affect the on-disk layout.
type LocalFileStorage struct {
	dataDir  string
	compress bool
}

// NewLocalFileStorage creates a new LocalFileStorage rooted at dataDir.
func NewLocalFileStorage(dataDir string) *LocalFileStorage {
	return &LocalFileStorage{dataDir: dataDir}
}

// NewLocalFileStorageWithGzip creates a new LocalFileStorage rooted at
// dataDir that transparently gzips payloads on disk while still returning
// the original (decompressed) bytes from GetObject. Existing uncompressed
// objects remain readable.
func NewLocalFileStorageWithGzip(dataDir string) *LocalFileStorage {
	return &LocalFileStorage{dataDir: dataDir, compress: true}
}

// ObjectPath computes the full filesystem path for the object identified by
// hashHex
func ObjectPath(directory string, hashHex string) (string, error) {
	if len(hashHex) < 4 {
		return "", fmt.Errorf("invalid hash length: %d", len(hashHex))
	}
	subdir := hashHex[:2] + string(os.PathSeparator) + hashHex[2:4]
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

	lock, err := acquireLock(objPath)
	if err != nil {
		return err
	}
	defer lock.Unlock()

	if !s.compress {
		return os.WriteFile(objPath, data, 0o644)
	}

	dst, err := os.OpenFile(objPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer dst.Close()

	if _, err := dst.Write([]byte(gzipMagicHeader)); err != nil {
		return err
	}

	gw := gzip.NewWriter(dst)
	defer func() {
		_ = gw.Close()
	}()

	if _, err := gw.Write(data); err != nil {
		return err
	}

	return nil
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

	lock, err := acquireLock(objPath)
	if err != nil {
		return err
	}
	defer lock.Unlock()

	if !s.compress {
		if err := os.Rename(tempPath, objPath); err != nil {
			return err
		}
		return nil
	}

	src, err := os.Open(tempPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.OpenFile(objPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer dst.Close()

	if _, err := dst.Write([]byte(gzipMagicHeader)); err != nil {
		return err
	}

	gw := gzip.NewWriter(dst)
	if _, err := io.Copy(gw, src); err != nil {
		_ = gw.Close()
		return err
	}
	if err := gw.Close(); err != nil {
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

	lock, err := acquireLock(objPath)
	if err != nil {
		return nil, err
	}
	defer lock.Unlock()

	data, err := os.ReadFile(objPath)
	if err != nil {
		return nil, err
	}

	// If gzip compression is disabled, return the raw bytes.
	if !s.compress {
		return data, nil
	}

	// When gzip compression is enabled, we support both the newer
	// gzip-wrapped format (with a magic header) and legacy uncompressed
	// objects. This allows toggling compression without breaking
	// existing data.
	if len(data) >= len(gzipMagicHeader) && bytes.Equal(data[:len(gzipMagicHeader)], []byte(gzipMagicHeader)) {
		gr, err := gzip.NewReader(bytes.NewReader(data[len(gzipMagicHeader):]))
		if err != nil {
			return nil, err
		}
		defer gr.Close()

		uncompressed, err := io.ReadAll(gr)
		if err != nil {
			return nil, err
		}
		return uncompressed, nil
	}

	// Fallback for legacy uncompressed objects.
	return data, nil
}

func (s *LocalFileStorage) DeleteObject(bucket string, hashHex string) error {
	// Intentionally a no-op for now; garbage collection of unreferenced
	// payloads can be implemented separately.

	return nil
}

// FileLock represents a best-effort, per-path lock implemented via a
// companion ".lock" file. It is intended for coarse-grained mutual
// exclusion around writes in a single-node deployment.
type FileLock struct {
	path string
}

// gzipMagicHeader is a short marker written ahead of gzip-compressed
// payloads on disk. It allows LocalFileStorage to distinguish between
// legacy uncompressed objects and newer gzip-wrapped ones when
// compression is enabled.
const gzipMagicHeader = "SILO_GZ1\n"

// acquireLock attempts to create a lock file next to the target path
// using O_CREATE|O_EXCL, retrying for a short bounded period if the lock
// already exists.
func acquireLock(targetPath string) (*FileLock, error) {
	lockPath := targetPath + ".lock"
	const (
		MaxWait   = 5 * time.Second
		SleepStep = 10 * time.Millisecond
	)

	deadline := time.Now().Add(MaxWait)
	for {
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			// Successfully created the lock file; we no longer need the handle.
			_ = f.Close()
			return &FileLock{path: lockPath}, nil
		}

		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("acquire lock for %s: %w", targetPath, err)
		}

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timeout acquiring lock for %s", targetPath)
		}

		time.Sleep(SleepStep)
	}
}

// Unlock releases the file-based lock. Errors are ignored except for the
// case where the lock file unexpectedly persists, which is benign for Silo's
// single-node usage.
func (l *FileLock) Unlock() {
	if l == nil || l.path == "" {
		return
	}

	if err := os.Remove(l.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		// Best-effort cleanup; ignore failures.
		_ = err
	}
}

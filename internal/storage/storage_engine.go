package storage

// StorageEngine defines the interface for a storage backend that manages
// object payloads organized into buckets, identified by their SHA-256
// hexadecimal hashes.

type StorageEngine interface {
	// PutObject stores the raw object payload identified by its SHA-256
	// hexadecimal hash.
	PutObject(bucket string, hashHex string, data []byte) error

	// PutObjectFromFile stores the payload identified by its SHA-256
	// hexadecimal hash, using the contents of the file at tempPath.
	PutObjectFromFile(bucket string, hashHex string, tempPath string, size int64) error

	// GetObject retrieves the raw object payload previously stored under the
	// SHA-256 hexadecimal hash.
	GetObject(bucket string, hashHex string) ([]byte, error)

	// DeleteObject removes the payload associated with the given hash.
	DeleteObject(bucket string, hashHex string) error
}

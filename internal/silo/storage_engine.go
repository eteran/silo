package silo

type StorageEngine interface {
	// PutObject stores the raw object payload identified by its SHA-256
	// hexadecimal hash within the given bucket. The caller is responsible for
	// computing the hash and ensuring it is stable for a given payload.
	PutObject(bucket string, hashHex string, data []byte) error

	// GetObject retrieves the raw object payload previously stored under the
	// given bucket and SHA-256 hexadecimal hash.
	GetObject(bucket string, hashHex string) ([]byte, error)

	// DeleteObject removes the payload associated with the given hash in the
	// specified bucket. The current implementation of LocalFileStorage keeps
	// this as a no-op so that unreferenced payloads can be garbage-collected
	// separately.
	DeleteObject(bucket string, hashHex string) error
}

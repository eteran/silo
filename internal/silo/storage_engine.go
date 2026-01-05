package silo

type StorageEngine interface {
	// PutObject stores the raw object payload identified by its SHA-256
	// hexadecimal hash within the given bucket. The caller is responsible for
	// computing the hash and ensuring it is stable for a given payload.
	PutObject(bucket string, hashHex string, data []byte) error

	// PutObjectFromFile stores the payload identified by its SHA-256
	// hexadecimal hash within the given bucket, using the contents of the
	// file at tempPath. Implementations may move, copy, or hard-link this
	// file into their content-addressed store. The size argument is the
	// length of the decoded payload in bytes.
	PutObjectFromFile(bucket string, hashHex string, tempPath string, size int64) error

	// GetObject retrieves the raw object payload previously stored under the
	// given bucket and SHA-256 hexadecimal hash.
	GetObject(bucket string, hashHex string) ([]byte, error)

	// CopyObject ensures that the payload identified by hashHex is present in
	// the destination bucket, reusing storage where possible. Implementations
	// are expected to avoid reading and rewriting the payload when a more
	// efficient mechanism (such as hard links) is available.
	CopyObject(srcBucket, hashHex, destBucket string) error

	// DeleteObject removes the payload associated with the given hash in the
	// specified bucket. The current implementation of LocalFileStorage keeps
	// this as a no-op so that unreferenced payloads can be garbage-collected
	// separately.
	DeleteObject(bucket string, hashHex string) error
}

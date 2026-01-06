package silo

type StorageEngine interface {
	// PutObject stores the raw object payload identified by its SHA-256
	// hexadecimal hash within the given bucket.
	PutObject(bucket string, hashHex string, data []byte) error

	// PutObjectFromFile stores the payload identified by its SHA-256
	// hexadecimal hash within the given bucket, using the contents of the
	// file at tempPath.
	PutObjectFromFile(bucket string, hashHex string, tempPath string, size int64) error

	// GetObject retrieves the raw object payload previously stored under the
	// given bucket and SHA-256 hexadecimal hash.
	GetObject(bucket string, hashHex string) ([]byte, error)

	// CopyObject ensures that the payload identified by hashHex is present in
	// the destination bucket, reusing storage where possible.
	CopyObject(srcBucket, hashHex, destBucket string) error

	// DeleteObject removes the payload associated with the given hash in the
	// specified bucket.
	DeleteObject(bucket string, hashHex string) error

	// DeleteBucket removes all payloads and any associated filesystem
	// structures for the given bucket. Implementations should behave as if
	// the bucket's storage root were recursively deleted.
	DeleteBucket(bucket string) error
}

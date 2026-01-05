package silo

type StorageEngine interface {
	PutObject(bucket, key string, data []byte) error
	GetObject(bucket, key string) ([]byte, error)
	DeleteObject(bucket, key string) error
	ListObjects(bucket, prefix string) ([]string, error)
	CreateBucket(bucket string) error
	DeleteBucket(bucket string) error
	ListBuckets() ([]string, error)
}

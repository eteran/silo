package main

import (
	"bytes"
	"context"
	"log"
	"os"
	"path/filepath"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// getenv returns the value of the environment variable named by key or
// fallback if the variable is not present.
func getenv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

func main() {
	endpoint := getenv("MINIO_ENDPOINT", "localhost:8080")
	accessKey := getenv("MINIO_ACCESS_KEY", "minioadmin")
	secretKey := getenv("MINIO_SECRET_KEY", "minioadmin")
	bucketName := getenv("MINIO_BUCKET", "example-bucket")
	objectName := "example.txt"

	// Use insecure (HTTP) by default for local development, matching
	// example.py behaviour.
	useSSL := false

	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useSSL,
	})
	if err != nil {
		log.Fatalf("failed to create MinIO client: %v", err)
	}

	ctx := context.Background()

	// Ensure bucket exists.
	exists, err := client.BucketExists(ctx, bucketName)
	if err != nil {
		log.Fatalf("failed to check bucket existence: %v", err)
	}
	if !exists {
		if err := client.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{}); err != nil {
			log.Fatalf("failed to create bucket %q: %v", bucketName, err)
		}
	}

	// 1. Upload an example.txt file.
	content := []byte("Hello from MinIO example!\n")
	reader := bytes.NewReader(content)
	info, err := client.PutObject(ctx, bucketName, objectName, reader, int64(len(content)), minio.PutObjectOptions{
		ContentType: "text/plain",
	})
	if err != nil {
		log.Fatalf("failed to upload object %q to bucket %q: %v", objectName, bucketName, err)
	}
	log.Printf("Uploaded %q to bucket %q (%d bytes)", objectName, bucketName, info.Size)

	// 2. List the contents of the bucket.
	log.Printf("Objects in bucket %q:", bucketName)
	for objectInfo := range client.ListObjects(ctx, bucketName, minio.ListObjectsOptions{Recursive: true}) {
		if objectInfo.Err != nil {
			log.Fatalf("failed to list objects in bucket %q: %v", bucketName, objectInfo.Err)
		}
		log.Printf(" - %s (%d bytes)", objectInfo.Key, objectInfo.Size)
	}

	// 3. Download the file.
	downloadPath := filepath.Join(".", "downloaded_"+objectName)
	if err := client.FGetObject(ctx, bucketName, objectName, downloadPath, minio.GetObjectOptions{}); err != nil {
		log.Fatalf("failed to download object %q from bucket %q: %v", objectName, bucketName, err)
	}
	log.Printf("Downloaded to %q", downloadPath)

	// 4. Copy the object within the same bucket.
	copySrc := minio.CopySrcOptions{Bucket: bucketName, Object: objectName}
	copyDst := minio.CopyDestOptions{Bucket: bucketName, Object: "example_copy.txt"}
	if _, err := client.CopyObject(ctx, copyDst, copySrc); err != nil {
		log.Fatalf("failed to copy object %q to example_copy.txt in bucket %q: %v", objectName, bucketName, err)
	}
	log.Printf("Copied %q to example_copy.txt in bucket %q", objectName, bucketName)

	// 5. Ensure another-bucket exists.
	otherBucket := "another-bucket"
	exists, err = client.BucketExists(ctx, otherBucket)
	if err != nil {
		log.Fatalf("failed to check bucket existence for %q: %v", otherBucket, err)
	}
	if !exists {
		if err := client.MakeBucket(ctx, otherBucket, minio.MakeBucketOptions{}); err != nil {
			log.Fatalf("failed to create bucket %q: %v", otherBucket, err)
		}
	}

	// 6. Copy example_copy.txt to another-bucket with the specified path.
	copySrc = minio.CopySrcOptions{Bucket: bucketName, Object: "example_copy.txt"}
	copyDst = minio.CopyDestOptions{Bucket: otherBucket, Object: "/some/path/example_copy_cross_bucket.txt"}
	if _, err := client.CopyObject(ctx, copyDst, copySrc); err != nil {
		log.Fatalf("failed to copy object example_copy.txt to cross-bucket destination: %v", err)
	}
	log.Printf("Copied example_copy.txt to %q in bucket %q", "/some/path/example_copy_cross_bucket.txt", otherBucket)
}

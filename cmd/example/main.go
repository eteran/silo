package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
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

const (
	BucketName         = "example-bucket"
	OtherBucket        = "another-bucket"
	ObjectName         = "example.txt"
	ObjectContent      = "Hello from MinIO example!\n"
	OtherObjectName    = "home/eteran/documents/report.pdf"
	OtherObjectContent = "Lorem duo nisl aliquip amet. Sadipscing vero diam rebum eirmod ea ut ad sit ipsum labore dolore. Accusam amet dolore sit consectetuer. Ipsum autem enim gubergren lorem clita et eu dolor illum dolore vel accusam consetetur amet diam sadipscing et accusam. Magna sed suscipit duo aliquyam eirmod. Gubergren ea vero ut iusto accusam. Et sea eum et diam amet dolor invidunt et iriure dolore. Adipiscing nonumy kasd. Dolor stet eum diam ullamcorper stet consetetur labore magna ex suscipit dolore delenit sed invidunt takimata. Sed consequat in ea feugiat erat. Diam illum sea eros ut gubergren tincidunt ullamcorper est volutpat et ea aliquyam dolore invidunt lorem. Sadipscing ipsum exerci lobortis aliquyam accusam sanctus nonummy in. Soluta tation et doming mazim ut sit adipiscing et est dolor ipsum esse voluptua sit ad sadipscing. Blandit at dolore elitr. Sed sadipscing at assum tempor consequat sed ipsum et amet lorem. Ipsum invidunt voluptua."
)

// EnsureBucket checks if a bucket exists, and creates it if it does not.
func EnsureBucket(ctx context.Context, client *minio.Client, bucketName string) error {
	exists, err := client.BucketExists(ctx, bucketName)
	if err != nil {
		return fmt.Errorf("failed to check bucket existence: %w", err)
	}

	if !exists {
		if err := client.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{}); err != nil {
			return fmt.Errorf("failed to create bucket %q: %w", bucketName, err)
		}
	}
	return nil
}

// UploadFile uploads an object to the specified bucket.
func UploadFile(ctx context.Context, client *minio.Client, bucketName string, objectName string, objectContent []byte) error {
	// Upload an example.txt file.
	content := objectContent
	reader := bytes.NewReader(content)
	_, err := client.PutObject(ctx, bucketName, objectName, reader, int64(len(content)), minio.PutObjectOptions{
		ContentType: "text/plain",
	})
	if err != nil {
		return fmt.Errorf("failed to upload object %q to bucket %q: %w", objectName, bucketName, err)
	}

	slog.Info("Uploaded object to bucket", "object", objectName, "bucket", bucketName)
	return nil
}

// ListBucketObjects lists all objects in the specified bucket.
func ListBucketObjects(ctx context.Context, client *minio.Client, bucketName string) error {
	slog.Info("Objects in bucket", "bucket", bucketName)
	for objectInfo := range client.ListObjects(ctx, bucketName, minio.ListObjectsOptions{Recursive: true}) {
		if objectInfo.Err != nil {
			return fmt.Errorf("failed to list objects in bucket %q: %w", bucketName, objectInfo.Err)
		}
		slog.Info("Object in bucket", "key", objectInfo.Key, "size", objectInfo.Size)
	}
	return nil
}

// DownloadFile downloads an object from the specified bucket to a local file.
func DownloadFile(ctx context.Context, client *minio.Client, bucketName string, objectName string, downloadPath string) error {
	if err := client.FGetObject(ctx, bucketName, objectName, downloadPath, minio.GetObjectOptions{}); err != nil {
		slog.Error("failed to download object from bucket", "object", objectName, "bucket", bucketName, "err", err)
		os.Exit(1)
	}
	slog.Info("Downloaded object", "path", downloadPath)
	return nil
}

func CopyObject(ctx context.Context, client *minio.Client, srcBucket string, srcObject string, destBucket string, destObject string) error {
	copySrc := minio.CopySrcOptions{Bucket: srcBucket, Object: srcObject}
	copyDst := minio.CopyDestOptions{Bucket: destBucket, Object: destObject}
	if _, err := client.CopyObject(ctx, copyDst, copySrc); err != nil {
		return fmt.Errorf("failed to copy object from %q/%q to %q/%q: %w", srcBucket, srcObject, destBucket, destObject, err)
	}
	slog.Info("Copied object bucket", "source_object", srcObject, "dest_object", destObject, "source_bucket", srcBucket, "dest_bucket", destBucket)
	return nil
}

func Run(ctx context.Context, client *minio.Client) error {
	// Ensure bucket exists.
	if err := EnsureBucket(ctx, client, BucketName); err != nil {
		return fmt.Errorf("failed to ensure bucket exists: %w", err)
	}

	// 1. Upload an example.txt file.
	if err := UploadFile(ctx, client, BucketName, ObjectName, []byte(ObjectContent)); err != nil {
		return fmt.Errorf("failed to upload example file: %w", err)
	}

	// 2. List the contents of the bucket.
	if err := ListBucketObjects(ctx, client, BucketName); err != nil {
		return fmt.Errorf("failed to list bucket objects: %w", err)
	}

	// 3. Download the file.
	downloadPath := filepath.Join(".", "downloaded_"+ObjectName)
	if err := DownloadFile(ctx, client, BucketName, ObjectName, downloadPath); err != nil {
		return fmt.Errorf("failed to download file: %w", err)
	}

	// 4. Copy the object within the same bucket.
	if err := CopyObject(ctx, client, BucketName, ObjectName, BucketName, "example_copy.txt"); err != nil {
		return fmt.Errorf("failed to copy object within bucket: %w", err)
	}

	if err := CopyObject(ctx, client, BucketName, ObjectName, BucketName, "some/path/example_copy.txt"); err != nil {
		return fmt.Errorf("failed to copy object within bucket: %w", err)
	}

	// 5. Ensure another-bucket exists.
	if err := EnsureBucket(ctx, client, OtherBucket); err != nil {
		return fmt.Errorf("failed to ensure another bucket exists: %w", err)
	}

	// 6. Copy example_copy.txt to another-bucket with the specified path.
	if err := CopyObject(ctx, client, BucketName, "example_copy.txt", OtherBucket, "/some/path/example_copy_cross_bucket.txt"); err != nil {
		return fmt.Errorf("failed to copy object to another bucket: %w", err)
	}

	// 7. Upload an example.txt file.
	if err := UploadFile(ctx, client, OtherBucket, OtherObjectName, []byte(OtherObjectContent)); err != nil {
		return fmt.Errorf("failed to upload example file: %w", err)
	}

	// 8. List the contents of the second bucket.
	if err := ListBucketObjects(ctx, client, OtherBucket); err != nil {
		return fmt.Errorf("failed to list bucket objects: %w", err)
	}

	return nil
}

func main() {
	endpoint := getenv("MINIO_ENDPOINT", "localhost:9000")
	accessKey := getenv("MINIO_ACCESS_KEY", "minioadmin")
	secretKey := getenv("MINIO_SECRET_KEY", "minioadmin")

	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: false,
	})

	if err != nil {
		slog.Error("failed to create MinIO client", "err", err)
		os.Exit(1)
	}

	ctx := context.Background()

	if err := Run(ctx, client); err != nil {
		slog.Error("error running example", "err", err)
		os.Exit(1)
	}
}

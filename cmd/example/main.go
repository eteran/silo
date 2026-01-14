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
	OtherObjectContent = `At dolor dolores dolore feugiat et consequat. Amet sed no et quis et clita voluptua. Ipsum esse clita lorem diam dolor clita duis erat ut diam sed accusam consetetur labore dolore magna. Consetetur magna lorem erat takimata dolor takimata invidunt velit dolor labore ipsum nam dolor sed. In duo ipsum et eirmod gubergren sanctus. Labore elitr sea commodo at ut at elitr ipsum sed dolores sed sea et luptatum kasd ipsum sit sit. Stet magna nostrud et amet aliquyam invidunt et ea clita invidunt. Sed et amet et sadipscing eros clita suscipit nulla sed sit diam voluptua tempor et. Et vulputate et dignissim gubergren autem tincidunt dolor dolor te ipsum. Lorem no facilisi invidunt tempor ut luptatum dolor at aliquip ea. Diam ea sit et magna consequat diam rebum enim nonummy veniam dolore diam ut vero. Facer sadipscing amet commodo sanctus luptatum. Blandit amet rebum illum elitr lorem diam lorem duo labore. Commodo at amet liber in kasd et. Ipsum eirmod aliquyam at vel kasd autem sit lorem dolore rebum dolor sed lobortis no aliquip. Et dolores ipsum in ut magna dolore dolor takimata justo.

Labore volutpat sed illum sed blandit dolor eirmod suscipit amet eos minim dolor. Dolores lorem dolore esse diam duo sadipscing lorem vero sadipscing est dolor accumsan eos ut diam sea. Et consectetuer justo et eos possim amet. Facilisis stet dolor dolores consetetur praesent no et dolor placerat ea qui sed veniam vel ut dolor dolor. Tempor no erat ut eum sed magna consequat et labore tempor. Sanctus tempor amet quis magna dolor in ipsum takimata dolore molestie voluptua kasd augue nonumy. Laoreet eirmod et et voluptua ea rebum magna ipsum diam. At delenit dolores hendrerit nonumy te sea tempor autem kasd dolor quis labore takimata ipsum duo eos. Ipsum vero labore ipsum duis sed dolore amet eirmod nonumy ipsum dolor tempor clita esse. Veniam ea diam exerci. Lorem ut voluptua sed eirmod dolore elitr et at diam. Sed vero erat tempor duo.

Nonumy nisl eirmod in et lobortis et takimata facilisi voluptua labore sea delenit clita clita laoreet ipsum invidunt. Clita veniam et sea amet sanctus veniam sit option facilisis dolore ut dolore takimata invidunt. Est kasd no clita ipsum duis magna rebum dolores lorem. Rebum labore aliquyam gubergren at stet no imperdiet. Et dolore et sed erat diam eros dolor eos suscipit. Lorem ad aliquyam takimata lorem consetetur veniam sanctus sit magna tation elitr accusam augue ipsum duo et. Lobortis et et eu vel dolor takimata diam feugiat dolor sit vero duo diam. Stet stet ut eirmod sanctus justo dolore et."
`
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

func MultipartUploadExample(ctx context.Context, client *minio.Client) error {

	const (
		bucket = "minio-core-multipart-bucket"
		object = "core-multipart-object.bin"
	)

	creds, err := client.GetCreds()
	if err != nil {
		return fmt.Errorf("failed to get client credentials: %w", err)
	}

	endpointURL := client.EndpointURL()

	coreClient, err := minio.NewCore(endpointURL.Host, &minio.Options{
		Creds:        credentials.NewStaticV4(creds.AccessKeyID, creds.SecretAccessKey, ""),
		Secure:       false,
		BucketLookup: minio.BucketLookupPath,
	})

	if err != nil {
		return fmt.Errorf("failed to create core client: %w", err)
	}

	// Create the bucket using the high-level MinIO client.
	if err := coreClient.MakeBucket(ctx, bucket, minio.MakeBucketOptions{Region: "us-east-1"}); err != nil {
		return fmt.Errorf("failed to create bucket %q: %w", bucket, err)
	}

	// Initiate multipart upload.
	uploadID, err := coreClient.NewMultipartUpload(ctx, bucket, object, minio.PutObjectOptions{ContentType: "application/octet-stream"})
	if err != nil {
		return fmt.Errorf("failed to initiate multipart upload: %w", err)
	}

	log := slog.With("bucket", bucket, "object", object, "upload_id", uploadID)
	log.Info("Started multipart upload")

	// Prepare three distinct parts and remember their combined payload.
	partData := [][]byte{
		bytes.Repeat([]byte("AAAA"), 256*1024), // ~1 MiB
		bytes.Repeat([]byte("BBBB"), 256*1024),
		bytes.Repeat([]byte("CCCC"), 128*1024), // smaller last part
	}

	var parts []minio.CompletePart
	totalLength := 0

	for i, data := range partData {
		partNumber := i + 1

		objPart, err := coreClient.PutObjectPart(ctx, bucket, object, uploadID, partNumber, bytes.NewReader(data), int64(len(data)), minio.PutObjectPartOptions{})
		if err != nil {
			return fmt.Errorf("failed to upload part %d: %w", partNumber, err)
		}

		parts = append(parts, minio.CompletePart{
			PartNumber: partNumber,
			ETag:       objPart.ETag,
		})
		totalLength += len(data)
	}

	// Complete the multipart upload.
	_, err = coreClient.CompleteMultipartUpload(ctx, bucket, object, uploadID, parts, minio.PutObjectOptions{ContentType: "application/octet-stream"})
	if err != nil {
		return fmt.Errorf("failed to complete multipart upload: %w", err)
	}

	log.Info("Completed multipart upload", "total_size", totalLength)
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

	// 9. Demonstrate multipart upload using low-level Core client.
	if err := MultipartUploadExample(ctx, client); err != nil {
		return fmt.Errorf("failed to run multipart upload example: %w", err)
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

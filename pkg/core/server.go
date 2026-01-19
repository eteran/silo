package core

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/eteran/silo/pkg/auth"
	"github.com/eteran/silo/pkg/storage"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

var (
	//go:embed migrations
	migrationsFS embed.FS

	// Regex for validating S3 bucket names.
	// matches lowercase letters, digits, dots, and hyphens,
	// must start and end with a letter or digit, and must be between 3 and 63 characters long.
	bucketNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
)

// Server provides a minimal S3-compatible HTTP API.
type Server struct {
	Config Config
	Db     *sql.DB
}

// initSchema initializes the metadata database schema by applying all
// SQL files in the embedded migrations in lexicographical order.
func initSchema(ctx context.Context, db *sql.DB) error {
	return fs.WalkDir(migrationsFS, "migrations", func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}

		content, readError := migrationsFS.ReadFile(path)
		if readError != nil {
			return fmt.Errorf("error reading SQL file: %w", readError)
		}

		slog.Info("Running migration", "path", path)
		_, execError := db.ExecContext(ctx, string(content))
		return execError
	})
}

// NewServer initializes the metadata database and returns a new Server.
func NewServer(ctx context.Context, cfg Config) (*Server, error) {

	if cfg.DataDir == "" {
		return nil, errors.New("DataDir must not be empty")
	}

	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}

	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	dbPath := path.Join(cfg.DataDir, "metadata.sqlite")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	if err := initSchema(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}

	if cfg.Engine == nil {
		cfg.Engine = storage.NewLocalFileStorage(cfg.DataDir)
	}

	if cfg.Authenticator == nil {
		cfg.Authenticator = auth.NewCompoundAuthEngine(
			auth.NewAwsHmacAuthEngine(),
			auth.NewBasicAuthEngine(),
		)
	}

	return &Server{Config: cfg, Db: db}, nil
}

// Close closes any resources held by the Server.
func (s *Server) Close() error {
	return s.Db.Close()
}

// withTransaction runs a function within a database transaction.
func withTransaction(ctx context.Context, db *sql.DB, fn func(tx *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("error beginning transaction: %w", err)
	}
	defer tx.Rollback()

	if err := fn(tx); err != nil {
		return fmt.Errorf("error executing transaction: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("error committing transaction: %w", err)
	}

	return nil
}

// bucketExists checks whether a bucket with the given name exists.
func (s *Server) bucketExists(ctx context.Context, bucket string) (bool, error) {
	var count int
	if err := s.Db.QueryRowContext(ctx, `SELECT COUNT(*) FROM buckets WHERE name = ?`, bucket).Scan(&count); err != nil {
		return false, err
	}

	return count > 0, nil
}

// ensureBucket makes sure the given bucket exists, creating it if necessary.
// It returns true if the bucket was created, false if it already existed.
func (s *Server) ensureBucket(ctx context.Context, name string) (bool, error) {
	now := time.Now().UTC()
	res, err := s.Db.ExecContext(ctx,
		`INSERT OR IGNORE INTO buckets(name, created_at, modified_at) VALUES(?, ?, ?)`,
		name, now, now,
	)

	if err != nil {
		return false, err
	}

	rows, err := res.RowsAffected()
	return rows > 0, err
}

// writeNotImplemented is a helper for stubbing unsupported S3 operations.
func (s *Server) writeNotImplemented(w http.ResponseWriter, r *http.Request, op string) {
	message := op + " is not implemented."
	writeS3Error(w, "NotImplemented", message, r.URL.Path, http.StatusNotImplemented)
}

// writeS3Error writes a minimal S3-style XML error response.
func writeS3Error(w http.ResponseWriter, code string, message string, resource string, status int) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_ = xml.NewEncoder(w).Encode(S3Error{
		Code:     code,
		Message:  message,
		Resource: resource,
	})
}

// writeInternalError writes a generic S3 InternalError response.
func writeInternalError(w http.ResponseWriter, r *http.Request) {
	writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
}

// writeNoSuchBucketError writes a generic S3 NoSuchBucket error response.
func writeNoSuchBucketError(w http.ResponseWriter, r *http.Request) {
	writeS3Error(w, "NoSuchBucket", "The specified bucket does not exist.", r.URL.Path, http.StatusNotFound)
}

// writeNoSuchKeyError writes a generic S3 NoSuchKey error response.
func writeNoSuchKeyError(w http.ResponseWriter, r *http.Request) {
	writeS3Error(w, "NoSuchKey", "The specified key does not exist.", r.URL.Path, http.StatusNotFound)
}

// isValidBucketName implements the standard S3 bucket naming rules for
// "virtual hosted-style" buckets.
func isValidBucketName(name string) bool {

	// Must consist only of lowercase letters, digits, dots, or hyphens,
	// and must start and end with a letter or digit.
	if !bucketNamePattern.MatchString(name) {
		return false
	}

	// Disallow patterns like "..", ".-", "-.".
	if strings.Contains(name, "..") {
		return false
	}

	for i := 1; i < len(name); i++ {
		if (name[i-1] == '.' && name[i] == '-') || (name[i-1] == '-' && name[i] == '.') {
			return false
		}
	}

	// Bucket name must not be formatted as an IPv4 address.
	ip := net.ParseIP(name)
	return ip == nil
}

// isValidObjectKey enforces basic S3 object key constraints: non-empty,
// at most 1024 bytes, and no control characters.
func isValidObjectKey(key string) bool {
	if len(key) == 0 || len(key) > 1024 {
		return false
	}

	return !strings.ContainsFunc(key, func(c rune) bool {
		return c < 0x20 || c == 0x7f
	})
}

// validateBucketNameOrError writes an S3 InvalidBucketName error and returns
// false if the provided name does not meet S3 bucket naming rules.
func validateBucketNameOrError(w http.ResponseWriter, r *http.Request, bucket string) bool {
	if !isValidBucketName(bucket) {
		writeS3Error(w, "InvalidBucketName", "The specified bucket is not valid.", r.URL.Path, http.StatusBadRequest)
		return false
	}
	return true
}

// validateObjectKeyOrError writes an S3-style error for invalid object keys.
func validateObjectKeyOrError(w http.ResponseWriter, r *http.Request, key string) bool {
	if !isValidObjectKey(key) {
		writeS3Error(w, "InvalidObjectName", "The specified key is not valid.", r.URL.Path, http.StatusBadRequest)
		return false
	}
	return true
}

// writeXMLResponse encodes v as XML and writes it to w with a 200 OK status.
func writeXMLResponse(w http.ResponseWriter, v any) error {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	return xml.NewEncoder(w).Encode(v)
}

// createETag formats a hash hex string as an ETag value.
func createETag(hashHex string) string {
	return fmt.Sprintf("\"%s\"", hashHex)
}

// upsertObjectMetadata inserts or updates an object's metadata row.
func (s *Server) upsertObjectMetadata(ctx context.Context, bucket, key, hashHex string, size int64, contentType any, now time.Time) error {
	_, err := s.Db.ExecContext(ctx,
		`INSERT INTO objects(bucket, key, hash, size, content_type, created_at, modified_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(bucket, key) DO UPDATE SET
		 	hash=excluded.hash,
		 	size=excluded.size,
		 	content_type=excluded.content_type,
		 	modified_at=excluded.modified_at`,
		bucket, key, hashHex, size, contentType, now, now,
	)
	return err
}

// decodeStreamingPayloadToTemp decodes an AWS Signature Version 4 streaming
// (chunked) payload into a temporary file under the server's data directory
// while computing the SHA-256 hash of the decoded payload. It returns the
// temp file path, the decoded payload length, and the payload hash.
func (s *Server) decodeStreamingPayloadToTemp(f io.Writer, body io.Reader, decodedLen int64) (int64, string, error) {
	br := bufio.NewReader(body)

	h := sha256.New()
	var written int64
	buf := make([]byte, 32*1024)

	for {
		// Each chunk begins with: <size-hex>[;extensions]\r\n
		line, err := br.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				return 0, "", errors.New("unexpected EOF while reading chunk header")
			}
			return 0, "", fmt.Errorf("read chunk header: %w", err)
		}

		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			// Skip empty lines if any.
			continue
		}

		// Strip any chunk extensions (e.g. ";chunk-signature=...").
		if idx := strings.IndexByte(line, ';'); idx != -1 {
			line = line[:idx]
		}

		sizeHex := strings.TrimSpace(line)
		size, err := strconv.ParseInt(sizeHex, 16, 64)
		if err != nil {
			return 0, "", fmt.Errorf("parse chunk size %q: %w", sizeHex, err)
		}

		if size == 0 {
			// Final chunk. Per AWS streaming format, this is followed by a
			// trailing CRLF and optional trailers. For our purposes we can
			// consume a single empty line and stop.
			_, _ = br.ReadString('\n') // best-effort consume trailer terminator
			break
		}

		// Stream this chunk through a TeeReader so it is hashed and
		// written to the destination in a single pass.
		limited := &io.LimitedReader{R: br, N: size}
		n, err := io.CopyBuffer(f, io.TeeReader(limited, h), buf)
		if err != nil {
			return 0, "", fmt.Errorf("read chunk body: %w", err)
		}
		if n != size {
			return 0, "", fmt.Errorf("short read while reading chunk body: expected %d bytes, got %d", size, n)
		}
		written += n

		// Consume the trailing CRLF after the chunk body.
		if b, err := br.ReadByte(); err != nil || b != '\r' {
			if err == nil {
				return 0, "", fmt.Errorf("expected CR after chunk, got %q", b)
			}
			return 0, "", fmt.Errorf("read CR after chunk: %w", err)
		}
		if b, err := br.ReadByte(); err != nil || b != '\n' {
			if err == nil {
				return 0, "", fmt.Errorf("expected LF after chunk, got %q", b)
			}
			return 0, "", fmt.Errorf("read LF after chunk: %w", err)
		}
	}

	// If decodedLen was provided, use it as a sanity check but do not
	// fail hard if it does not match exactly – some clients may omit or
	// mis-report it. The storage layer relies on the actual length we
	// decoded.
	if decodedLen >= 0 && written != decodedLen {
		slog.Debug("Decoded streaming payload length mismatch", "expected", decodedLen, "actual", written)
	}

	hashHex := hex.EncodeToString(h.Sum(nil))
	return written, hashHex, nil
}

// handleListParts implements the ListParts API:
// GET /bucket/key?uploadId=ID[&part-number-marker=N][&max-parts=M]
func (s *Server) handleListParts(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string, key string, uploadID string) {
	// Ensure bucket exists; do not auto-create.
	if exists, err := s.bucketExists(ctx, bucket); err != nil {
		slog.Error("ListParts bucket lookup", "bucket", bucket, "err", err)
		writeInternalError(w, r)
		return
	} else if !exists {
		writeNoSuchBucketError(w, r)
		return
	}

	uploadDir := filepath.Join(s.Config.DataDir, "uploads", uploadID)
	if stat, err := os.Stat(uploadDir); err != nil || !stat.IsDir() {
		writeS3Error(w, "NoSuchUpload", "The specified multipart upload does not exist.", r.URL.Path, http.StatusNotFound)
		return
	}

	// Parse optional pagination parameters.
	q := r.URL.Query()
	partNumberMarker := 0
	if v := q.Get("part-number-marker"); v != "" {
		m, err := strconv.Atoi(v)
		if err != nil || m < 0 {
			writeS3Error(w, "InvalidArgument", "The part-number-marker query parameter is invalid.", r.URL.Path, http.StatusBadRequest)
			return
		}
		partNumberMarker = m
	}

	maxParts := 1000
	if v := q.Get("max-parts"); v != "" {
		m, err := strconv.Atoi(v)
		if err != nil || m <= 0 {
			writeS3Error(w, "InvalidArgument", "The max-parts query parameter is invalid.", r.URL.Path, http.StatusBadRequest)
			return
		}
		if m < maxParts {
			maxParts = m
		}
	}

	entries, err := os.ReadDir(uploadDir)
	if err != nil {
		slog.Error("ListParts read upload dir", "path", uploadDir, "err", err)
		writeInternalError(w, r)
		return
	}

	numbers := make([]int, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		var n int
		if _, err := fmt.Sscanf(entry.Name(), "part-%06d", &n); err != nil {
			continue
		}
		numbers = append(numbers, n)
	}

	sort.Ints(numbers)

	parts := make([]ListPartsPart, 0, len(numbers))
	var nextPartNumberMarker int
	isTruncated := false
	count := 0

	for idx, n := range numbers {
		if n <= partNumberMarker {
			continue
		}

		partPath := filepath.Join(uploadDir, fmt.Sprintf("part-%06d", n))
		info, err := os.Stat(partPath)
		if err != nil {
			if os.IsNotExist(err) {
				writeS3Error(w, "InvalidPart", "One or more of the specified parts could not be found.", r.URL.Path, http.StatusBadRequest)
				return
			}
			slog.Error("ListParts stat part file", "path", partPath, "err", err)
			writeInternalError(w, r)
			return
		}

		pf, err := os.Open(partPath)
		if err != nil {
			slog.Error("ListParts open part file", "path", partPath, "err", err)
			writeS3Error(w, "InvalidPart", "One or more of the specified parts could not be found.", r.URL.Path, http.StatusBadRequest)
			return
		}

		h := sha256.New()
		if _, err := io.Copy(h, pf); err != nil {
			_ = pf.Close()
			slog.Error("ListParts hash part file", "path", partPath, "err", err)
			writeInternalError(w, r)
			return
		}
		if err := pf.Close(); err != nil {
			slog.Debug("ListParts close part file", "path", partPath, "err", err)
		}

		etag := createETag(hex.EncodeToString(h.Sum(nil)))
		parts = append(parts, ListPartsPart{
			PartNumber:   n,
			LastModified: info.ModTime().UTC().Format(time.RFC3339),
			ETag:         etag,
			Size:         info.Size(),
		})

		nextPartNumberMarker = n
		count++
		if count >= maxParts {
			// Determine if there are more parts beyond what we've returned.
			if idx < len(numbers)-1 {
				isTruncated = true
			}
			break
		}
	}

	if count == 0 {
		nextPartNumberMarker = partNumberMarker
	}

	resp := ListPartsResult{
		XMLNS:                S3XMLNamespace,
		Bucket:               bucket,
		Key:                  key,
		UploadID:             uploadID,
		PartNumberMarker:     partNumberMarker,
		NextPartNumberMarker: nextPartNumberMarker,
		MaxParts:             maxParts,
		IsTruncated:          isTruncated,
		Parts:                parts,
	}

	if err := writeXMLResponse(w, resp); err != nil {
		slog.Error("Encode ListParts XML", "bucket", bucket, "key", key, "err", err)
	}
}

// ------ Dispatchers for bucket-level HTTP handlers ------

// handleBucketPut dispatches PUT /bucket[?subresource] between CreateBucket
// and various bucket configuration APIs.
func (s *Server) handleBucketPut(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string) {
	if !validateBucketNameOrError(w, r, bucket) {
		return
	}

	q := r.URL.Query()
	switch {
	case q.Has("tagging"):
		s.handlePutBucketTagging(ctx, w, r, bucket)
	case q.Has("versioning"):
		s.writeNotImplemented(w, r, "PutBucketVersioning")
	case q.Has("encryption"):
		s.writeNotImplemented(w, r, "PutBucketEncryption")
	case q.Has("cors"):
		s.writeNotImplemented(w, r, "PutBucketCors")
	case q.Has("lifecycle"):
		s.writeNotImplemented(w, r, "PutBucketLifecycleConfiguration")
	case q.Has("notification"):
		s.writeNotImplemented(w, r, "PutBucketNotificationConfiguration")
	case q.Has("policy"):
		s.writeNotImplemented(w, r, "PutBucketPolicy")
	case q.Has("replication"):
		s.writeNotImplemented(w, r, "PutBucketReplication")
	default:
		s.handleCreateBucket(ctx, w, r, bucket)
	}
}

// handleBucketPost implements POST /bucket[?subresource], such as DeleteObjects.
func (s *Server) handleBucketPost(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string) {
	if !validateBucketNameOrError(w, r, bucket) {
		return
	}

	q := r.URL.Query()
	switch {
	case q.Has("delete"):
		s.handleDeleteObjects(ctx, w, r, bucket)
	default:
		s.writeNotImplemented(w, r, "BucketPost")
	}
}

// handleBucketGet dispatches GET /bucket[?subresource] between ListObjects
// and bucket-level read APIs.
func (s *Server) handleBucketGet(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string) {
	if !validateBucketNameOrError(w, r, bucket) {
		return
	}

	q := r.URL.Query()
	switch {
	case q.Has("location"):
		s.handleGetBucketLocation(ctx, w, r, bucket)
	case q.Has("tagging"):
		s.handleGetBucketTagging(ctx, w, r, bucket)
	case q.Has("versioning"):
		s.writeNotImplemented(w, r, "GetBucketVersioning")
	case q.Has("encryption"):
		s.writeNotImplemented(w, r, "GetBucketEncryption")
	case q.Has("cors"):
		s.writeNotImplemented(w, r, "GetBucketCors")
	case q.Has("lifecycle"):
		s.writeNotImplemented(w, r, "GetBucketLifecycleConfiguration")
	case q.Has("notification"):
		s.writeNotImplemented(w, r, "GetBucketNotificationConfiguration")
	case q.Has("policy"):
		s.writeNotImplemented(w, r, "GetBucketPolicy")
	case q.Has("replication"):
		s.writeNotImplemented(w, r, "GetBucketReplication")
	case q.Get("list-type") == "2":
		s.handleListObjectsV2(ctx, w, r, bucket)
	case q.Has("versions"):
		s.writeNotImplemented(w, r, "ListObjectVersions")
	case q.Has("uploads"):
		s.handleListMultipartUploads(ctx, w, r, bucket)
	default:
		s.handleListObjects(ctx, w, r, bucket)
	}
}

// handleBucketDelete implements DELETE /bucket[?subresource].
func (s *Server) handleBucketDelete(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string) {
	if !validateBucketNameOrError(w, r, bucket) {
		return
	}

	q := r.URL.Query()
	switch {
	case q.Has("tagging"):
		s.handleDeleteBucketTagging(ctx, w, r, bucket)
	case q.Has("encryption"):
		s.writeNotImplemented(w, r, "DeleteBucketEncryption")
	case q.Has("cors"):
		s.writeNotImplemented(w, r, "DeleteBucketCors")
	case q.Has("lifecycle"):
		s.writeNotImplemented(w, r, "DeleteBucketLifecycle")
	case q.Has("policy"):
		s.writeNotImplemented(w, r, "DeleteBucketPolicy")
	case q.Has("replication"):
		s.writeNotImplemented(w, r, "DeleteBucketReplication")
	default:
		// Primary bucket deletion (no subresources).
		s.handleDeleteBucket(ctx, w, r, bucket)
	}
}

// handleBucketHead implements HEAD /bucket.
func (s *Server) handleBucketHead(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string) {
	if !validateBucketNameOrError(w, r, bucket) {
		return
	}

	// Ensure bucket exists.
	if exists, err := s.bucketExists(ctx, bucket); err != nil {
		slog.Error("Bucket head", "bucket", bucket, "err", err)
		writeInternalError(w, r)
		return
	} else if !exists {
		writeNoSuchBucketError(w, r)
		return
	}

	// S3-compatible HEAD bucket: 200 with no body.
	w.WriteHeader(http.StatusOK)
}

// ------ Dispatchers for object-level HTTP handlers ------

// handleObjectPost implements POST /bucket/key[?subresource] operations such
// as CompleteMultipartUpload, RestoreObject, and SelectObjectContent.
func (s *Server) handleObjectPost(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string, key string) {
	if !validateBucketNameOrError(w, r, bucket) {
		return
	}
	if !validateObjectKeyOrError(w, r, key) {
		return
	}

	q := r.URL.Query()
	switch {
	case q.Has("uploads"):
		// CreateMultipartUpload
		s.handleCreateMultipartUpload(ctx, w, r, bucket, key)
	case q.Has("uploadId"):
		uploadID := q.Get("uploadId")
		// CompleteMultipartUpload
		s.handleCompleteMultipartUpload(ctx, w, r, bucket, key, uploadID)
	case q.Has("uploadId"):
	case q.Has("restore"):
		s.writeNotImplemented(w, r, "RestoreObject")
	case q.Has("select"):
		s.writeNotImplemented(w, r, "SelectObjectContent")
	default:
		s.writeNotImplemented(w, r, "ObjectPost")
	}
}

// handleObjectGet implements GET /bucket/key to retrieve an object.
func (s *Server) handleObjectGet(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string, key string) {
	if !validateBucketNameOrError(w, r, bucket) {
		return
	}
	if !validateObjectKeyOrError(w, r, key) {
		return
	}

	q := r.URL.Query()
	switch {
	case q.Has("tagging"):
		s.handleGetObjectTagging(ctx, w, r, bucket, key)
	case q.Has("attributes"):
		s.writeNotImplemented(w, r, "GetObjectAttributes")
	case q.Has("uploadId"):
		uploadID := q.Get("uploadId")
		s.handleListParts(ctx, w, r, bucket, key, uploadID)
	default:
		s.handleGetObject(ctx, w, r, bucket, key)
	}
}

// handleObjectDelete implements DELETE /bucket/key to delete an object.
func (s *Server) handleObjectDelete(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string, key string) {
	if !validateBucketNameOrError(w, r, bucket) {
		return
	}
	if !validateObjectKeyOrError(w, r, key) {
		return
	}

	q := r.URL.Query()
	switch {
	case q.Has("tagging"):
		s.handleDeleteObjectTagging(ctx, w, r, bucket, key)
	case q.Has("uploadId"):
		uploadID := q.Get("uploadId")
		s.handleAbortMultipartUpload(ctx, w, r, bucket, key, uploadID)
	default:
		s.handleDeleteObject(ctx, w, r, bucket, key)
	}
}

// handleObjectPut implements PUT /bucket/key to store an object.
func (s *Server) handleObjectPut(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string, key string) {
	if !validateBucketNameOrError(w, r, bucket) {
		return
	}
	if !validateObjectKeyOrError(w, r, key) {
		return
	}

	q := r.URL.Query()

	if uploadID := q.Get("uploadId"); uploadID != "" {
		if partNumber := q.Get("partNumber"); partNumber != "" {
			if r.Header.Get("x-amz-copy-source") != "" {
				s.writeNotImplemented(w, r, "UploadPartCopy")
				return
			}

			partNum, err := strconv.Atoi(partNumber)
			if err != nil || partNum <= 0 {
				writeS3Error(w, "InvalidArgument", "Invalid part number.", r.URL.Path, http.StatusBadRequest)
				return
			}

			s.handleUploadPart(ctx, w, r, bucket, key, uploadID, partNum)
			return
		}
	}

	if q.Has("tagging") {
		s.handlePutObjectTagging(ctx, w, r, bucket, key)
		return
	}

	if copySource := r.Header.Get("x-amz-copy-source"); copySource != "" {
		s.handleCopyObject(ctx, w, r, bucket, key, copySource)
		return
	}

	if bucket == "" || key == "" {
		writeS3Error(w, "InvalidRequest", "Bucket and key must not be empty", r.URL.Path, http.StatusBadRequest)
		return
	}

	// Ensure bucket exists; align behavior with S3/MinIO by
	// returning an error instead of auto-creating missing buckets.
	if exists, err := s.bucketExists(ctx, bucket); err != nil {
		slog.Error("Lookup bucket for put object", "bucket", bucket, "err", err)
		writeInternalError(w, r)
		return
	} else if !exists {
		writeNoSuchBucketError(w, r)
		return
	}

	var (
		data    []byte
		length  int64
		hashHex string
		err     error
	)

	contentSHA := r.Header.Get("X-Amz-Content-Sha256")
	if strings.EqualFold(contentSHA, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD") {
		decodedLenStr := r.Header.Get("X-Amz-Decoded-Content-Length")
		if decodedLenStr == "" {
			slog.Error("Missing X-Amz-Decoded-Content-Length for streaming payload")
			writeS3Error(w, "InvalidRequest", "Missing X-Amz-Decoded-Content-Length for streaming payload", r.URL.Path, http.StatusBadRequest)
			return
		}

		decodedLen, parseErr := strconv.ParseInt(decodedLenStr, 10, 64)
		if parseErr != nil || decodedLen < 0 {
			slog.Error("Invalid X-Amz-Decoded-Content-Length", "value", decodedLenStr, "err", parseErr)
			writeS3Error(w, "InvalidRequest", "Invalid X-Amz-Decoded-Content-Length", r.URL.Path, http.StatusBadRequest)
			return
		}

		tmpDir := filepath.Join(s.Config.DataDir, "uploads")
		if err := os.MkdirAll(tmpDir, 0o755); err != nil {
			slog.Error("Error creating temp dir for streaming upload", "path", tmpDir, "err", err)
			writeInternalError(w, r)
			return
		}

		tempPath, err := os.CreateTemp(tmpDir, "upload-*")
		if err != nil {
			slog.Error("Error creating temp dir for streaming upload", "path", tmpDir, "err", err)
			writeInternalError(w, r)
			return
		}
		defer func() {
			if err := tempPath.Close(); err != nil {
				slog.Debug("Failed to close temp upload file", "path", tempPath.Name(), "err", err)
			}

			// Best-effort cleanup of the temporary file; if the storage engine
			// moved it into place via rename, this will just fail with ENOENT.
			if err := os.Remove(tempPath.Name()); err != nil && !os.IsNotExist(err) {
				slog.Debug("Failed to remove temp upload file", "path", tempPath, "err", err)
			}
		}()

		size, hash, err := s.decodeStreamingPayloadToTemp(tempPath, r.Body, decodedLen)
		if err != nil {
			slog.Error("Decode streaming payload", "err", err)
			writeS3Error(w, "InvalidRequest", "Failed to decode streaming payload", r.URL.Path, http.StatusBadRequest)
			return
		}

		if err := s.Config.Engine.PutObjectFromFile(bucket, hash, tempPath.Name(), size); err != nil {
			slog.Error("Store object payload from file", "bucket", bucket, "key", key, "err", err)
			writeInternalError(w, r)
			return
		}

		length = size
		hashHex = hash
	} else {
		data, err = io.ReadAll(r.Body)
		if err != nil {
			slog.Error("Read request body", "err", err)
			writeS3Error(w, "InvalidRequest", "Failed to read request body", r.URL.Path, http.StatusBadRequest)
			return
		}
		length = int64(len(data))

		sum := sha256.Sum256(data)
		hashHex = hex.EncodeToString(sum[:])
		if err := s.Config.Engine.PutObject(bucket, hashHex, data); err != nil {
			slog.Error("Store object payload", "bucket", bucket, "key", key, "err", err)
			writeInternalError(w, r)
			return
		}
	}
	defer r.Body.Close()

	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	now := time.Now().UTC()

	if err := s.upsertObjectMetadata(ctx, bucket, key, hashHex, length, contentType, now); err != nil {
		slog.Error("Upsert object metadata", "bucket", bucket, "key", key, "err", err)
		writeInternalError(w, r)
		return
	}

	w.Header().Set("ETag", createETag(hashHex))
	w.WriteHeader(http.StatusOK)
}

// handleObjectHead implements HEAD /bucket/key, returning metadata headers
// compatible with S3 but without a response body.
func (s *Server) handleObjectHead(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string, key string) {
	if !validateBucketNameOrError(w, r, bucket) {
		return
	}
	if !validateObjectKeyOrError(w, r, key) {
		return
	}

	hashHex, size, contentType, modifiedAt, err := s.lookupObjectMetadata(ctx, bucket, key)
	if errors.Is(err, sql.ErrNoRows) {
		writeNoSuchKeyError(w, r)
		return
	}
	if err != nil {
		slog.Error("Lookup object metadata (HEAD)", "bucket", bucket, "key", key, "err", err)
		writeInternalError(w, r)
		return
	}

	if contentType.Valid {
		w.Header().Set("Content-Type", contentType.String)
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	if size >= 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	}
	w.Header().Set("Last-Modified", modifiedAt.UTC().Format(http.TimeFormat))
	w.Header().Set("ETag", createETag(hashHex))
	w.Header().Set("Accept-Ranges", "bytes")

	w.WriteHeader(http.StatusOK)
}

// lookupObjectMetadata loads basic metadata for the given object key.
func (s *Server) lookupObjectMetadata(ctx context.Context, bucket, key string) (hashHex string, size int64, contentType sql.NullString, modifiedAt time.Time, err error) {
	err = s.Db.QueryRowContext(ctx,
		`SELECT hash, size, content_type, modified_at FROM objects WHERE bucket = ? AND key = ?`,
		bucket, key,
	).Scan(&hashHex, &size, &contentType, &modifiedAt)
	return
}

// objectExists reports whether an object with the given bucket/key exists.
func (s *Server) objectExists(ctx context.Context, bucket, key string) (bool, error) {
	var exists int
	err := s.Db.QueryRowContext(ctx, `SELECT 1 FROM objects WHERE bucket = ? AND key = ?`, bucket, key).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// ------ Individual API HTTP handlers ------

func (s *Server) handleDeleteObject(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string, key string) {
	_, err := s.Db.ExecContext(ctx, `DELETE FROM objects WHERE bucket = ? AND key = ?`, bucket, key)
	if err != nil {
		slog.Error("Delete object metadata", "bucket", bucket, "key", key, "err", err)
		writeInternalError(w, r)
		return
	}

	// Note: we intentionally do not garbage-collect unreferenced payload
	// files yet. That can be added later based on hash reference counts.
	w.WriteHeader(http.StatusNoContent)
}

// handlePutObjectTagging implements PUT /bucket/key?tagging to replace the
// complete set of tags associated with an object. It treats tags as a
// separate metadata resource and does not change the object's modified_at
// (which reflects payload changes).
func (s *Server) handlePutObjectTagging(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string, key string) {

	// Ensure object exists.
	if exists, err := s.objectExists(ctx, bucket, key); err != nil {
		slog.Error("Put object tagging lookup", "bucket", bucket, "key", key, "err", err)
		writeInternalError(w, r)
		return
	} else if !exists {
		writeNoSuchKeyError(w, r)
		return
	}

	defer r.Body.Close()
	var tagging Tagging
	if err := xml.NewDecoder(r.Body).Decode(&tagging); err != nil {
		slog.Error("Decode object tagging XML", "bucket", bucket, "key", key, "err", err)
		writeS3Error(w, "MalformedXML", "The XML you provided was not well-formed or did not validate against our published schema.", r.URL.Path, http.StatusBadRequest)
		return
	}

	if len(tagging.TagSet) > 50 {
		writeS3Error(w, "InvalidRequest", "The TagSet cannot contain more than 50 tags.", r.URL.Path, http.StatusBadRequest)
		return
	}

	if err := withTransaction(ctx, s.Db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM object_tags WHERE bucket = ? AND key = ?`, bucket, key); err != nil {
			slog.Error("Delete existing object tags", "bucket", bucket, "key", key, "err", err)
			writeInternalError(w, r)
			return fmt.Errorf("error deleting existing object tags %w", err)
		}

		for _, tag := range tagging.TagSet {
			if tag.Key == "" {
				writeS3Error(w, "InvalidTag", "The TagKey you have provided is invalid.", r.URL.Path, http.StatusBadRequest)
				return fmt.Errorf("invalid object tag key `%s`", tag.Key)
			}

			if strings.HasPrefix(strings.ToLower(tag.Key), "aws:") {
				writeS3Error(w, "InvalidTag", "System tags prefixed with 'aws:' are reserved and cannot be modified.", r.URL.Path, http.StatusBadRequest)
				return fmt.Errorf("reserved object tag key `%s`", tag.Key)
			}

			if _, err := tx.ExecContext(ctx, `INSERT INTO object_tags(bucket, key, tag_key, tag_value) VALUES(?, ?, ?, ?)`, bucket, key, tag.Key, tag.Value); err != nil {
				slog.Error("Insert object tag", "bucket", bucket, "key", key, "tag_key", tag.Key, "err", err)
				writeInternalError(w, r)
				return fmt.Errorf("error inserting object tag `%s` %w", tag.Key, err)
			}
		}

		return nil
	}); err != nil {
		slog.Error("Put object tagging transaction", "bucket", bucket, "key", key, "err", err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleGetObjectTagging implements GET /bucket/key?tagging to retrieve the
// current set of tags associated with an object.
func (s *Server) handleGetObjectTagging(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string, key string) {
	// Ensure object exists.
	if exists, err := s.objectExists(ctx, bucket, key); err != nil {
		slog.Error("Get object tagging lookup", "bucket", bucket, "key", key, "err", err)
		writeInternalError(w, r)
		return
	} else if !exists {
		writeNoSuchKeyError(w, r)
		return
	}

	rows, err := s.Db.QueryContext(ctx, `SELECT tag_key, tag_value FROM object_tags WHERE bucket = ? AND key = ? ORDER BY tag_key`, bucket, key)
	if err != nil {
		slog.Error("Query object tags", "bucket", bucket, "key", key, "err", err)
		writeInternalError(w, r)
		return
	}
	defer rows.Close()

	tagging := Tagging{XMLNS: S3XMLNamespace}
	for rows.Next() {
		var tag Tag
		if err := rows.Scan(&tag.Key, &tag.Value); err != nil {
			slog.Error("Scan object tag", "bucket", bucket, "key", key, "err", err)
			continue
		}
		tagging.TagSet = append(tagging.TagSet, tag)
	}

	if len(tagging.TagSet) == 0 {
		writeS3Error(w, "NoSuchTagSet", "The TagSet does not exist.", r.URL.Path, http.StatusNotFound)
		return
	}

	if err := writeXMLResponse(w, tagging); err != nil {
		slog.Error("Encode object tagging XML", "bucket", bucket, "key", key, "err", err)
	}
}

// handleDeleteObjectTagging implements DELETE /bucket/key?tagging to remove
// all tags associated with an object.
func (s *Server) handleDeleteObjectTagging(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string, key string) {

	// Ensure object exists.
	if exists, err := s.objectExists(ctx, bucket, key); err != nil {
		slog.Error("Delete object tagging lookup", "bucket", bucket, "key", key, "err", err)
		writeInternalError(w, r)
		return
	} else if !exists {
		writeNoSuchKeyError(w, r)
		return
	}

	if err := withTransaction(ctx, s.Db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM object_tags WHERE bucket = ? AND key = ?`, bucket, key); err != nil {
			slog.Error("Delete object tags", "bucket", bucket, "key", key, "err", err)
			writeInternalError(w, r)
			return fmt.Errorf("error deleting object tags %w", err)
		}

		return nil
	}); err != nil {
		slog.Error("Delete object tagging transaction", "bucket", bucket, "key", key, "err", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleDeleteObjects implements the multi-object delete API:
// POST /bucket?delete
func (s *Server) handleDeleteObjects(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string) {
	// Ensure bucket exists; do not auto-create.
	if exists, err := s.bucketExists(ctx, bucket); err != nil {
		slog.Error("DeleteObjects bucket lookup", "bucket", bucket, "err", err)
		writeInternalError(w, r)
		return
	} else if !exists {
		writeNoSuchBucketError(w, r)
		return
	}

	defer r.Body.Close()
	var req DeleteObjectsRequest
	if err := xml.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Error("Decode DeleteObjects XML", "bucket", bucket, "err", err)
		writeS3Error(w, "MalformedXML", "The XML you provided was not well-formed or did not validate against our published schema.", r.URL.Path, http.StatusBadRequest)
		return
	}

	if len(req.Objects) == 0 {
		writeS3Error(w, "InvalidRequest", "You must specify at least one object to delete.", r.URL.Path, http.StatusBadRequest)
		return
	}

	deleted := make([]DeleteObject, 0, len(req.Objects))
	for _, obj := range req.Objects {
		if obj.Key == "" {
			continue
		}

		if _, err := s.Db.ExecContext(ctx, `DELETE FROM objects WHERE bucket = ? AND key = ?`, bucket, obj.Key); err != nil {
			slog.Error("DeleteObjects delete row", "bucket", bucket, "key", obj.Key, "err", err)
			writeInternalError(w, r)
			return
		}

		deleted = append(deleted, obj)
	}

	resp := DeleteResult{
		XMLNS:   S3XMLNamespace,
		Deleted: deleted,
	}

	if err := writeXMLResponse(w, resp); err != nil {
		slog.Error("Encode DeleteObjects XML", "bucket", bucket, "err", err)
	}
}

func (s *Server) handleGetObject(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string, key string) {
	hashHex, size, contentType, modifiedAt, err := s.lookupObjectMetadata(ctx, bucket, key)

	if errors.Is(err, sql.ErrNoRows) {
		writeNoSuchKeyError(w, r)
		return
	}

	if err != nil {
		slog.Error("Lookup object metadata", "bucket", bucket, "key", key, "err", err)
		writeInternalError(w, r)
		return
	}

	data, err := s.Config.Engine.GetObject(bucket, hashHex)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "object payload missing", http.StatusInternalServerError)
			return
		}
		slog.Error("Read object payload", "bucket", bucket, "key", key, "err", err)
		writeInternalError(w, r)
		return
	}

	if size != int64(len(data)) {
		slog.Error("Object size mismatch", "bucket", bucket, "key", key, "expected", size, "actual", len(data))
		http.Error(w, "object size mismatch", http.StatusInternalServerError)
		return
	}

	if contentType.Valid {
		w.Header().Set("Content-Type", contentType.String)
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	if size >= 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	}
	w.Header().Set("Last-Modified", modifiedAt.UTC().Format(http.TimeFormat))
	w.Header().Set("ETag", createETag(hashHex))
	w.Header().Set("Accept-Ranges", "bytes")

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(data); err != nil {
		slog.Error("Stream object", "bucket", bucket, "key", key, "err", err)
	}
}

// handleCreateBucket implements PUT /bucket to create a new bucket.
func (s *Server) handleCreateBucket(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string) {

	if created, err := s.ensureBucket(ctx, bucket); err != nil {
		slog.Error("Create bucket", "bucket", bucket, "err", err)
		writeInternalError(w, r)
		return
	} else if !created {
		// Bucket already existed; S3 returns 409 BucketAlreadyExists.
		writeS3Error(w, "BucketAlreadyExists", "The requested bucket name is not available. The bucket namespace is shared by all users of the system. Please select a different name and try again.", r.URL.Path, http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleGetBucketLocation implements GET /bucket?location
func (s *Server) handleGetBucketLocation(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string) {

	// Ensure bucket exists.
	if exists, err := s.bucketExists(ctx, bucket); err != nil {
		slog.Error("Get bucket location", "bucket", bucket, "err", err)
		writeInternalError(w, r)
		return
	} else if !exists {
		writeNoSuchBucketError(w, r)
		return
	}

	resp := LocationConstraint{
		XMLNS:  S3XMLNamespace,
		Region: s.Config.Region,
	}

	if err := writeXMLResponse(w, resp); err != nil {
		slog.Error("Encode bucket location XML", "bucket", bucket, "err", err)
	}
}

// handlePutBucketTagging implements PUT /bucket?tagging to replace the
// complete set of tags associated with a bucket.
func (s *Server) handlePutBucketTagging(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string) {

	// Ensure bucket exists.
	if exists, err := s.bucketExists(ctx, bucket); err != nil {
		slog.Error("Put bucket tagging lookup", "bucket", bucket, "err", err)
		writeInternalError(w, r)
		return
	} else if !exists {
		writeNoSuchBucketError(w, r)
		return
	}

	defer r.Body.Close()
	var tagging Tagging
	if err := xml.NewDecoder(r.Body).Decode(&tagging); err != nil {
		slog.Error("Decode bucket tagging XML", "bucket", bucket, "err", err)
		writeS3Error(w, "MalformedXML", "The XML you provided was not well-formed or did not validate against our published schema.", r.URL.Path, http.StatusBadRequest)
		return
	}

	if len(tagging.TagSet) > 50 {
		writeS3Error(w, "InvalidRequest", "The TagSet cannot contain more than 50 tags.", r.URL.Path, http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()

	err := withTransaction(ctx, s.Db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM bucket_tags WHERE bucket = ?`, bucket); err != nil {
			slog.Error("Delete existing bucket tags", "bucket", bucket, "err", err)
			writeInternalError(w, r)
			return fmt.Errorf("error deleting existing tag %w", err)
		}

		for _, tag := range tagging.TagSet {
			if tag.Key == "" {
				writeS3Error(w, "InvalidTag", "The TagKey you have provided is invalid.", r.URL.Path, http.StatusBadRequest)
				return fmt.Errorf("invalid tag key `%s`", tag.Key)
			}

			if strings.HasPrefix(strings.ToLower(tag.Key), "aws:") {
				writeS3Error(w, "InvalidTag", "System tags prefixed with 'aws:' are reserved and cannot be modified.", r.URL.Path, http.StatusBadRequest)
				return fmt.Errorf("reserved tag key `%s`", tag.Key)
			}

			if _, err := tx.ExecContext(ctx, `INSERT INTO bucket_tags(bucket, key, value) VALUES(?, ?, ?)`, bucket, tag.Key, tag.Value); err != nil {
				slog.Error("Insert bucket tag", "bucket", bucket, "key", tag.Key, "err", err)
				writeInternalError(w, r)
				return fmt.Errorf("error inserting tag `%s` %w", tag.Key, err)
			}
		}

		if _, err := tx.ExecContext(ctx, `UPDATE buckets SET modified_at = ? WHERE name = ?`, now, bucket); err != nil {
			slog.Error("Update bucket modified_at for tagging", "bucket", bucket, "err", err)
			writeInternalError(w, r)
			return fmt.Errorf("error updating bucket modified_at %w", err)
		}

		return nil
	})

	if err != nil {
		slog.Error("Put bucket tagging transaction", "bucket", bucket, "err", err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleGetBucketTagging implements GET /bucket?tagging to retrieve the
// current set of tags associated with a bucket.
func (s *Server) handleGetBucketTagging(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string) {
	// Ensure bucket exists.
	if exists, err := s.bucketExists(ctx, bucket); err != nil {
		slog.Error("Get bucket tagging lookup", "bucket", bucket, "err", err)
		writeInternalError(w, r)
		return
	} else if !exists {
		writeNoSuchBucketError(w, r)
		return
	}

	rows, err := s.Db.QueryContext(ctx, `SELECT key, value FROM bucket_tags WHERE bucket = ? ORDER BY key`, bucket)
	if err != nil {
		slog.Error("Query bucket tags", "bucket", bucket, "err", err)
		writeInternalError(w, r)
		return
	}
	defer rows.Close()

	tagging := Tagging{XMLNS: S3XMLNamespace}
	for rows.Next() {
		var tag Tag
		if err := rows.Scan(&tag.Key, &tag.Value); err != nil {
			slog.Error("Scan bucket tag", "bucket", bucket, "err", err)
			continue
		}
		tagging.TagSet = append(tagging.TagSet, tag)
	}

	if len(tagging.TagSet) == 0 {
		writeS3Error(w, "NoSuchTagSet", "The TagSet does not exist.", r.URL.Path, http.StatusNotFound)
		return
	}

	if err := writeXMLResponse(w, tagging); err != nil {
		slog.Error("Encode bucket tagging XML", "bucket", bucket, "err", err)
	}
}

// handleDeleteBucketTagging implements DELETE /bucket?tagging to remove all
// tags associated with a bucket.
func (s *Server) handleDeleteBucketTagging(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string) {

	// Ensure bucket exists.
	if exists, err := s.bucketExists(ctx, bucket); err != nil {
		slog.Error("Delete bucket tagging lookup", "bucket", bucket, "err", err)
		writeInternalError(w, r)
		return
	} else if !exists {
		writeNoSuchBucketError(w, r)
		return
	}

	now := time.Now().UTC()

	if err := withTransaction(ctx, s.Db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM bucket_tags WHERE bucket = ?`, bucket); err != nil {
			slog.Error("Delete bucket tags", "bucket", bucket, "err", err)
			writeInternalError(w, r)
			return fmt.Errorf("error deleting bucket tags %w", err)
		}

		if _, err := tx.ExecContext(ctx, `UPDATE buckets SET modified_at = ? WHERE name = ?`, now, bucket); err != nil {
			slog.Error("Update bucket modified_at for delete tagging", "bucket", bucket, "err", err)
			writeInternalError(w, r)
			return fmt.Errorf("error updating bucket modified_at %w", err)
		}

		return nil
	}); err != nil {
		slog.Error("Delete bucket tagging transaction", "bucket", bucket, "err", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleListBuckets implements GET / to list all buckets.
func (s *Server) handleListBuckets(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	rows, err := s.Db.QueryContext(ctx, `SELECT name, created_at FROM buckets ORDER BY name`)
	if err != nil {
		slog.Error("List buckets", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	buckets := make([]BucketEntry, 0)
	for rows.Next() {
		var b BucketEntry
		if err := rows.Scan(&b.Name, &b.CreationDate); err != nil {
			slog.Error("Scan bucket", "err", err)
			continue
		}
		buckets = append(buckets, b)
	}

	resp := ListAllMyBucketsResult{
		XMLNS: S3XMLNamespace,
		Owner: Owner{
			ID:          "silo",
			DisplayName: "silo",
		},
		Buckets: buckets,
	}

	if err := writeXMLResponse(w, resp); err != nil {
		slog.Error("Encode list buckets XML", "err", err)
	}
}

// handleCopyObject implements a basic version of S3 CopyObject for
// non-multipart copies without conditional headers.
func (s *Server) handleCopyObject(ctx context.Context, w http.ResponseWriter, r *http.Request, destBucket string, destKey string, copySource string) {
	// Parse x-amz-copy-source, which is typically of the form
	// "/source-bucket/source-key" or "source-bucket/source-key" and may be
	// URL-encoded and include a query string.
	src := copySource
	if i := strings.Index(src, "?"); i != -1 {
		src = src[:i]
	}
	src = strings.TrimPrefix(src, "/")
	decoded, err := url.PathUnescape(src)
	if err != nil {
		writeS3Error(w, "InvalidRequest", "Unable to parse copy source.", r.URL.Path, http.StatusBadRequest)
		return
	}

	parts := strings.SplitN(decoded, "/", 2)
	if len(parts) != 2 {
		writeS3Error(w, "InvalidRequest", "Invalid copy source.", r.URL.Path, http.StatusBadRequest)
		return
	}
	srcBucket, srcKey := parts[0], parts[1]

	// Ensure destination bucket exists; align behavior with S3/MinIO by
	// returning an error instead of auto-creating missing buckets.
	if exists, err := s.bucketExists(ctx, destBucket); err != nil {
		slog.Error("Lookup dest bucket for copy", "bucket", destBucket, "err", err)
		writeInternalError(w, r)
		return
	} else if !exists {
		writeNoSuchBucketError(w, r)
		return
	}

	// Look up source object metadata.
	hashHex, size, contentType, _, err := s.lookupObjectMetadata(ctx, srcBucket, srcKey)
	if errors.Is(err, sql.ErrNoRows) {
		writeNoSuchKeyError(w, r)
		return
	}
	if err != nil {
		slog.Error("Lookup source object for copy", "srcBucket", srcBucket, "srcKey", srcKey, "err", err)
		writeInternalError(w, r)
		return
	}

	// Ensure destination bucket exists; for convenience, auto-create if missing.
	if _, err := s.ensureBucket(ctx, destBucket); err != nil {
		slog.Error("Ensure dest bucket for copy", "bucket", destBucket, "err", err)
		writeInternalError(w, r)
		return
	}

	now := time.Now().UTC()

	var ct any
	if contentType.Valid {
		ct = contentType.String
	}
	if err := s.upsertObjectMetadata(ctx, destBucket, destKey, hashHex, size, ct, now); err != nil {
		slog.Error("Upsert dest object metadata for copy", "destBucket", destBucket, "destKey", destKey, "err", err)
		writeInternalError(w, r)
		return
	}

	resp := CopyObjectResult{
		XMLNS:        S3XMLNamespace,
		LastModified: now.UTC().Format(time.RFC3339),
		ETag:         createETag(hashHex),
	}

	if err := writeXMLResponse(w, resp); err != nil {
		slog.Error("Encode copy object XML", "destBucket", destBucket, "destKey", destKey, "err", err)
	}
}

// handleDeleteBucket implements DELETE /bucket for the primary bucket
// deletion operation (without subresources). It removes the bucket's
// metadata entry and cascades object rows, then asks the storage engine to
// delete the corresponding on-disk data.
func (s *Server) handleDeleteBucket(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string) {

	// Ensure bucket exists.
	if exists, err := s.bucketExists(ctx, bucket); err != nil {
		slog.Error("Delete bucket lookup", "bucket", bucket, "err", err)
		writeInternalError(w, r)
		return
	} else if !exists {
		writeNoSuchBucketError(w, r)
		return
	}

	// Delete the bucket row; foreign-key cascade removes its objects.
	if _, err := s.Db.ExecContext(ctx, `DELETE FROM buckets WHERE name = ?`, bucket); err != nil {
		slog.Error("Delete bucket metadata", "bucket", bucket, "err", err)
		writeInternalError(w, r)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleListObjects implements a simplified version of S3 ListObjects (v2)
// for a single bucket: GET /bucket[?prefix=&max-keys=].
func (s *Server) handleListObjects(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string) {

	// Ensure bucket exists.
	if exists, err := s.bucketExists(ctx, bucket); err != nil {
		slog.Error("Check bucket exists", "bucket", bucket, "err", err)
		writeInternalError(w, r)
		return
	} else if !exists {
		writeNoSuchBucketError(w, r)
		return
	}

	q := r.URL.Query()
	prefix := q.Get("prefix")
	delimiter := q.Get("delimiter")
	maxKeys := 1000
	if raw := q.Get("max-keys"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			maxKeys = v
		}
	}

	// Fetch up to maxKeys+1 to determine truncation. We may emit fewer
	// entries than rows when using a delimiter (due to CommonPrefixes),
	// but this keeps the query bounded.
	args := []any{bucket}
	query := `SELECT key, hash, size, modified_at FROM objects WHERE bucket = ?`
	if prefix != "" {
		query += " AND key LIKE ?"
		args = append(args, prefix+"%")
	}
	query += " ORDER BY key LIMIT ?"
	args = append(args, maxKeys+1)

	rows, err := s.Db.QueryContext(ctx, query, args...)
	if err != nil {
		slog.Error("List objects", "bucket", bucket, "err", err)
		writeInternalError(w, r)
		return
	}
	defer rows.Close()

	var (
		summaries      []ObjectSummary
		commonPrefixes []CommonPrefix
		seenPrefixes   = make(map[string]struct{})
		isTruncated    bool
		entryCount     int
	)

	for rows.Next() {
		var (
			key        string
			hashHex    string
			size       int64
			modifiedAt time.Time
		)
		if err := rows.Scan(&key, &hashHex, &size, &modifiedAt); err != nil {
			slog.Error("Scan object", "bucket", bucket, "err", err)
			continue
		}

		// If no delimiter is requested, return a flat listing.
		if delimiter == "" {
			if entryCount < maxKeys {
				summaries = append(summaries, ObjectSummary{
					Key:          key,
					LastModified: modifiedAt.UTC().Format(time.RFC3339),
					ETag:         createETag(hashHex),
					Size:         size,
					StorageClass: "STANDARD",
				})
				entryCount++
			} else {
				isTruncated = true
				break
			}
			continue
		}

		// Delimited listing: group keys into CommonPrefixes for the first
		// path segment after the prefix. Objects directly under the prefix
		// are returned as Contents.
		rel := strings.TrimPrefix(key, prefix)
		idx := strings.Index(rel, delimiter)
		if idx == -1 {
			// No further delimiter; treat as an object at this level.
			if entryCount < maxKeys {
				summaries = append(summaries, ObjectSummary{
					Key:          key,
					LastModified: modifiedAt.UTC().Format(time.RFC3339),
					ETag:         createETag(hashHex),
					Size:         size,
					StorageClass: "STANDARD",
				})
				entryCount++
			} else {
				isTruncated = true
				break
			}
			continue
		}

		// There is another delimiter; emit or reuse a CommonPrefix.
		cp := prefix + rel[:idx+1]
		if _, ok := seenPrefixes[cp]; ok {
			continue
		}
		if entryCount < maxKeys {
			seenPrefixes[cp] = struct{}{}
			commonPrefixes = append(commonPrefixes, CommonPrefix{Prefix: cp})
			entryCount++
		} else {
			isTruncated = true
			break
		}
	}

	resp := ListBucketResultV1{
		XMLNS:          S3XMLNamespace,
		Name:           bucket,
		Prefix:         prefix,
		Delimiter:      delimiter,
		MaxKeys:        maxKeys,
		IsTruncated:    isTruncated,
		Contents:       summaries,
		CommonPrefixes: commonPrefixes,
	}

	if err := writeXMLResponse(w, resp); err != nil {
		slog.Error("Encode list objects XML", "bucket", bucket, "err", err)
	}
}

// handleListObjectsV2 implements S3 ListObjectsV2:
// GET /bucket?list-type=2[&prefix=&max-keys=&continuation-token=&start-after=].
func (s *Server) handleListObjectsV2(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string) {

	// Ensure bucket exists.
	if exists, err := s.bucketExists(ctx, bucket); err != nil {
		slog.Error("Check bucket exists (v2)", "bucket", bucket, "err", err)
		writeInternalError(w, r)
		return
	} else if !exists {
		writeNoSuchBucketError(w, r)
		return
	}

	q := r.URL.Query()
	prefix := q.Get("prefix")
	delimiter := q.Get("delimiter")
	continuationToken := q.Get("continuation-token")
	startAfter := ""
	if continuationToken == "" {
		startAfter = q.Get("start-after")
	}

	maxKeys := 1000
	if raw := q.Get("max-keys"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			maxKeys = v
		}
	}

	// Fetch up to maxKeys+1 to determine truncation. As with v1, we may
	// emit fewer entries than rows when using a delimiter.
	args := []any{bucket}
	query := `SELECT key, hash, size, modified_at FROM objects WHERE bucket = ?`
	if prefix != "" {
		query += " AND key LIKE ?"
		args = append(args, prefix+"%")
	}
	if continuationToken != "" {
		query += " AND key > ?"
		args = append(args, continuationToken)
	} else if startAfter != "" {
		query += " AND key > ?"
		args = append(args, startAfter)
	}
	query += " ORDER BY key LIMIT ?"
	args = append(args, maxKeys+1)

	rows, err := s.Db.QueryContext(ctx, query, args...)
	if err != nil {
		slog.Error("List objects v2", "bucket", bucket, "err", err)
		writeInternalError(w, r)
		return
	}
	defer rows.Close()

	var (
		summaries      []ObjectSummary
		commonPrefixes []CommonPrefix
		seenPrefixes   = make(map[string]struct{})
		isTruncated    bool
		entryCount     int
		lastScannedKey string
	)

	for rows.Next() {
		var (
			key        string
			hashHex    string
			size       int64
			modifiedAt time.Time
		)
		if err := rows.Scan(&key, &hashHex, &size, &modifiedAt); err != nil {
			slog.Error("Scan object (v2)", "bucket", bucket, "err", err)
			continue
		}
		lastScannedKey = key

		// Flat (recursive-style) listing when no delimiter is provided.
		if delimiter == "" {
			if entryCount < maxKeys {
				summaries = append(summaries, ObjectSummary{
					Key:          key,
					LastModified: modifiedAt.UTC().Format(time.RFC3339),
					ETag:         createETag(hashHex),
					Size:         size,
					StorageClass: "STANDARD",
				})
				entryCount++
			} else {
				isTruncated = true
				break
			}
			continue
		}

		// Delimited listing: group by first path segment after prefix.
		rel := strings.TrimPrefix(key, prefix)
		idx := strings.Index(rel, delimiter)
		if idx == -1 {
			if entryCount < maxKeys {
				summaries = append(summaries, ObjectSummary{
					Key:          key,
					LastModified: modifiedAt.UTC().Format(time.RFC3339),
					ETag:         createETag(hashHex),
					Size:         size,
					StorageClass: "STANDARD",
				})
				entryCount++
			} else {
				isTruncated = true
				break
			}
			continue
		}

		cp := prefix + rel[:idx+1]
		if _, ok := seenPrefixes[cp]; ok {
			continue
		}
		if entryCount < maxKeys {
			seenPrefixes[cp] = struct{}{}
			commonPrefixes = append(commonPrefixes, CommonPrefix{Prefix: cp})
			entryCount++
		} else {
			isTruncated = true
			break
		}
	}

	keyCount := entryCount
	nextContinuationToken := ""
	if isTruncated {
		// When there is no delimiter (or no common prefixes), follow the
		// usual S3/ListObjectsV2 behavior of using the last returned object
		// key as the continuation token so clients resume after the last
		// visible entry. When using a delimiter and returning common
		// prefixes, fall back to the last scanned key, which is sufficient
		// for forward progress and compatible with minio-go.
		if (delimiter == "" || len(commonPrefixes) == 0) && len(summaries) > 0 {
			nextContinuationToken = summaries[len(summaries)-1].Key
		} else if lastScannedKey != "" {
			nextContinuationToken = lastScannedKey
		}
	}

	resp := ListBucketResultV2{
		XMLNS:                 S3XMLNamespace,
		Name:                  bucket,
		Prefix:                prefix,
		Delimiter:             delimiter,
		KeyCount:              keyCount,
		MaxKeys:               maxKeys,
		IsTruncated:           isTruncated,
		ContinuationToken:     continuationToken,
		NextContinuationToken: nextContinuationToken,
		StartAfter:            startAfter,
		Contents:              summaries,
		CommonPrefixes:        commonPrefixes,
	}

	if err := writeXMLResponse(w, resp); err != nil {
		slog.Error("Encode list objects v2 XML", "bucket", bucket, "err", err)
	}
}

// ------ Multipart upload handlers ------

// multipartUploadMetadata is stored alongside each in-progress multipart
// upload under data/uploads/<uploadId>/ to record its associated bucket
// and key.
type multipartUploadMetadata struct {
	Bucket  string
	Key     string
	Created string
}

// writeMultipartUploadMetadata writes a simple metadata file into uploadDir
// so that ListMultipartUploads can discover the bucket/key for an upload ID.
func writeMultipartUploadMetadata(uploadDir string, meta multipartUploadMetadata) error {
	metaPath := filepath.Join(uploadDir, "metadata")
	f, err := os.Create(metaPath)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := fmt.Fprintln(f, meta.Bucket); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f, meta.Key); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f, meta.Created); err != nil {
		return err
	}

	return nil
}

// readMultipartUploadMetadata loads multipartUploadMetadata from uploadDir.
func readMultipartUploadMetadata(uploadDir string) (multipartUploadMetadata, error) {
	metaPath := filepath.Join(uploadDir, "metadata")
	f, err := os.Open(metaPath)
	if err != nil {
		return multipartUploadMetadata{}, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return multipartUploadMetadata{}, err
	}
	if len(lines) < 2 {
		return multipartUploadMetadata{}, fmt.Errorf("invalid multipart metadata: expected at least 2 lines, got %d", len(lines))
	}

	meta := multipartUploadMetadata{
		Bucket: lines[0],
		Key:    lines[1],
	}
	if len(lines) >= 3 {
		meta.Created = lines[2]
	}
	return meta, nil
}

// handleCreateMultipartUpload implements CreateMultipartUpload
// (InitiateMultipartUpload): POST /bucket/key?uploads
func (s *Server) handleCreateMultipartUpload(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string, key string) {
	// Ensure bucket exists; do not auto-create.
	if exists, err := s.bucketExists(ctx, bucket); err != nil {
		slog.Error("Create multipart upload bucket lookup", "bucket", bucket, "err", err)
		writeInternalError(w, r)
		return
	} else if !exists {
		writeNoSuchBucketError(w, r)
		return
	}

	uploadID := uuid.NewString()
	uploadDir := filepath.Join(s.Config.DataDir, "uploads", uploadID)
	if err := os.MkdirAll(uploadDir, 0o755); err != nil {
		slog.Error("Create multipart upload dir", "path", uploadDir, "err", err)
		writeInternalError(w, r)
		return
	}

	// Record basic metadata for this in-progress upload so that
	// ListMultipartUploads can associate upload IDs with bucket/keys.
	meta := multipartUploadMetadata{
		Bucket:  bucket,
		Key:     key,
		Created: time.Now().UTC().Format(time.RFC3339),
	}
	if err := writeMultipartUploadMetadata(uploadDir, meta); err != nil {
		slog.Error("Write multipart upload metadata", "path", uploadDir, "err", err)
		writeInternalError(w, r)
		return
	}

	resp := InitiateMultipartUploadResult{
		XMLNS:    S3XMLNamespace,
		Bucket:   bucket,
		Key:      key,
		UploadID: uploadID,
	}

	if err := writeXMLResponse(w, resp); err != nil {
		slog.Error("Encode create multipart upload XML", "bucket", bucket, "key", key, "err", err)
	}
}

// handleUploadPart implements UploadPart: PUT /bucket/key?partNumber=N&uploadId=ID
func (s *Server) handleUploadPart(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string, key string, uploadID string, partNumber int) {
	// Ensure bucket exists; do not auto-create.
	if exists, err := s.bucketExists(ctx, bucket); err != nil {
		slog.Error("Upload part bucket lookup", "bucket", bucket, "err", err)
		writeInternalError(w, r)
		return
	} else if !exists {
		writeNoSuchBucketError(w, r)
		return
	}

	uploadDir := filepath.Join(s.Config.DataDir, "uploads", uploadID)
	if stat, err := os.Stat(uploadDir); err != nil || !stat.IsDir() {
		writeS3Error(w, "NoSuchUpload", "The specified multipart upload does not exist.", r.URL.Path, http.StatusNotFound)
		return
	}

	partFilename := fmt.Sprintf("part-%06d", partNumber)
	partPath := filepath.Join(uploadDir, partFilename)
	partFile, err := os.Create(partPath)
	if err != nil {
		slog.Error("Create upload part file", "path", partPath, "err", err)
		writeInternalError(w, r)
		return
	}
	defer func() {
		if err := partFile.Close(); err != nil {
			slog.Debug("Failed to close upload part file", "path", partPath, "err", err)
		}
	}()

	contentSHA := r.Header.Get("X-Amz-Content-Sha256")
	h := sha256.New()
	var size int64

	if strings.EqualFold(contentSHA, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD") {
		decodedLenStr := r.Header.Get("X-Amz-Decoded-Content-Length")
		if decodedLenStr == "" {
			slog.Error("Missing X-Amz-Decoded-Content-Length for streaming upload part")
			writeS3Error(w, "InvalidRequest", "Missing X-Amz-Decoded-Content-Length for streaming payload", r.URL.Path, http.StatusBadRequest)
			return
		}

		decodedLen, parseErr := strconv.ParseInt(decodedLenStr, 10, 64)
		if parseErr != nil || decodedLen < 0 {
			slog.Error("Invalid X-Amz-Decoded-Content-Length for upload part", "value", decodedLenStr, "err", parseErr)
			writeS3Error(w, "InvalidRequest", "Invalid X-Amz-Decoded-Content-Length", r.URL.Path, http.StatusBadRequest)
			return
		}

		// Re-use the streaming decoder to write into the part file and
		// compute the SHA-256 hash.
		written, hashHex, err := s.decodeStreamingPayloadToTemp(io.MultiWriter(partFile, h), r.Body, decodedLen)
		if err != nil {
			slog.Error("Decode streaming upload part", "bucket", bucket, "key", key, "err", err)
			writeS3Error(w, "InvalidRequest", "Failed to decode streaming payload", r.URL.Path, http.StatusBadRequest)
			return
		}
		_ = hashHex
		size = written
	} else {
		// Regular (non-streaming) payload: stream to file while hashing.
		mw := io.MultiWriter(partFile, h)
		written, err := io.Copy(mw, r.Body)
		if err != nil {
			slog.Error("Write upload part payload", "bucket", bucket, "key", key, "err", err)
			writeS3Error(w, "InvalidRequest", "Failed to read request body", r.URL.Path, http.StatusBadRequest)
			return
		}
		size = written
	}

	_ = size // Size is not currently persisted per-part.

	// Return a simple ETag derived from the SHA-256 of the part.
	hashHex := hex.EncodeToString(h.Sum(nil))
	w.Header().Set("ETag", createETag(hashHex))
	w.WriteHeader(http.StatusOK)
}

// handleCompleteMultipartUpload implements CompleteMultipartUpload:
// POST /bucket/key?uploadId=ID
func (s *Server) handleCompleteMultipartUpload(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string, key string, uploadID string) {
	// Ensure bucket exists; do not auto-create.
	if exists, err := s.bucketExists(ctx, bucket); err != nil {
		slog.Error("Complete multipart upload bucket lookup", "bucket", bucket, "err", err)
		writeInternalError(w, r)
		return
	} else if !exists {
		writeNoSuchBucketError(w, r)
		return
	}

	uploadDir := filepath.Join(s.Config.DataDir, "uploads", uploadID)
	if stat, err := os.Stat(uploadDir); err != nil || !stat.IsDir() {
		writeS3Error(w, "NoSuchUpload", "The specified multipart upload does not exist.", r.URL.Path, http.StatusNotFound)
		return
	}

	defer r.Body.Close()
	var req CompleteMultipartUpload
	if err := xml.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Error("Decode complete multipart upload XML", "bucket", bucket, "key", key, "err", err)
		writeS3Error(w, "MalformedXML", "The XML you provided was not well-formed or did not validate against our published schema.", r.URL.Path, http.StatusBadRequest)
		return
	}

	if len(req.Parts) == 0 {
		writeS3Error(w, "InvalidRequest", "You must specify at least one part.", r.URL.Path, http.StatusBadRequest)
		return
	}

	uploadsRoot := filepath.Join(s.Config.DataDir, "uploads")
	if err := os.MkdirAll(uploadsRoot, 0o755); err != nil {
		slog.Error("Ensure uploads root for complete", "path", uploadsRoot, "err", err)
		writeInternalError(w, r)
		return
	}

	finalFile, err := os.CreateTemp(uploadsRoot, "multipart-final-*")
	if err != nil {
		slog.Error("Create final multipart temp file", "bucket", bucket, "key", key, "err", err)
		writeInternalError(w, r)
		return
	}
	defer func() {
		name := finalFile.Name()
		if err := finalFile.Close(); err != nil {
			slog.Debug("Failed to close final multipart file", "path", name, "err", err)
		}
		// Best-effort cleanup; storage engine may have moved the file.
		if err := os.Remove(name); err != nil && !os.IsNotExist(err) {
			slog.Debug("Failed to remove final multipart temp file", "path", name, "err", err)
		}
	}()

	h := sha256.New()
	var totalSize int64
	buf := make([]byte, 32*1024)

	for _, part := range req.Parts {
		if part.PartNumber <= 0 {
			writeS3Error(w, "InvalidArgument", "Invalid part number.", r.URL.Path, http.StatusBadRequest)
			return
		}
		partFilename := fmt.Sprintf("part-%06d", part.PartNumber)
		partPath := filepath.Join(uploadDir, partFilename)
		pf, err := os.Open(partPath)
		if err != nil {
			slog.Error("Open upload part file for complete", "path", partPath, "err", err)
			writeS3Error(w, "InvalidPart", "One or more of the specified parts could not be found.", r.URL.Path, http.StatusBadRequest)
			return
		}

		defer func() {
			if err := pf.Close(); err != nil {
				slog.Debug("Failed to close upload part file after complete", "path", partPath, "err", err)
			}
		}()

		// Stream the part into the final file while simultaneously hashing it
		// using a TeeReader to avoid manually duplicating writes.
		n, err := io.CopyBuffer(finalFile, io.TeeReader(pf, h), buf)
		if err != nil {
			slog.Error("Stream upload part into final file", "bucket", bucket, "key", key, "path", partPath, "err", err)
			writeInternalError(w, r)
			return
		}
		totalSize += n
	}

	hashHex := hex.EncodeToString(h.Sum(nil))

	// Store the completed object using the storage engine.
	if err := s.Config.Engine.PutObjectFromFile(bucket, hashHex, finalFile.Name(), totalSize); err != nil {
		slog.Error("Store completed multipart object", "bucket", bucket, "key", key, "err", err)
		writeInternalError(w, r)
		return
	}

	// Record object metadata.
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	now := time.Now().UTC()
	if err := s.upsertObjectMetadata(ctx, bucket, key, hashHex, totalSize, contentType, now); err != nil {
		slog.Error("Upsert object metadata (complete multipart)", "bucket", bucket, "key", key, "err", err)
		writeInternalError(w, r)
		return
	}

	// Best-effort cleanup of the multipart upload directory.
	if err := os.RemoveAll(uploadDir); err != nil && !os.IsNotExist(err) {
		slog.Debug("Failed to remove multipart upload dir", "path", uploadDir, "err", err)
	}

	resp := CompleteMultipartUploadResult{
		XMLNS:    S3XMLNamespace,
		Location: fmt.Sprintf("/%s/%s", bucket, key),
		Bucket:   bucket,
		Key:      key,
		ETag:     createETag(hashHex),
	}

	if err := writeXMLResponse(w, resp); err != nil {
		slog.Error("Encode complete multipart upload XML", "bucket", bucket, "key", key, "err", err)
	}
}

// handleAbortMultipartUpload implements AbortMultipartUpload:
// DELETE /bucket/key?uploadId=ID
func (s *Server) handleAbortMultipartUpload(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string, key string, uploadID string) {
	_ = ctx
	_ = key

	// Per S3 semantics this is largely idempotent; we simply remove the
	// temporary upload directory if it exists.
	uploadDir := filepath.Join(s.Config.DataDir, "uploads", uploadID)
	if err := os.RemoveAll(uploadDir); err != nil && !os.IsNotExist(err) {
		slog.Debug("Failed to remove multipart upload dir on abort", "path", uploadDir, "err", err)
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleListMultipartUploads implements ListMultipartUploads:
// GET /bucket?uploads
func (s *Server) handleListMultipartUploads(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string) {
	// Ensure bucket exists; do not auto-create.
	if exists, err := s.bucketExists(ctx, bucket); err != nil {
		slog.Error("ListMultipartUploads bucket lookup", "bucket", bucket, "err", err)
		writeInternalError(w, r)
		return
	} else if !exists {
		writeNoSuchBucketError(w, r)
		return
	}

	q := r.URL.Query()
	prefix := q.Get("prefix")
	maxUploads := 1000
	if raw := q.Get("max-uploads"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			maxUploads = v
		}
	}

	uploadsRoot := filepath.Join(s.Config.DataDir, "uploads")
	entries, err := os.ReadDir(uploadsRoot)
	if err != nil {
		if os.IsNotExist(err) {
			// No in-progress uploads; return an empty result.
			resp := ListMultipartUploadsResult{
				XMLNS:       S3XMLNamespace,
				Bucket:      bucket,
				MaxUploads:  maxUploads,
				IsTruncated: false,
				Prefix:      prefix,
			}
			if wErr := writeXMLResponse(w, resp); wErr != nil {
				slog.Error("Encode empty ListMultipartUploads XML", "bucket", bucket, "err", wErr)
			}
			return
		}
		slog.Error("ListMultipartUploads read uploads root", "path", uploadsRoot, "err", err)
		writeInternalError(w, r)
		return
	}

	uploads := make([]MultipartUploadInfo, 0)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		uploadID := entry.Name()
		uploadDir := filepath.Join(uploadsRoot, uploadID)
		meta, err := readMultipartUploadMetadata(uploadDir)
		if err != nil {
			slog.Debug("ListMultipartUploads read metadata", "path", uploadDir, "err", err)
			continue
		}

		if meta.Bucket != bucket {
			continue
		}
		if prefix != "" && !strings.HasPrefix(meta.Key, prefix) {
			continue
		}

		initiated := meta.Created
		if initiated == "" {
			if info, err := os.Stat(uploadDir); err == nil {
				initiated = info.ModTime().UTC().Format(time.RFC3339)
			}
		}

		owner := Owner{ID: "silo", DisplayName: "silo"}
		uploads = append(uploads, MultipartUploadInfo{
			Key:          meta.Key,
			UploadID:     uploadID,
			Initiator:    owner,
			Owner:        owner,
			StorageClass: "STANDARD",
			Initiated:    initiated,
		})

		if len(uploads) >= maxUploads {
			break
		}
	}

	resp := ListMultipartUploadsResult{
		XMLNS:       S3XMLNamespace,
		Bucket:      bucket,
		MaxUploads:  maxUploads,
		IsTruncated: len(uploads) >= maxUploads,
		Prefix:      prefix,
		Uploads:     uploads,
	}

	if err := writeXMLResponse(w, resp); err != nil {
		slog.Error("Encode ListMultipartUploads XML", "bucket", bucket, "err", err)
	}
}

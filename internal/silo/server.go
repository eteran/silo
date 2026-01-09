package silo

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
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var (
	//go:embed migrations
	migrationsFS embed.FS

	bucketNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*[a-z0-9]$`)
)

type Config struct {
	DataDir string
	Region  string
	Engine  StorageEngine
}

// Server provides a minimal S3-compatible HTTP API.
type Server struct {
	cfg Config
	db  *sql.DB
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

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	if err := initSchema(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}

	if cfg.Engine == nil {
		cfg.Engine = NewLocalFileStorage(cfg.DataDir)
	}

	return &Server{cfg: cfg, db: db}, nil
}

// Close closes any resources held by the Server.
func (s *Server) Close() error {
	return s.db.Close()
}

// WithTransaction runs a function within a database transaction.
func WithTransaction(ctx context.Context, db *sql.DB, fn func(tx *sql.Tx) error) error {
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
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM buckets WHERE name = ?`, bucket).Scan(&count); err != nil {
		return false, err
	}

	return count > 0, nil
}

// ensureBucket makes sure the given bucket exists, creating it if necessary.
// It returns true if the bucket was created, false if it already existed.
func (s *Server) ensureBucket(ctx context.Context, name string) (bool, error) {
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx,
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

// parentPrefixForKey returns the immediate parent prefix for a given S3
// object key. For example:
//
//	"a/b/c.txt" -> "a/b/"
//	"file.txt"  -> ""
//	"dir/"      -> "" (treated as a top-level key whose name ends with '/')
func parentPrefixForKey(key string) string {
	trimmed := strings.TrimRight(key, "/")
	idx := strings.LastIndex(trimmed, "/")
	if idx == -1 {
		return ""
	}
	// Include the trailing slash from the original key up to and including idx.
	return key[:idx+1]
}

// isValidBucketName implements the standard S3 bucket naming rules for
// "virtual hosted-style" buckets.
func isValidBucketName(name string) bool {
	if len(name) < 3 || len(name) > 63 {
		return false
	}

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

// decodeStreamingPayloadToTemp decodes an AWS Signature Version 4 streaming
// (chunked) payload into a temporary file under the server's data directory
// while computing the SHA-256 hash of the decoded payload. It returns the
// temp file path, the decoded payload length, and the payload hash.
func (s *Server) decodeStreamingPayloadToTemp(f io.Writer, body io.Reader, decodedLen int64) (int64, string, error) {
	br := bufio.NewReader(body)

	h := sha256.New()
	var written int64

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

		remaining := size
		buf := make([]byte, 32*1024)
		for remaining > 0 {
			toRead := min(remaining, int64(len(buf)))
			n, err := io.ReadFull(br, buf[:toRead])
			if err != nil {
				return 0, "", fmt.Errorf("read chunk body: %w", err)
			}
			if _, err := f.Write(buf[:n]); err != nil {
				return 0, "", fmt.Errorf("write chunk to temp file: %w", err)
			}
			if _, err := h.Write(buf[:n]); err != nil {
				return 0, "", fmt.Errorf("hash chunk: %w", err)
			}
			written += int64(n)
			remaining -= int64(n)
		}

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

// ------ Dispatchers for bucket-level HTTP handlers ------

// handleBucketPut dispatches PUT /bucket[?subresource] between CreateBucket
// and various bucket configuration APIs.
func (s *Server) handleBucketPut(w http.ResponseWriter, r *http.Request, bucket string) {
	if !validateBucketNameOrError(w, r, bucket) {
		return
	}

	q := r.URL.Query()
	switch {
	case q.Has("tagging"):
		s.handlePutBucketTagging(w, r, bucket)
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
		s.handleCreateBucket(w, r, bucket)
	}
}

// handleBucketPost implements POST /bucket[?subresource], such as DeleteObjects.
func (s *Server) handleBucketPost(w http.ResponseWriter, r *http.Request, bucket string) {
	if !validateBucketNameOrError(w, r, bucket) {
		return
	}

	q := r.URL.Query()
	switch {
	case q.Has("delete"):
		s.writeNotImplemented(w, r, "DeleteObjects")
	default:
		s.writeNotImplemented(w, r, "BucketPost")
	}
}

// handleBucketGet dispatches GET /bucket[?subresource] between ListObjects
// and bucket-level read APIs.
func (s *Server) handleBucketGet(w http.ResponseWriter, r *http.Request, bucket string) {
	if !validateBucketNameOrError(w, r, bucket) {
		return
	}

	q := r.URL.Query()
	switch {
	case q.Has("location"):
		s.handleGetBucketLocation(w, r, bucket)
	case q.Has("tagging"):
		s.handleGetBucketTagging(w, r, bucket)
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
		s.handleListObjectsV2(w, r, bucket)
	case q.Has("versions"):
		s.writeNotImplemented(w, r, "ListObjectVersions")
	case q.Has("uploads"):
		s.writeNotImplemented(w, r, "ListMultipartUploads")
	default:
		s.handleListObjects(w, r, bucket)
	}
}

// handleBucketDelete implements DELETE /bucket[?subresource].
func (s *Server) handleBucketDelete(w http.ResponseWriter, r *http.Request, bucket string) {
	if !validateBucketNameOrError(w, r, bucket) {
		return
	}

	q := r.URL.Query()
	switch {
	case q.Has("tagging"):
		s.handleDeleteBucketTagging(w, r, bucket)
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
		s.handleDeleteBucket(w, r, bucket)
	}
}

// handleBucketHead implements HEAD /bucket.
func (s *Server) handleBucketHead(w http.ResponseWriter, r *http.Request, bucket string) {
	if !validateBucketNameOrError(w, r, bucket) {
		return
	}

	// Ensure bucket exists.
	if exists, err := s.bucketExists(r.Context(), bucket); err != nil {
		slog.Error("Bucket head", "bucket", bucket, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	} else if !exists {
		writeS3Error(w, "NoSuchBucket", "The specified bucket does not exist.", r.URL.Path, http.StatusNotFound)
		return
	}

	// S3-compatible HEAD bucket: 200 with no body.
	w.WriteHeader(http.StatusOK)
}

// ------ Dispatchers for object-level HTTP handlers ------

// handleObjectPost implements POST /bucket/key[?subresource] operations such
// as CompleteMultipartUpload, RestoreObject, and SelectObjectContent.
func (s *Server) handleObjectPost(w http.ResponseWriter, r *http.Request, bucket string, key string) {
	if !validateBucketNameOrError(w, r, bucket) {
		return
	}
	if !validateObjectKeyOrError(w, r, key) {
		return
	}

	q := r.URL.Query()
	switch {
	case q.Has("uploadId"):
		s.writeNotImplemented(w, r, "CompleteMultipartUpload")
	case q.Has("restore"):
		s.writeNotImplemented(w, r, "RestoreObject")
	case q.Has("select"):
		s.writeNotImplemented(w, r, "SelectObjectContent")
	default:
		s.writeNotImplemented(w, r, "ObjectPost")
	}
}

// handleObjectGet implements GET /bucket/key to retrieve an object.
func (s *Server) handleObjectGet(w http.ResponseWriter, r *http.Request, bucket string, key string) {
	if !validateBucketNameOrError(w, r, bucket) {
		return
	}
	if !validateObjectKeyOrError(w, r, key) {
		return
	}

	q := r.URL.Query()
	switch {
	case q.Has("tagging"):
		s.handleGetObjectTagging(w, r, bucket, key)
	case q.Has("attributes"):
		s.writeNotImplemented(w, r, "GetObjectAttributes")
	case q.Has("uploadId"):
		s.writeNotImplemented(w, r, "ListParts")
	default:
		s.handleGetObject(w, r, bucket, key)
	}
}

// handleObjectDelete implements DELETE /bucket/key to delete an object.
func (s *Server) handleObjectDelete(w http.ResponseWriter, r *http.Request, bucket string, key string) {
	if !validateBucketNameOrError(w, r, bucket) {
		return
	}
	if !validateObjectKeyOrError(w, r, key) {
		return
	}

	q := r.URL.Query()
	switch {
	case q.Has("tagging"):
		s.handleDeleteObjectTagging(w, r, bucket, key)
	case q.Has("uploadId"):
		s.writeNotImplemented(w, r, "AbortMultipartUpload")
	default:
		s.handleDeleteObject(w, r, bucket, key)
	}
}

// handleObjectPut implements PUT /bucket/key to store an object.
func (s *Server) handleObjectPut(w http.ResponseWriter, r *http.Request, bucket string, key string) {
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
			} else {
				s.writeNotImplemented(w, r, "UploadPart")
			}
			return
		}
	}

	if q.Has("tagging") {
		s.handlePutObjectTagging(w, r, bucket, key)
		return
	}

	if copySource := r.Header.Get("x-amz-copy-source"); copySource != "" {
		s.handleCopyObject(w, r, bucket, key, copySource)
		return
	}

	if bucket == "" || key == "" {
		writeS3Error(w, "InvalidRequest", "Bucket and key must not be empty", r.URL.Path, http.StatusBadRequest)
		return
	}

	// Ensure bucket exists; for convenience, auto-create if missing.
	if _, err := s.ensureBucket(r.Context(), bucket); err != nil {
		slog.Error("Ensure bucket", "bucket", bucket, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
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

		tmpDir := filepath.Join(s.cfg.DataDir, "tmp")
		if err := os.MkdirAll(tmpDir, 0o755); err != nil {
			slog.Error("Error creating temp dir for streaming upload", "path", tmpDir, "err", err)
			writeS3Error(w, "InternalError", "Error creating temp dir for streaming upload", r.URL.Path, http.StatusInternalServerError)
		}

		tempPath, err := os.CreateTemp(tmpDir, "upload-*")
		if err != nil {
			slog.Error("Error creating temp dir for streaming upload", "path", tmpDir, "err", err)
			writeS3Error(w, "InternalError", "Error creating temp dir for streaming upload", r.URL.Path, http.StatusInternalServerError)
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

		if err := s.cfg.Engine.PutObjectFromFile(bucket, hash, tempPath.Name(), size); err != nil {
			slog.Error("Store object payload from file", "bucket", bucket, "key", key, "err", err)
			writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
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
		if err := s.cfg.Engine.PutObject(bucket, hashHex, data); err != nil {
			slog.Error("Store object payload", "bucket", bucket, "key", key, "err", err)
			writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
			return
		}
	}
	defer r.Body.Close()

	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	parent := parentPrefixForKey(key)
	now := time.Now().UTC()

	_, err = s.db.ExecContext(r.Context(),
		`INSERT INTO objects(bucket, key, parent, hash, size, content_type, created_at, modified_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(bucket, key) DO UPDATE SET
		 	parent=excluded.parent,
		 	hash=excluded.hash,
		 	size=excluded.size,
		 	content_type=excluded.content_type,
		 	modified_at=excluded.modified_at`,
		bucket, key, parent, hashHex, length, contentType, now, now,
	)
	if err != nil {
		slog.Error("Upsert object metadata", "bucket", bucket, "key", key, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	}

	w.Header().Set("ETag", createETag(hashHex))
	w.WriteHeader(http.StatusOK)
}

// handleObjectHead implements HEAD /bucket/key, returning metadata headers
// compatible with S3 but without a response body.
func (s *Server) handleObjectHead(w http.ResponseWriter, r *http.Request, bucket string, key string) {
	if !validateBucketNameOrError(w, r, bucket) {
		return
	}
	if !validateObjectKeyOrError(w, r, key) {
		return
	}

	var (
		hashHex     string
		size        int64
		contentType sql.NullString
		modifiedAt  time.Time
	)

	err := s.db.QueryRowContext(r.Context(),
		`SELECT hash, size, content_type, modified_at FROM objects WHERE bucket = ? AND key = ?`,
		bucket, key,
	).Scan(&hashHex, &size, &contentType, &modifiedAt)
	if errors.Is(err, sql.ErrNoRows) {
		writeS3Error(w, "NoSuchKey", "The specified key does not exist.", r.URL.Path, http.StatusNotFound)
		return
	}
	if err != nil {
		slog.Error("Lookup object metadata (HEAD)", "bucket", bucket, "key", key, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
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

// ------ Individual API HTTP handlers ------

func (s *Server) handleDeleteObject(w http.ResponseWriter, r *http.Request, bucket string, key string) {
	_, err := s.db.ExecContext(r.Context(), `DELETE FROM objects WHERE bucket = ? AND key = ?`, bucket, key)
	if err != nil {
		slog.Error("Delete object metadata", "bucket", bucket, "key", key, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
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
func (s *Server) handlePutObjectTagging(w http.ResponseWriter, r *http.Request, bucket string, key string) {
	ctx := r.Context()

	// Ensure object exists.
	var exists int
	if err := s.db.QueryRowContext(r.Context(), `SELECT 1 FROM objects WHERE bucket = ? AND key = ?`, bucket, key).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeS3Error(w, "NoSuchKey", "The specified key does not exist.", r.URL.Path, http.StatusNotFound)
			return
		}
		slog.Error("Put object tagging lookup", "bucket", bucket, "key", key, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
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

	if err := WithTransaction(ctx, s.db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM object_tags WHERE bucket = ? AND key = ?`, bucket, key); err != nil {
			slog.Error("Delete existing object tags", "bucket", bucket, "key", key, "err", err)
			writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
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
				writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
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
func (s *Server) handleGetObjectTagging(w http.ResponseWriter, r *http.Request, bucket string, key string) {
	// Ensure object exists.
	var exists int
	if err := s.db.QueryRowContext(r.Context(), `SELECT 1 FROM objects WHERE bucket = ? AND key = ?`, bucket, key).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeS3Error(w, "NoSuchKey", "The specified key does not exist.", r.URL.Path, http.StatusNotFound)
			return
		}
		slog.Error("Get object tagging lookup", "bucket", bucket, "key", key, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	}

	rows, err := s.db.QueryContext(r.Context(), `SELECT tag_key, tag_value FROM object_tags WHERE bucket = ? AND key = ? ORDER BY tag_key`, bucket, key)
	if err != nil {
		slog.Error("Query object tags", "bucket", bucket, "key", key, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	tagging := Tagging{XMLNS: s3XMLNamespace}
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
func (s *Server) handleDeleteObjectTagging(w http.ResponseWriter, r *http.Request, bucket string, key string) {
	ctx := r.Context()
	// Ensure object exists.
	var exists int
	if err := s.db.QueryRowContext(r.Context(), `SELECT 1 FROM objects WHERE bucket = ? AND key = ?`, bucket, key).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeS3Error(w, "NoSuchKey", "The specified key does not exist.", r.URL.Path, http.StatusNotFound)
			return
		}
		slog.Error("Delete object tagging lookup", "bucket", bucket, "key", key, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	}

	if err := WithTransaction(ctx, s.db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM object_tags WHERE bucket = ? AND key = ?`, bucket, key); err != nil {
			slog.Error("Delete object tags", "bucket", bucket, "key", key, "err", err)
			writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
			return fmt.Errorf("error deleting object tags %w", err)
		}

		return nil
	}); err != nil {
		slog.Error("Delete object tagging transaction", "bucket", bucket, "key", key, "err", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetObject(w http.ResponseWriter, r *http.Request, bucket string, key string) {
	var (
		hashHex     string
		size        int64
		contentType sql.NullString
		modifiedAt  time.Time
	)

	err := s.db.QueryRowContext(r.Context(),
		`SELECT hash, size, content_type, modified_at FROM objects WHERE bucket = ? AND key = ?`,
		bucket, key,
	).Scan(&hashHex, &size, &contentType, &modifiedAt)

	if errors.Is(err, sql.ErrNoRows) {
		writeS3Error(w, "NoSuchKey", "The specified key does not exist.", r.URL.Path, http.StatusNotFound)
		return
	}

	if err != nil {
		slog.Error("Lookup object metadata", "bucket", bucket, "key", key, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	}

	data, err := s.cfg.Engine.GetObject(bucket, hashHex)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "object payload missing", http.StatusInternalServerError)
			return
		}
		slog.Error("Read object payload", "bucket", bucket, "key", key, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
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
func (s *Server) handleCreateBucket(w http.ResponseWriter, r *http.Request, bucket string) {

	if created, err := s.ensureBucket(r.Context(), bucket); err != nil {
		slog.Error("Create bucket", "bucket", bucket, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	} else if !created {
		// Bucket already existed; S3 returns 409 BucketAlreadyExists.
		writeS3Error(w, "BucketAlreadyExists", "The requested bucket name is not available. The bucket namespace is shared by all users of the system. Please select a different name and try again.", r.URL.Path, http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleGetBucketLocation implements GET /bucket?location
func (s *Server) handleGetBucketLocation(w http.ResponseWriter, r *http.Request, bucket string) {

	// Ensure bucket exists.
	if exists, err := s.bucketExists(r.Context(), bucket); err != nil {
		slog.Error("Get bucket location", "bucket", bucket, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	} else if !exists {
		writeS3Error(w, "NoSuchBucket", "The specified bucket does not exist.", r.URL.Path, http.StatusNotFound)
		return
	}

	resp := LocationConstraint{
		XMLNS:  s3XMLNamespace,
		Region: s.cfg.Region,
	}

	if err := writeXMLResponse(w, resp); err != nil {
		slog.Error("Encode bucket location XML", "bucket", bucket, "err", err)
	}
}

// handlePutBucketTagging implements PUT /bucket?tagging to replace the
// complete set of tags associated with a bucket.
func (s *Server) handlePutBucketTagging(w http.ResponseWriter, r *http.Request, bucket string) {

	ctx := r.Context()

	// Ensure bucket exists.
	if exists, err := s.bucketExists(ctx, bucket); err != nil {
		slog.Error("Put bucket tagging lookup", "bucket", bucket, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	} else if !exists {
		writeS3Error(w, "NoSuchBucket", "The specified bucket does not exist.", r.URL.Path, http.StatusNotFound)
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

	err := WithTransaction(ctx, s.db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM bucket_tags WHERE bucket = ?`, bucket); err != nil {
			slog.Error("Delete existing bucket tags", "bucket", bucket, "err", err)
			writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
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
				writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
				return fmt.Errorf("error inserting tag `%s` %w", tag.Key, err)
			}
		}

		if _, err := tx.ExecContext(ctx, `UPDATE buckets SET modified_at = ? WHERE name = ?`, now, bucket); err != nil {
			slog.Error("Update bucket modified_at for tagging", "bucket", bucket, "err", err)
			writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
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
func (s *Server) handleGetBucketTagging(w http.ResponseWriter, r *http.Request, bucket string) {
	// Ensure bucket exists.
	if exists, err := s.bucketExists(r.Context(), bucket); err != nil {
		slog.Error("Get bucket tagging lookup", "bucket", bucket, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	} else if !exists {
		writeS3Error(w, "NoSuchBucket", "The specified bucket does not exist.", r.URL.Path, http.StatusNotFound)
		return
	}

	rows, err := s.db.QueryContext(r.Context(), `SELECT key, value FROM bucket_tags WHERE bucket = ? ORDER BY key`, bucket)
	if err != nil {
		slog.Error("Query bucket tags", "bucket", bucket, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	tagging := Tagging{XMLNS: s3XMLNamespace}
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
func (s *Server) handleDeleteBucketTagging(w http.ResponseWriter, r *http.Request, bucket string) {
	ctx := r.Context()
	// Ensure bucket exists.
	if exists, err := s.bucketExists(ctx, bucket); err != nil {
		slog.Error("Delete bucket tagging lookup", "bucket", bucket, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	} else if !exists {
		writeS3Error(w, "NoSuchBucket", "The specified bucket does not exist.", r.URL.Path, http.StatusNotFound)
		return
	}

	now := time.Now().UTC()

	if err := WithTransaction(ctx, s.db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM bucket_tags WHERE bucket = ?`, bucket); err != nil {
			slog.Error("Delete bucket tags", "bucket", bucket, "err", err)
			writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
			return fmt.Errorf("error deleting bucket tags %w", err)
		}

		if _, err := tx.ExecContext(ctx, `UPDATE buckets SET modified_at = ? WHERE name = ?`, now, bucket); err != nil {
			slog.Error("Update bucket modified_at for delete tagging", "bucket", bucket, "err", err)
			writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
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
func (s *Server) handleListBuckets(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.QueryContext(r.Context(), `SELECT name, created_at FROM buckets ORDER BY name`)
	if err != nil {
		slog.Error("List buckets", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	buckets := make([]ListAllMyBucketsEntry, 0)
	for rows.Next() {
		var b ListAllMyBucketsEntry
		if err := rows.Scan(&b.Name, &b.CreationDate); err != nil {
			slog.Error("Scan bucket", "err", err)
			continue
		}
		buckets = append(buckets, b)
	}

	resp := ListAllMyBucketsResult{
		XMLNS: s3XMLNamespace,
		Owner: ListAllMyBucketsOwner{
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
func (s *Server) handleCopyObject(w http.ResponseWriter, r *http.Request, destBucket string, destKey string, copySource string) {
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

	// Look up source object metadata.
	var (
		hashHex     string
		size        int64
		contentType sql.NullString
	)

	err = s.db.QueryRowContext(r.Context(),
		`SELECT hash, size, content_type FROM objects WHERE bucket = ? AND key = ?`,
		srcBucket, srcKey,
	).Scan(&hashHex, &size, &contentType)
	if errors.Is(err, sql.ErrNoRows) {
		writeS3Error(w, "NoSuchKey", "The specified key does not exist.", r.URL.Path, http.StatusNotFound)
		return
	}
	if err != nil {
		slog.Error("Lookup source object for copy", "srcBucket", srcBucket, "srcKey", srcKey, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	}

	// Ensure destination bucket exists; for convenience, auto-create if missing.
	if _, err := s.ensureBucket(r.Context(), destBucket); err != nil {
		slog.Error("Ensure dest bucket for copy", "bucket", destBucket, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	}

	// If copying across buckets, ask the storage engine to ensure the payload
	// exists in the destination bucket, avoiding unnecessary reads/writes.
	if srcBucket != destBucket {
		if err := s.cfg.Engine.CopyObject(srcBucket, hashHex, destBucket); err != nil {
			if os.IsNotExist(err) {
				http.Error(w, "object payload missing", http.StatusInternalServerError)
				return
			}
			slog.Error("Copy payload between buckets", "srcBucket", srcBucket, "destBucket", destBucket, "err", err)
			writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
			return
		}
	}

	parent := parentPrefixForKey(destKey)
	now := time.Now().UTC()

	var ct any
	if contentType.Valid {
		ct = contentType.String
	} else {
		ct = nil
	}

	_, err = s.db.ExecContext(r.Context(),
		`INSERT INTO objects(bucket, key, parent, hash, size, content_type, created_at, modified_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(bucket, key) DO UPDATE SET
		 	parent=excluded.parent,
		 	hash=excluded.hash,
		 	size=excluded.size,
		 	content_type=excluded.content_type,
		 	modified_at=excluded.modified_at`,
		destBucket, destKey, parent, hashHex, size, ct, now, now,
	)
	if err != nil {
		slog.Error("Upsert dest object metadata for copy", "destBucket", destBucket, "destKey", destKey, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	}

	resp := CopyObjectResult{
		XMLNS:        s3XMLNamespace,
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
func (s *Server) handleDeleteBucket(w http.ResponseWriter, r *http.Request, bucket string) {

	// Ensure bucket exists.
	if exists, err := s.bucketExists(r.Context(), bucket); err != nil {
		slog.Error("Delete bucket lookup", "bucket", bucket, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	} else if !exists {
		writeS3Error(w, "NoSuchBucket", "The specified bucket does not exist.", r.URL.Path, http.StatusNotFound)
		return
	}

	// Delete the bucket row; foreign-key cascade removes its objects.
	if _, err := s.db.ExecContext(r.Context(), `DELETE FROM buckets WHERE name = ?`, bucket); err != nil {
		slog.Error("Delete bucket metadata", "bucket", bucket, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	}

	// Remove on-disk contents for the bucket.
	if err := s.cfg.Engine.DeleteBucket(bucket); err != nil {
		slog.Error("Delete bucket storage", "bucket", bucket, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleListObjects implements a simplified version of S3 ListObjects (v2)
// for a single bucket: GET /bucket[?prefix=&max-keys=].
func (s *Server) handleListObjects(w http.ResponseWriter, r *http.Request, bucket string) {

	// Ensure bucket exists.
	if exists, err := s.bucketExists(r.Context(), bucket); err != nil {
		slog.Error("Check bucket exists", "bucket", bucket, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	} else if !exists {
		writeS3Error(w, "NoSuchBucket", "The specified bucket does not exist.", r.URL.Path, http.StatusNotFound)
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

	rows, err := s.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		slog.Error("List objects", "bucket", bucket, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
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

	resp := ListBucketResult{
		XMLNS:          s3XMLNamespace,
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
func (s *Server) handleListObjectsV2(w http.ResponseWriter, r *http.Request, bucket string) {

	// Ensure bucket exists.
	if exists, err := s.bucketExists(r.Context(), bucket); err != nil {
		slog.Error("Check bucket exists (v2)", "bucket", bucket, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	} else if !exists {
		writeS3Error(w, "NoSuchBucket", "The specified bucket does not exist.", r.URL.Path, http.StatusNotFound)
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

	rows, err := s.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		slog.Error("List objects v2", "bucket", bucket, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
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
		XMLNS:                 s3XMLNamespace,
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

package silo

import (
	"bufio"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var bucketNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*[a-z0-9]$`)

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

// NewServer initializes the metadata database and returns a new Server.
func NewServer(cfg Config) (*Server, error) {

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

	if err := initSchema(db); err != nil {
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

// initSchema initializes the metadata database schema.
func initSchema(db *sql.DB) error {
	stmts := []string{
		`PRAGMA foreign_keys = ON;`,
		`CREATE TABLE IF NOT EXISTS buckets (
			name TEXT PRIMARY KEY,
			created_at TIMESTAMP NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS objects (
			bucket TEXT NOT NULL,
			key TEXT NOT NULL,
			parent TEXT NOT NULL,
			hash TEXT NOT NULL,
			size INTEGER NOT NULL,
			content_type TEXT,
			created_at TIMESTAMP NOT NULL,
			PRIMARY KEY (bucket, key),
			FOREIGN KEY(bucket) REFERENCES buckets(name) ON DELETE CASCADE
		);`,
	}

	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("init schema: %w", err)
		}
	}

	// Create indexes used for lookups by content hash and for efficient
	// prefix-based listings (bucket + parent + key).
	indexStmts := []string{
		`CREATE INDEX IF NOT EXISTS idx_objects_hash ON objects(hash);`,
		`CREATE INDEX IF NOT EXISTS idx_objects_parent ON objects(bucket, parent, key);`,
	}

	for _, stmt := range indexStmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("init schema indexes: %w", err)
		}
	}
	return nil
}

// handleBucketPut dispatches PUT /bucket[?subresource] between CreateBucket
// and various bucket configuration APIs.
func (s *Server) handleBucketPut(w http.ResponseWriter, r *http.Request, bucket string) {
	if !validateBucketNameOrError(w, r, bucket) {
		return
	}

	q := r.URL.Query()
	switch {
	case q.Has("tagging"):
		s.writeNotImplemented(w, r, "PutBucketTagging")
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

// ensureBucket makes sure the given bucket exists, creating it if necessary.
func (s *Server) ensureBucket(name string) (sql.Result, error) {
	res, err := s.db.Exec(
		`INSERT OR IGNORE INTO buckets(name, created_at) VALUES(?, ?)`,
		name, time.Now().UTC(),
	)
	return res, err
}

// handleCreateBucket implements PUT /bucket to create a new bucket.
func (s *Server) handleCreateBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	if !validateBucketNameOrError(w, r, bucket) {
		return
	}

	res, err := s.ensureBucket(bucket)
	if err != nil {
		slog.Error("Create bucket", "bucket", bucket, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	}

	rows, err := res.RowsAffected()
	if err == nil && rows == 0 {
		// Bucket already existed; S3 returns 409 BucketAlreadyOwnedByYou.
		writeS3Error(w, "BucketAlreadyOwnedByYou", "Your previous request to create the named bucket succeeded and you already own it.", r.URL.Path, http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusOK)
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
		s.writeNotImplemented(w, r, "GetBucketTagging")
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

// handleGetBucketLocation implements GET /bucket?location
func (s *Server) handleGetBucketLocation(w http.ResponseWriter, r *http.Request, bucket string) {
	// Ensure bucket exists.
	var bucketName string
	err := s.db.QueryRow(`SELECT name FROM buckets WHERE name = ?`, bucket).Scan(&bucketName)
	if errors.Is(err, sql.ErrNoRows) {
		writeS3Error(w, "NoSuchBucket", "The specified bucket does not exist.", r.URL.Path, http.StatusNotFound)
		return
	}

	if err != nil {
		slog.Error("Get bucket location", "bucket", bucket, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
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

// handleListBuckets implements GET / to list all buckets.
func (s *Server) handleListBuckets(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(`SELECT name, created_at FROM buckets ORDER BY name`)
	if err != nil {
		slog.Error("List buckets", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var buckets []struct {
		Name      string
		CreatedAt time.Time
	}
	for rows.Next() {
		var b struct {
			Name      string
			CreatedAt time.Time
		}
		if err := rows.Scan(&b.Name, &b.CreatedAt); err != nil {
			slog.Error("Scan bucket", "err", err)
			continue
		}
		buckets = append(buckets, b)
	}

	resp := ListAllMyBucketsResult{
		XMLNS: s3XMLNamespace,
	}
	resp.Owner.ID = "silo"
	resp.Owner.DisplayName = "silo"
	for _, b := range buckets {
		resp.Buckets = append(resp.Buckets, struct {
			Name         string `xml:"Name"`
			CreationDate string `xml:"CreationDate"`
		}{
			Name:         b.Name,
			CreationDate: b.CreatedAt.UTC().Format(time.RFC3339),
		})
	}

	if err := writeXMLResponse(w, resp); err != nil {
		slog.Error("Encode list buckets XML", "err", err)
	}
}

// handlePutObject implements PUT /bucket/key to store an object.
func (s *Server) handlePutObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
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
		s.writeNotImplemented(w, r, "PutObjectTagging")
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
	if _, err := s.ensureBucket(bucket); err != nil {
		slog.Error("Ensure bucket", "bucket", bucket, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	}

	var (
		data []byte
		err  error
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

		data, err = readStreamingV4Payload(r.Body, decodedLen)
		if err != nil {
			slog.Error("Decode streaming payload", "err", err)
			writeS3Error(w, "InvalidRequest", "Failed to decode streaming payload", r.URL.Path, http.StatusBadRequest)
			return
		}
	} else {
		data, err = io.ReadAll(r.Body)
		if err != nil {
			slog.Error("Read request body", "err", err)
			writeS3Error(w, "InvalidRequest", "Failed to read request body", r.URL.Path, http.StatusBadRequest)
			return
		}
	}
	defer r.Body.Close()

	sum := sha256.Sum256(data)
	hashHex := hex.EncodeToString(sum[:])
	if err := s.cfg.Engine.PutObject(bucket, hashHex, data); err != nil {
		slog.Error("Store object payload", "bucket", bucket, "key", key, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	}

	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	parent := parentPrefixForKey(key)

	_, err = s.db.Exec(
		`INSERT INTO objects(bucket, key, parent, hash, size, content_type, created_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(bucket, key) DO UPDATE SET
		 	parent=excluded.parent,
		 	hash=excluded.hash,
		 	size=excluded.size,
		 	content_type=excluded.content_type,
		 	created_at=excluded.created_at`,
		bucket, key, parent, hashHex, len(data), contentType, time.Now().UTC(),
	)
	if err != nil {
		slog.Error("Upsert object metadata", "bucket", bucket, "key", key, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	}

	w.Header().Set("ETag", createETag(hashHex))
	w.WriteHeader(http.StatusOK)
}

// readStreamingV4Payload decodes an AWS Signature Version 4 streaming
// (chunked) payload into a contiguous byte slice. The decodedLen parameter
// should be taken from the X-Amz-Decoded-Content-Length header.
func readStreamingV4Payload(body io.Reader, decodedLen int64) ([]byte, error) {
	br := bufio.NewReader(body)
	buf := make([]byte, 0, decodedLen)

	for {
		// Each chunk begins with: <size-hex>[;extensions]\r\n
		line, err := br.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, fmt.Errorf("unexpected EOF while reading chunk header")
			}
			return nil, fmt.Errorf("read chunk header: %w", err)
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
			return nil, fmt.Errorf("parse chunk size %q: %w", sizeHex, err)
		}

		if size == 0 {
			// Final chunk. Per AWS streaming format, this is followed by a
			// trailing CRLF and optional trailers. For our purposes we can
			// consume a single empty line and stop.
			_, _ = br.ReadString('\n') // best-effort consume trailer terminator
			break
		}

		chunk := make([]byte, size)
		if _, err := io.ReadFull(br, chunk); err != nil {
			return nil, fmt.Errorf("read chunk body: %w", err)
		}
		buf = append(buf, chunk...)

		// Consume the trailing CRLF after the chunk body.
		if b, err := br.ReadByte(); err != nil || b != '\r' {
			if err == nil {
				return nil, fmt.Errorf("expected CR after chunk, got %q", b)
			}
			return nil, fmt.Errorf("read CR after chunk: %w", err)
		}
		if b, err := br.ReadByte(); err != nil || b != '\n' {
			if err == nil {
				return nil, fmt.Errorf("expected LF after chunk, got %q", b)
			}
			return nil, fmt.Errorf("read LF after chunk: %w", err)
		}
	}

	// If decodedLen was provided, use it as a sanity check but do not
	// fail hard if it does not match exactly – some clients may omit or
	// mis-report it. The storage layer relies on the actual length we
	// decoded.
	if decodedLen >= 0 && int64(len(buf)) != decodedLen {
		slog.Debug("Decoded streaming payload length mismatch", "expected", decodedLen, "actual", len(buf))
	}

	return buf, nil
}

// handleGetObject implements GET /bucket/key to retrieve an object.
func (s *Server) handleGetObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	if !validateBucketNameOrError(w, r, bucket) {
		return
	}
	if !validateObjectKeyOrError(w, r, key) {
		return
	}

	q := r.URL.Query()
	switch {
	case q.Has("tagging"):
		s.writeNotImplemented(w, r, "GetObjectTagging")
		return
	case q.Has("attributes"):
		s.writeNotImplemented(w, r, "GetObjectAttributes")
		return
	case q.Has("uploadId"):
		s.writeNotImplemented(w, r, "ListParts")
		return
	}

	var (
		hashHex     string
		size        int64
		contentType sql.NullString
		createdAt   time.Time
	)

	err := s.db.QueryRow(
		`SELECT hash, size, content_type, created_at FROM objects WHERE bucket = ? AND key = ?`,
		bucket, key,
	).Scan(&hashHex, &size, &contentType, &createdAt)

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

	if contentType.Valid {
		w.Header().Set("Content-Type", contentType.String)
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	if size >= 0 {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
	}
	w.Header().Set("Last-Modified", createdAt.UTC().Format(http.TimeFormat))
	w.Header().Set("ETag", createETag(hashHex))
	w.Header().Set("Accept-Ranges", "bytes")

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(data); err != nil {
		slog.Error("Stream object", "bucket", bucket, "key", key, "err", err)
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

	err = s.db.QueryRow(
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
	if _, err := s.ensureBucket(destBucket); err != nil {
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
	createdAt := time.Now().UTC()

	var ct any
	if contentType.Valid {
		ct = contentType.String
	} else {
		ct = nil
	}

	_, err = s.db.Exec(
		`INSERT INTO objects(bucket, key, parent, hash, size, content_type, created_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(bucket, key) DO UPDATE SET
		 	parent=excluded.parent,
		 	hash=excluded.hash,
		 	size=excluded.size,
		 	content_type=excluded.content_type,
		 	created_at=excluded.created_at`,
		destBucket, destKey, parent, hashHex, size, ct, createdAt,
	)
	if err != nil {
		slog.Error("Upsert dest object metadata for copy", "destBucket", destBucket, "destKey", destKey, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	}

	resp := CopyObjectResult{
		XMLNS:        s3XMLNamespace,
		LastModified: createdAt.UTC().Format(time.RFC3339),
		ETag:         createETag(hashHex),
	}

	if err := writeXMLResponse(w, resp); err != nil {
		slog.Error("Encode copy object XML", "destBucket", destBucket, "destKey", destKey, "err", err)
	}
}

// handleDeleteObject implements DELETE /bucket/key to delete an object.
func (s *Server) handleDeleteObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	if !validateBucketNameOrError(w, r, bucket) {
		return
	}
	if !validateObjectKeyOrError(w, r, key) {
		return
	}

	q := r.URL.Query()
	switch {
	case q.Has("tagging"):
		s.writeNotImplemented(w, r, "DeleteObjectTagging")
		return
	case q.Has("uploadId"):
		s.writeNotImplemented(w, r, "AbortMultipartUpload")
		return
	}

	_, err := s.db.Exec(`DELETE FROM objects WHERE bucket = ? AND key = ?`, bucket, key)
	if err != nil {
		slog.Error("Delete object metadata", "bucket", bucket, "key", key, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	}

	// Note: we intentionally do not garbage-collect unreferenced payload
	// files yet. That can be added later based on hash reference counts.
	w.WriteHeader(http.StatusNoContent)
}

// handleHeadBucket implements HEAD /bucket.
func (s *Server) handleHeadBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	if !validateBucketNameOrError(w, r, bucket) {
		return
	}

	// Check whether the bucket exists.
	var bucketName string
	err := s.db.QueryRow(`SELECT name FROM buckets WHERE name = ?`, bucket).Scan(&bucketName)
	if errors.Is(err, sql.ErrNoRows) {
		writeS3Error(w, "NoSuchBucket", "The specified bucket does not exist.", r.URL.Path, http.StatusNotFound)
		return
	}
	if err != nil {
		slog.Error("Head bucket", "bucket", bucket, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	}

	// S3-compatible HEAD bucket: 200 with no body.
	w.WriteHeader(http.StatusOK)
}

// handleHeadObject implements HEAD /bucket/key, returning metadata headers
// compatible with S3 but without a response body.
func (s *Server) handleHeadObject(w http.ResponseWriter, r *http.Request, bucket string, key string) {
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
		createdAt   time.Time
	)

	err := s.db.QueryRow(
		`SELECT hash, size, content_type, created_at FROM objects WHERE bucket = ? AND key = ?`,
		bucket, key,
	).Scan(&hashHex, &size, &contentType, &createdAt)
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
	w.Header().Set("Last-Modified", createdAt.UTC().Format(http.TimeFormat))
	w.Header().Set("ETag", createETag(hashHex))
	w.Header().Set("Accept-Ranges", "bytes")

	w.WriteHeader(http.StatusOK)
}

// handleBucketDelete implements DELETE /bucket[?subresource].
func (s *Server) handleBucketDelete(w http.ResponseWriter, r *http.Request, bucket string) {
	if !validateBucketNameOrError(w, r, bucket) {
		return
	}

	q := r.URL.Query()
	switch {
	case q.Has("tagging"):
		s.writeNotImplemented(w, r, "DeleteBucketTagging")
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
		s.writeNotImplemented(w, r, "DeleteBucket")
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

// handleListObjects implements a simplified version of S3 ListObjects (v2)
// for a single bucket: GET /bucket[?prefix=&max-keys=].
func (s *Server) handleListObjects(w http.ResponseWriter, r *http.Request, bucket string) {
	if !validateBucketNameOrError(w, r, bucket) {
		return
	}

	// Ensure bucket exists.
	var bucketName string
	err := s.db.QueryRow(`SELECT name FROM buckets WHERE name = ?`, bucket).Scan(&bucketName)
	if errors.Is(err, sql.ErrNoRows) {
		writeS3Error(w, "NoSuchBucket", "The specified bucket does not exist.", r.URL.Path, http.StatusNotFound)
		return
	}
	if err != nil {
		slog.Error("Check bucket exists", "bucket", bucket, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	}

	q := r.URL.Query()
	prefix := q.Get("prefix")
	maxKeys := 1000
	if raw := q.Get("max-keys"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			maxKeys = v
		}
	}

	// Fetch up to maxKeys+1 to determine truncation.
	args := []any{bucket}
	query := `SELECT key, hash, size, created_at FROM objects WHERE bucket = ?`
	if prefix != "" {
		query += " AND key LIKE ?"
		args = append(args, prefix+"%")
	}
	query += " ORDER BY key LIMIT ?"
	args = append(args, maxKeys+1)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		slog.Error("List objects", "bucket", bucket, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var summaries []ObjectSummary
	for rows.Next() {
		var (
			key       string
			hashHex   string
			size      int64
			createdAt time.Time
		)
		if err := rows.Scan(&key, &hashHex, &size, &createdAt); err != nil {
			slog.Error("Scan object", "bucket", bucket, "err", err)
			continue
		}
		summaries = append(summaries, ObjectSummary{
			Key:          key,
			LastModified: createdAt.UTC().Format(time.RFC3339),
			ETag:         createETag(hashHex),
			Size:         size,
			StorageClass: "STANDARD",
		})
	}

	isTruncated := false
	if len(summaries) > maxKeys {
		isTruncated = true
		summaries = summaries[:maxKeys]
	}

	resp := ListBucketResult{
		XMLNS:       s3XMLNamespace,
		Name:        bucket,
		Prefix:      prefix,
		MaxKeys:     maxKeys,
		IsTruncated: isTruncated,
		Contents:    summaries,
	}

	if err := writeXMLResponse(w, resp); err != nil {
		slog.Error("Encode list objects XML", "bucket", bucket, "err", err)
	}
}

// handleListObjectsV2 implements S3 ListObjectsV2:
// GET /bucket?list-type=2[&prefix=&max-keys=&continuation-token=&start-after=].
func (s *Server) handleListObjectsV2(w http.ResponseWriter, r *http.Request, bucket string) {
	if !validateBucketNameOrError(w, r, bucket) {
		return
	}

	// Ensure bucket exists.
	// TODO(eteran): likely unnecessary...
	var bucketName string
	err := s.db.QueryRow(`SELECT name FROM buckets WHERE name = ?`, bucket).Scan(&bucketName)
	if errors.Is(err, sql.ErrNoRows) {
		writeS3Error(w, "NoSuchBucket", "The specified bucket does not exist.", r.URL.Path, http.StatusNotFound)
		return
	}
	if err != nil {
		slog.Error("Check bucket exists (v2)", "bucket", bucket, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	}

	q := r.URL.Query()
	prefix := q.Get("prefix")
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

	// Fetch up to maxKeys+1 to determine truncation.
	args := []any{bucket}
	query := `SELECT key, hash, size, created_at FROM objects WHERE bucket = ?`
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

	rows, err := s.db.Query(query, args...)
	if err != nil {
		slog.Error("List objects v2", "bucket", bucket, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var summaries []ObjectSummary
	for rows.Next() {
		var (
			key       string
			hashHex   string
			size      int64
			createdAt time.Time
		)
		if err := rows.Scan(&key, &hashHex, &size, &createdAt); err != nil {
			slog.Error("Scan object (v2)", "bucket", bucket, "err", err)
			continue
		}
		summaries = append(summaries, ObjectSummary{
			Key:          key,
			LastModified: createdAt.UTC().Format(time.RFC3339),
			ETag:         createETag(hashHex),
			Size:         size,
			StorageClass: "STANDARD",
		})
	}

	isTruncated := false
	if len(summaries) > maxKeys {
		isTruncated = true
		summaries = summaries[:maxKeys]
	}

	keyCount := len(summaries)
	nextContinuationToken := ""
	if isTruncated && keyCount > 0 {
		nextContinuationToken = summaries[keyCount-1].Key
	}

	resp := ListBucketResultV2{
		XMLNS:                 s3XMLNamespace,
		Name:                  bucket,
		Prefix:                prefix,
		KeyCount:              keyCount,
		MaxKeys:               maxKeys,
		IsTruncated:           isTruncated,
		ContinuationToken:     continuationToken,
		NextContinuationToken: nextContinuationToken,
		StartAfter:            startAfter,
		Contents:              summaries,
	}

	if err := writeXMLResponse(w, resp); err != nil {
		slog.Error("Encode list objects v2 XML", "bucket", bucket, "err", err)
	}
}

// handleObjectPost implements POST /bucket/key[?subresource] operations such
// as CompleteMultipartUpload, RestoreObject, and SelectObjectContent.
func (s *Server) handleObjectPost(w http.ResponseWriter, r *http.Request, bucket, key string) {
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

// writeNotImplemented is a helper for stubbing unsupported S3 operations.
func (s *Server) writeNotImplemented(w http.ResponseWriter, r *http.Request, op string) {
	message := fmt.Sprintf("%s is not implemented.", op)
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
	if ip != nil {
		return false
	}

	return true
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
	if err := xml.NewEncoder(w).Encode(v); err != nil {
		return err
	}

	return nil
}

// createETag formats a hash hex string as an ETag value.
func createETag(hashHex string) string {
	return fmt.Sprintf("\"%s\"", hashHex)
}

package silo

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const s3XMLNamespace = "http://s3.amazonaws.com/doc/2006-03-01/"

// ListAllMyBucketsResult represents the XML response for the S3 ListBuckets API.
type ListAllMyBucketsResult struct {
	XMLName xml.Name `xml:"ListAllMyBucketsResult"`
	XMLNS   string   `xml:"xmlns,attr"`
	Owner   struct {
		ID          string `xml:"ID"`
		DisplayName string `xml:"DisplayName"`
	} `xml:"Owner"`
	Buckets []struct {
		Name         string `xml:"Name"`
		CreationDate string `xml:"CreationDate"`
	} `xml:"Buckets>Bucket"`
}

// ListBucketResult represents the XML response for the S3 ListObjects API.
type ListBucketResult struct {
	XMLName     xml.Name        `xml:"ListBucketResult"`
	XMLNS       string          `xml:"xmlns,attr"`
	Name        string          `xml:"Name"`
	Prefix      string          `xml:"Prefix"`
	MaxKeys     int             `xml:"MaxKeys"`
	IsTruncated bool            `xml:"IsTruncated"`
	Contents    []ObjectSummary `xml:"Contents"`
}

// ObjectSummary is a single entry in a ListBucketResult.
type ObjectSummary struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
}

// Config holds configuration for the local S3-compatible server.
type Config struct {
	// DataDir is the root directory where object payloads are stored.
	DataDir string
	// DBPath is the path to the SQLite metadata database.
	DBPath string
}

// Server provides a minimal S3-compatible HTTP API backed by the local
// filesystem for object storage and SQLite for metadata.
//
// This is intentionally small and incomplete but structured so additional
// S3/MinIO-compatible operations can be added over time.
type Server struct {
	cfg Config
	db  *sql.DB
}

// NewServer initializes the metadata database and returns a new Server.
func NewServer(cfg Config) (*Server, error) {
	if cfg.DataDir == "" {
		return nil, errors.New("DataDir must not be empty")
	}
	if cfg.DBPath == "" {
		return nil, errors.New("DBPath must not be empty")
	}

	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	db, err := sql.Open("sqlite3", cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	if err := initSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}

	return &Server{cfg: cfg, db: db}, nil
}

// Handler returns an http.Handler implementing a subset of the S3/MinIO API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Catch-all handler; we parse bucket/key from the path.
	mux.HandleFunc("/", s.handleRoot)
	return mux
}

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
			hash TEXT NOT NULL,
			size INTEGER NOT NULL,
			content_type TEXT,
			created_at TIMESTAMP NOT NULL,
			PRIMARY KEY (bucket, key),
			FOREIGN KEY(bucket) REFERENCES buckets(name) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_objects_hash ON objects(hash);`,
	}

	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("init schema: %w", err)
		}
	}
	return nil
}

// handleRoot dispatches based on HTTP method and parsed bucket/key.
// This is a deliberately small subset intended as a starting point and is
// not a fully S3-compatible implementation yet.
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	bucket, key := parseBucketAndKey(r.URL.Path)

	switch r.Method {
	case http.MethodPut:
		if key == "" && bucket != "" {
			// PUT /bucket -> create bucket
			s.handleCreateBucket(w, r, bucket)
			return
		}
		if bucket != "" && key != "" {
			// PUT /bucket/object -> put object
			s.handlePutObject(w, r, bucket, key)
			return
		}
	case http.MethodGet:
		if bucket == "" {
			// GET / -> list buckets
			s.handleListBuckets(w, r)
			return
		}
		if bucket != "" && key == "" {
			// GET /bucket -> list objects in bucket
			s.handleListObjects(w, r, bucket)
			return
		}
		if bucket != "" && key != "" {
			// GET /bucket/object -> get object
			s.handleGetObject(w, r, bucket, key)
			return
		}
	case http.MethodHead:
		if bucket != "" && key != "" {
			// HEAD /bucket/object -> get object metadata
			s.handleHeadObject(w, r, bucket, key)
			return
		}
	case http.MethodDelete:
		if bucket != "" && key != "" {
			// DELETE /bucket/object -> delete object
			s.handleDeleteObject(w, r, bucket, key)
			return
		}
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusNotImplemented)
	_, _ = w.Write([]byte("not implemented\n"))
}

func parseBucketAndKey(path string) (bucket, key string) {
	// Trim leading/trailing slashes and split.
	clean := strings.Trim(path, "/")
	if clean == "" {
		return "", ""
	}
	parts := strings.Split(clean, "/")
	bucket = parts[0]
	if len(parts) > 1 {
		key = strings.Join(parts[1:], "/")
	}
	return bucket, key
}

func (s *Server) handleCreateBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	if bucket == "" {
		writeS3Error(w, "InvalidBucketName", "Bucket name must not be empty", r.URL.Path, http.StatusBadRequest)
		return
	}

	res, err := s.db.Exec(
		`INSERT OR IGNORE INTO buckets(name, created_at) VALUES(?, ?)`,
		bucket, time.Now().UTC(),
	)
	if err != nil {
		slog.Error("create bucket", "bucket", bucket, "err", err)
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

func (s *Server) handleListBuckets(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(`SELECT name, created_at FROM buckets ORDER BY name`)
	if err != nil {
		slog.Error("list buckets", "err", err)
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
			slog.Error("scan bucket", "err", err)
			continue
		}
		buckets = append(buckets, b)
	}

	resp := ListAllMyBucketsResult{
		XMLNS: s3XMLNamespace,
	}
	resp.Owner.ID = "local-s3"
	resp.Owner.DisplayName = "local-s3"
	for _, b := range buckets {
		resp.Buckets = append(resp.Buckets, struct {
			Name         string `xml:"Name"`
			CreationDate string `xml:"CreationDate"`
		}{
			Name:         b.Name,
			CreationDate: b.CreatedAt.UTC().Format(time.RFC3339),
		})
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	if err := xml.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("encode list buckets xml", "err", err)
	}
}

func (s *Server) handlePutObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	if bucket == "" || key == "" {
		writeS3Error(w, "InvalidRequest", "Bucket and key must not be empty", r.URL.Path, http.StatusBadRequest)
		return
	}

	// Ensure bucket exists; for convenience, auto-create if missing.
	if err := s.ensureBucket(bucket); err != nil {
		slog.Error("ensure bucket", "bucket", bucket, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	}

	data, err := io.ReadAll(r.Body)
	if err != nil {
		slog.Error("read request body", "err", err)
		writeS3Error(w, "InvalidRequest", "Failed to read request body", r.URL.Path, http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	sum := sha256.Sum256(data)
	hashHex := hex.EncodeToString(sum[:])
	subdir := hashHex[:2]
	storeDir := filepath.Join(s.cfg.DataDir, subdir)
	if err := os.MkdirAll(storeDir, 0o755); err != nil {
		slog.Error("create object dir", "dir", storeDir, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	}

	objPath := filepath.Join(storeDir, hashHex)
	if err := os.WriteFile(objPath, data, 0o644); err != nil {
		slog.Error("write object file", "path", objPath, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	}

	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	_, err = s.db.Exec(
		`INSERT INTO objects(bucket, key, hash, size, content_type, created_at)
		 VALUES(?, ?, ?, ?, ?, ?)
		 ON CONFLICT(bucket, key) DO UPDATE SET
		 	hash=excluded.hash,
		 	size=excluded.size,
		 	content_type=excluded.content_type,
		 	created_at=excluded.created_at`,
		bucket, key, hashHex, len(data), contentType, time.Now().UTC(),
	)
	if err != nil {
		slog.Error("upsert object metadata", "bucket", bucket, "key", key, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	}

	w.Header().Set("ETag", fmt.Sprintf("\"%s\"", hashHex))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleGetObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
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
		slog.Error("lookup object metadata", "bucket", bucket, "key", key, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	}

	subdir := hashHex[:2]
	objPath := filepath.Join(s.cfg.DataDir, subdir, hashHex)
	f, err := os.Open(objPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "object payload missing", http.StatusInternalServerError)
			return
		}
		slog.Error("open object file", "path", objPath, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	}
	defer f.Close()

	if contentType.Valid {
		w.Header().Set("Content-Type", contentType.String)
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	if size >= 0 {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
	}
	w.Header().Set("Last-Modified", createdAt.UTC().Format(http.TimeFormat))
	w.Header().Set("ETag", fmt.Sprintf("\"%s\"", hashHex))
	w.Header().Set("Accept-Ranges", "bytes")

	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, f); err != nil {
		slog.Error("stream object", "bucket", bucket, "key", key, "err", err)
	}
}

func (s *Server) handleDeleteObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	_, err := s.db.Exec(`DELETE FROM objects WHERE bucket = ? AND key = ?`, bucket, key)
	if err != nil {
		slog.Error("delete object metadata", "bucket", bucket, "key", key, "err", err)
		writeS3Error(w, "InternalError", "We encountered an internal error. Please try again.", r.URL.Path, http.StatusInternalServerError)
		return
	}

	// Note: we intentionally do not garbage-collect unreferenced payload
	// files yet. That can be added later based on hash reference counts.
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) ensureBucket(name string) error {
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO buckets(name, created_at) VALUES(?, ?)`,
		name, time.Now().UTC(),
	)
	return err
}

// handleHeadObject implements HEAD /bucket/key, returning metadata headers
// compatible with S3 but without a response body.
func (s *Server) handleHeadObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
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
		slog.Error("lookup object metadata (HEAD)", "bucket", bucket, "key", key, "err", err)
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
	w.Header().Set("ETag", fmt.Sprintf("\"%s\"", hashHex))
	w.Header().Set("Accept-Ranges", "bytes")

	w.WriteHeader(http.StatusOK)
}

// handleListObjects implements a simplified version of S3 ListObjects (v2)
// for a single bucket: GET /bucket[?prefix=&max-keys=].
func (s *Server) handleListObjects(w http.ResponseWriter, r *http.Request, bucket string) {
	if bucket == "" {
		writeS3Error(w, "NoSuchBucket", "The specified bucket does not exist.", r.URL.Path, http.StatusNotFound)
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
		slog.Error("check bucket exists", "bucket", bucket, "err", err)
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
		slog.Error("list objects", "bucket", bucket, "err", err)
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
			slog.Error("scan object", "bucket", bucket, "err", err)
			continue
		}
		summaries = append(summaries, ObjectSummary{
			Key:          key,
			LastModified: createdAt.UTC().Format(time.RFC3339),
			ETag:         fmt.Sprintf("\"%s\"", hashHex),
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

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	if err := xml.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("encode list objects xml", "bucket", bucket, "err", err)
	}
}

// writeS3Error writes a minimal S3-style XML error response.
func writeS3Error(w http.ResponseWriter, code, message, resource string, status int) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	type s3Error struct {
		XMLName  xml.Name `xml:"Error"`
		Code     string   `xml:"Code"`
		Message  string   `xml:"Message"`
		Resource string   `xml:"Resource"`
	}
	_ = xml.NewEncoder(w).Encode(s3Error{
		Code:     code,
		Message:  message,
		Resource: resource,
	})
}

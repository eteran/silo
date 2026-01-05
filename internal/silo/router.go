package silo

import (
	"log/slog"
	"net/http"
	"time"
)

// logRequest is middleware that logs incoming HTTP requests.
func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		method := r.Method
		url := r.URL.String()
		proto := r.Proto

		start := time.Now()
		next.ServeHTTP(w, r)
		elapsed := time.Since(start).Nanoseconds()

		userAttrs := slog.Group("user", "ip", ip)
		requestAttrs := slog.Group("request", "method", method, "url", url, "proto", proto, "duration_ms", float64(elapsed)/float64(time.Millisecond))
		slog.Info("Request", userAttrs, requestAttrs)

	})
}

// requireAuthentication is middleware that enforces authentication for S3 API requests.
func requireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO(eteran): Implement authentication check.
		next.ServeHTTP(w, r)
	})
}

// Handler returns an http.Handler implementing the S3/MinIO API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// List all buckets
	mux.HandleFunc("GET /", s.handleListBuckets)

	// Bucket-level operations
	mux.HandleFunc("PUT /{bucket}", func(w http.ResponseWriter, r *http.Request) {
		bucket := r.PathValue("bucket")
		s.handleBucketPut(w, r, bucket)
	})
	mux.HandleFunc("GET /{bucket}", func(w http.ResponseWriter, r *http.Request) {
		bucket := r.PathValue("bucket")
		s.handleBucketGet(w, r, bucket)
	})
	mux.HandleFunc("HEAD /{bucket}", func(w http.ResponseWriter, r *http.Request) {
		bucket := r.PathValue("bucket")
		s.handleHeadBucket(w, r, bucket)
	})
	mux.HandleFunc("DELETE /{bucket}", func(w http.ResponseWriter, r *http.Request) {
		bucket := r.PathValue("bucket")
		s.handleBucketDelete(w, r, bucket)
	})
	mux.HandleFunc("POST /{bucket}", func(w http.ResponseWriter, r *http.Request) {
		bucket := r.PathValue("bucket")
		s.handleBucketPost(w, r, bucket)
	})

	// Object-level operations
	mux.HandleFunc("PUT /{bucket}/{key...}", func(w http.ResponseWriter, r *http.Request) {
		bucket := r.PathValue("bucket")
		key := r.PathValue("key")
		s.handlePutObject(w, r, bucket, key)
	})
	mux.HandleFunc("GET /{bucket}/{key...}", func(w http.ResponseWriter, r *http.Request) {
		bucket := r.PathValue("bucket")
		key := r.PathValue("key")
		s.handleGetObject(w, r, bucket, key)
	})
	mux.HandleFunc("HEAD /{bucket}/{key...}", func(w http.ResponseWriter, r *http.Request) {
		bucket := r.PathValue("bucket")
		key := r.PathValue("key")
		s.handleHeadObject(w, r, bucket, key)
	})
	mux.HandleFunc("DELETE /{bucket}/{key...}", func(w http.ResponseWriter, r *http.Request) {
		bucket := r.PathValue("bucket")
		key := r.PathValue("key")
		s.handleDeleteObject(w, r, bucket, key)
	})
	mux.HandleFunc("POST /{bucket}/{key...}", func(w http.ResponseWriter, r *http.Request) {
		bucket := r.PathValue("bucket")
		key := r.PathValue("key")
		s.handleObjectPost(w, r, bucket, key)
	})

	return logRequest(requireAuthentication(mux))
}

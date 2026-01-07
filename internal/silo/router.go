package silo

import (
	"net/http"
)

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
		s.handleBucketHead(w, r, bucket)
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
		s.handleObjectPut(w, r, bucket, key)
	})
	mux.HandleFunc("GET /{bucket}/{key...}", func(w http.ResponseWriter, r *http.Request) {
		bucket := r.PathValue("bucket")
		key := r.PathValue("key")
		s.handleObjectGet(w, r, bucket, key)
	})
	mux.HandleFunc("HEAD /{bucket}/{key...}", func(w http.ResponseWriter, r *http.Request) {
		bucket := r.PathValue("bucket")
		key := r.PathValue("key")
		s.handleObjectHead(w, r, bucket, key)
	})
	mux.HandleFunc("DELETE /{bucket}/{key...}", func(w http.ResponseWriter, r *http.Request) {
		bucket := r.PathValue("bucket")
		key := r.PathValue("key")
		s.handleObjectDelete(w, r, bucket, key)
	})
	mux.HandleFunc("POST /{bucket}/{key...}", func(w http.ResponseWriter, r *http.Request) {
		bucket := r.PathValue("bucket")
		key := r.PathValue("key")
		s.handleObjectPost(w, r, bucket, key)
	})

	// Add middleware
	handler := SlashFix(mux)
	handler = LogRequest(handler)
	handler = RequireAuthentication(handler)
	handler = Recoverer(handler)
	return handler
}

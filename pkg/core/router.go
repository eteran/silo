package core

import (
	"net/http"
)

// Handler returns an http.Handler implementing the S3/MinIO API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// List all buckets
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		s.handleRootGet(ctx, w, r)
	})
	mux.HandleFunc("POST /{$}", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		s.handleRootPost(ctx, w, r)
	})

	// Bucket-level operations
	mux.HandleFunc("PUT /{bucket}", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		bucket := r.PathValue("bucket")
		s.handleBucketPut(ctx, w, r, bucket)
	})
	mux.HandleFunc("GET /{bucket}", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		bucket := r.PathValue("bucket")
		s.handleBucketGet(ctx, w, r, bucket)
	})
	mux.HandleFunc("HEAD /{bucket}", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		bucket := r.PathValue("bucket")
		s.handleBucketHead(ctx, w, r, bucket)
	})
	mux.HandleFunc("DELETE /{bucket}", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		bucket := r.PathValue("bucket")
		s.handleBucketDelete(ctx, w, r, bucket)
	})
	mux.HandleFunc("POST /{bucket}", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		bucket := r.PathValue("bucket")
		s.handleBucketPost(ctx, w, r, bucket)
	})

	// Object-level operations
	mux.HandleFunc("PUT /{bucket}/{key...}", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		bucket := r.PathValue("bucket")
		key := r.PathValue("key")
		s.handleObjectPut(ctx, w, r, bucket, key)
	})
	mux.HandleFunc("GET /{bucket}/{key...}", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		bucket := r.PathValue("bucket")
		key := r.PathValue("key")
		s.handleObjectGet(ctx, w, r, bucket, key)
	})
	mux.HandleFunc("HEAD /{bucket}/{key...}", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		bucket := r.PathValue("bucket")
		key := r.PathValue("key")
		s.handleObjectHead(ctx, w, r, bucket, key)
	})
	mux.HandleFunc("DELETE /{bucket}/{key...}", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		bucket := r.PathValue("bucket")
		key := r.PathValue("key")
		s.handleObjectDelete(ctx, w, r, bucket, key)
	})
	mux.HandleFunc("POST /{bucket}/{key...}", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		bucket := r.PathValue("bucket")
		key := r.PathValue("key")
		s.handleObjectPost(ctx, w, r, bucket, key)
	})

	// Add middleware
	handler := s.SlashFix(mux)
	handler = s.LogRequest(handler)
	handler = s.RequireAuthentication(handler)
	handler = s.Recoverer(handler)
	return handler
}

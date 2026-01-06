package silo

import (
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// ResponseWriterWrapper is a wrapper around the default http.ResponseWriter.
// It intercepts the WriteHeader call and saves the response status code.
type ResponseWriterWrapper struct {
	http.ResponseWriter
	WrittenResponseCode int
}

// WriteHeader intercepts the status code and stores it, then calls the original WriteHeader.
func (w *ResponseWriterWrapper) WriteHeader(statusCode int) {
	w.WrittenResponseCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// Write calls the underlying ResponseWriter's Write method.
func (w *ResponseWriterWrapper) Write(b []byte) (int, error) {
	if w.WrittenResponseCode == 0 {
		w.WrittenResponseCode = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// LogRequest is middleware that logs incoming HTTP requests.
func LogRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ip := r.RemoteAddr
		method := r.Method
		url := r.URL.String()
		proto := r.Proto

		start := time.Now()

		writer := ResponseWriterWrapper{ResponseWriter: w}

		next.ServeHTTP(&writer, r)
		elapsed := time.Since(start).Nanoseconds()

		userAttrs := slog.Group("user", "ip", ip)
		requestAttrs := slog.Group("request", "proto", proto, "method", method, "url", url, "duration_ms", float64(elapsed)/float64(time.Millisecond), "status_code", writer.WrittenResponseCode)

		switch {
		case writer.WrittenResponseCode >= 500:
			slog.Error("Request", userAttrs, requestAttrs)
		case writer.WrittenResponseCode >= 400:
			slog.Error("Request", userAttrs, requestAttrs)
		default:
			slog.Info("Request", userAttrs, requestAttrs)
		}

		if false {
			var headerAttrs []any
			for key, values := range r.Header {
				for _, value := range values {
					if key == "Authorization" || key == "Cookie" {
						value = "[REDACTED]"
					}
					headerAttrs = append(headerAttrs, slog.String(key, value))
				}
			}

			slog.Debug("Request Headers", slog.Group("headers", headerAttrs...))
		}
	})
}

// RequireAuthentication is middleware that enforces authentication for S3 API requests.
func RequireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		auth := r.Header.Get("Authorization")
		_ = auth

		// TODO(eteran): Implement authentication check.
		/*
			if auth == "" {
				writeS3Error(w, "AccessDenied", "Access Denied", r.URL.Path, http.StatusForbidden)
				return
			}
		*/

		next.ServeHTTP(w, r)
	})
}

func SlashFix(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Replace all occurrences of "//" with "/" in the URL path
		r.URL.Path = strings.ReplaceAll(r.URL.Path, "//", "/")

		if r.URL.Path != "/" && strings.HasSuffix(r.URL.Path, "/") {
			r.URL.Path = strings.TrimSuffix(r.URL.Path, "/")
		}

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

	return LogRequest(RequireAuthentication(SlashFix(mux)))
}

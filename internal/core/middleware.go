package core

import (
	"encoding/base64"
	"log/slog"
	"net/http"
	"silo/internal/auth"
	"strings"
	"time"
)

const (
	AccessKeyID     = "minioadmin"
	SecretAccessKey = "minioadmin"
	BasicAuthPrefix = "Basic "
	AWSv4Prefix     = "AWS4-HMAC-SHA256 "
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

type LogEntry struct {
	IP         string
	Method     string
	URL        string
	Proto      string
	DurationMS float64
	StatusCode int
}

func (e LogEntry) User() slog.Attr {
	return slog.Group("user", "ip", e.IP)
}

func (e LogEntry) Request() slog.Attr {
	return slog.Group("request",
		"proto", e.Proto,
		"method", e.Method,
		"url", e.URL,
		"duration_ms", e.DurationMS,
		"status_code", e.StatusCode,
	)
}

// LogRequest is middleware that logs incoming HTTP requests.
func LogRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		entry := LogEntry{
			IP:     r.RemoteAddr,
			Method: r.Method,
			URL:    r.URL.String(),
			Proto:  r.Proto,
		}

		writer := ResponseWriterWrapper{ResponseWriter: w}

		start := time.Now()
		next.ServeHTTP(&writer, r)
		elapsed := time.Since(start).Nanoseconds()

		entry.DurationMS = float64(elapsed) / float64(time.Millisecond)
		entry.StatusCode = writer.WrittenResponseCode

		switch {
		case writer.WrittenResponseCode >= 500:
			slog.Error("Request", entry.User(), entry.Request())
		case writer.WrittenResponseCode >= 400:
			slog.Warn("Request", entry.User(), entry.Request())
		default:
			slog.Info("Request", entry.User(), entry.Request())
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

func validateBasicAuth(r *http.Request, accessKey string, secretKey string) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, BasicAuthPrefix) {
		return false
	}

	payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(auth[len(BasicAuthPrefix):]))
	if err != nil {
		return false
	}

	creds := strings.SplitN(string(payload), ":", 2)
	if len(creds) != 2 {
		return false
	}

	return creds[0] == accessKey && creds[1] == secretKey
}

// RequireAuthentication is middleware that enforces authentication for S3 API requests.
func RequireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ctx := r.Context()

		var authEngine auth.AuthEngine
		authHeader := r.Header.Get("Authorization")
		switch {
		case strings.HasPrefix(authHeader, AWSv4Prefix):
			authEngine = auth.NewAwsHmacAuthEngine()
		case strings.HasPrefix(authHeader, BasicAuthPrefix):
			authEngine = auth.NewBasicAuthEngine()
		default:
			// No Authorization header present
			writeS3Error(w, "AccessDenied", "Access Denied", r.URL.Path, http.StatusForbidden)
			return
		}

		if authorized, err := authEngine.AuthenticateRequest(ctx, r); !authorized || err != nil {
			writeS3Error(w, "AccessDenied", "Access Denied", r.URL.Path, http.StatusForbidden)
			return
		}

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

func Recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rvr := recover(); rvr != nil {
				if rvr == http.ErrAbortHandler {
					// we don't recover http.ErrAbortHandler so the response
					// to the client is aborted, this should not be logged
					panic(rvr)
				}

				slog.Error("Internal Error in HTTP handler", "error", rvr)

				if r.Header.Get("Connection") != "Upgrade" {
					w.WriteHeader(http.StatusInternalServerError)
				}
			}
		}()

		next.ServeHTTP(w, r)
	})
}

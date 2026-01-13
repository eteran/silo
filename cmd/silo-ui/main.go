package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"html"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"silo/internal/ui"
)

var (
	//go:embed static
	staticFS embed.FS
)

// getenv returns the value of the environment variable named by key or
// fallback if the variable is not present.
func getenv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

type Server struct {
	client *minio.Client
}

func (s *Server) Home(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	buckets, err := s.client.ListBuckets(ctx)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to list buckets: %v", err), http.StatusInternalServerError)
		return
	}

	uiBuckets := make([]ui.Bucket, 0, len(buckets))
	for _, b := range buckets {
		uiBuckets = append(uiBuckets, ui.Bucket{
			Name:         b.Name,
			CreationDate: b.CreationDate.UTC().Format(time.RFC3339),
		})
	}

	if err := ui.BucketsPage(uiBuckets).Render(ctx, w); err != nil {
		http.Error(w, fmt.Sprintf("failed to render buckets page: %v", err), http.StatusInternalServerError)
		return
	}
}

func (s *Server) BucketContents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	bucket := r.PathValue("bucket")
	if bucket == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	prefix := r.PathValue("key")

	// Always fetch all buckets so the sidebar can be rendered.
	buckets, err := s.client.ListBuckets(ctx)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to list buckets: %v", err), http.StatusInternalServerError)
		return
	}

	uiBuckets := make([]ui.Bucket, 0, len(buckets))
	for _, b := range buckets {
		uiBuckets = append(uiBuckets, ui.Bucket{
			Name:         b.Name,
			CreationDate: b.CreationDate.UTC().Format(time.RFC3339),
		})
	}

	opts := minio.ListObjectsOptions{
		Recursive: false,
		Prefix:    prefix,
	}

	objects := make([]ui.Object, 0, 64)
	for obj := range s.client.ListObjects(ctx, bucket, opts) {
		if obj.Err != nil {
			// Log and skip errors for individual objects.
			slog.Error("ListObjects error", "bucket", bucket, "err", obj.Err)
			continue
		}
		objects = append(objects, ui.Object{
			Key:          obj.Key,
			Size:         obj.Size,
			LastModified: obj.LastModified.UTC().Format(time.RFC3339),
		})
	}

	if err := ui.ObjectsPage(uiBuckets, bucket, prefix, objects).Render(ctx, w); err != nil {
		http.Error(w, fmt.Sprintf("failed to render objects page: %v", err), http.StatusInternalServerError)
		return
	}
}

func (s *Server) CreateBucket(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		http.Error(w, fmt.Sprintf("failed to parse form: %v", err), http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		msg := "bucket name is required"
		if r.Header.Get("HX-Request") == "true" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, "<p class=\"error-message\">%s</p>", html.EscapeString(msg))
			return
		}
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	if err := s.client.MakeBucket(ctx, name, minio.MakeBucketOptions{}); err != nil {
		slog.Error("failed to create bucket", "bucket", name, "err", err)
		msg := fmt.Sprintf("failed to create bucket: %v", err)
		if r.Header.Get("HX-Request") == "true" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, "<p class=\"error-message\">%s</p>", html.EscapeString(msg))
			return
		}
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}

	redirectURL := fmt.Sprintf("/bucket/%s/", name)
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", redirectURL)
		w.WriteHeader(http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func Run(ctx context.Context) error {
	port := flag.String("port", getenv("SILO_UI_PORT", "9100"), "HTTP listen port")
	endpoint := flag.String("s3-endpoint", getenv("SILO_UI_S3_ENDPOINT", "localhost:9000"), "S3 / Silo API endpoint (host:port)")
	accessKey := flag.String("s3-access-key", getenv("SILO_UI_S3_ACCESS_KEY", "minioadmin"), "S3 access key")
	secretKey := flag.String("s3-secret-key", getenv("SILO_UI_S3_SECRET_KEY", "minioadmin"), "S3 secret key")
	useSSL := flag.Bool("s3-ssl", getenv("SILO_UI_S3_SSL", "false") == "true", "Use HTTPS for S3 endpoint")
	flag.Parse()

	// Logging setup consistent with main silo server.
	handler := log.NewWithOptions(os.Stdout, log.Options{
		Level:           log.DebugLevel,
		TimeFormat:      time.RFC3339,
		ReportTimestamp: true,
		TimeFunction:    log.NowUTC,
		ReportCaller:    true,
	})
	slog.SetDefault(slog.New(handler))

	client, err := minio.New(*endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(*accessKey, *secretKey, ""),
		Secure: *useSSL,
	})
	if err != nil {
		return fmt.Errorf("failed to create S3 client: %w", err)
	}

	mux := http.NewServeMux()
	// Serve embedded static assets from /static/
	staticContent, err := fs.Sub(staticFS, "static")
	if err != nil {
		return fmt.Errorf("failed to access embedded static assets: %w", err)
	}

	server := &Server{
		client: client,
	}

	mux.HandleFunc("GET /{$}", server.Home)
	mux.HandleFunc("GET /bucket/{bucket}/{key...}", server.BucketContents)
	mux.HandleFunc("POST /buckets", server.CreateBucket)
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticContent))))

	srv := &http.Server{
		Addr:              ":" + *port,
		Handler:           mux,
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
	}

	slog.Info("Starting Silo UI server", "port", *port, "s3_endpoint", *endpoint)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("silo UI server failed: %w", err)
	}

	return nil
}

func main() {
	if err := Run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/charmbracelet/log"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"silo/internal/ui"
)

// getenv returns the value of the environment variable named by key or
// fallback if the variable is not present.
func getenv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

func main() {

	listen := flag.String("listen", getenv("SILO_UI_LISTEN", "9100"), "HTTP listen address (host:port or just port)")
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
		fmt.Fprintf(os.Stderr, "failed to create S3 client: %v\n", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()

	// Home: list buckets.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		buckets, err := client.ListBuckets(ctx)
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
	})

	// Bucket contents.
	mux.Handle("/bucket/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		bucket := r.URL.Path[len("/bucket/"):]
		if bucket == "" {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		// List objects using minio-go (non-recursive by default).
		opts := minio.ListObjectsOptions{
			Recursive: true,
		}

		var objects []ui.Object
		for obj := range client.ListObjects(ctx, bucket, opts) {
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

		if err := ui.ObjectsPage(bucket, objects).Render(ctx, w); err != nil {
			http.Error(w, fmt.Sprintf("failed to render objects page: %v", err), http.StatusInternalServerError)
			return
		}
	}))

	addr := *listen
	if addr[0] == ':' {
		// ok as-is
	} else if len(addr) > 0 && addr[0] >= '0' && addr[0] <= '9' && !containsRune(addr, ':') {
		// pure port like "9100" -> ":9100"
		addr = ":" + addr
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
	}

	slog.Info("Starting Silo UI server", "addr", addr, "endpoint", *endpoint)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("Silo UI server exited with error", "err", err)
		os.Exit(1)
	}
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"silo/internal/silo"
	"time"

	"github.com/charmbracelet/log"
	"golang.org/x/sync/errgroup"
)

func Run(ctx context.Context) error {

	ServerPortHttp := flag.String("listen", "9000", "HTTP listen address")
	dataDir := flag.String("data-dir", "./data", "directory to store object data")

	flag.Parse()

	ServerPortHttps := 8443
	ServerCrtFile := ""
	ServerKeyFile := ""

	handler := log.NewWithOptions(os.Stdout, log.Options{
		Level:           log.DebugLevel,
		TimeFormat:      time.RFC3339,
		ReportTimestamp: true,
		TimeFunction:    log.NowUTC,
		ReportCaller:    true,
	})

	slog.SetDefault(slog.New(handler))

	// Ensure data directory is absolute for easier debugging.
	absDataDir, err := filepath.Abs(*dataDir)
	if err != nil {
		return fmt.Errorf("failed to resolve data directory: %w", err)
	}

	if err := os.MkdirAll(absDataDir, 0o755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	cfg := silo.Config{
		DataDir: absDataDir,
	}

	server, err := silo.NewServer(cfg)
	if err != nil {
		return fmt.Errorf("failed to create silo server: %w", err)
	}

	defer server.Close()

	router := server.Handler()

	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%s", *ServerPortHttp),
		Handler:           router,
		ReadHeaderTimeout: 20 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
	}

	httpsServer := &http.Server{
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequestClientCert,
			MinVersion: tls.VersionTLS12,
		},
		Addr:              fmt.Sprintf(":%d", ServerPortHttps),
		Handler:           router,
		ReadHeaderTimeout: 20 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
	}

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		<-ctx.Done()
		return httpsServer.Shutdown(ctx)
	})

	eg.Go(func() error {
		<-ctx.Done()
		return httpServer.Shutdown(ctx)
	})

	eg.Go(func() error {
		if ServerCrtFile == "" || ServerKeyFile == "" {
			slog.Debug("Skipping HTTPS service because no certificate was provided")
			return nil
		}

		slog.Info("Starting Silo HTTPS server", "port", ServerPortHttps)
		err := httpsServer.ListenAndServeTLS(ServerCrtFile, ServerKeyFile)
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}

		return nil
	})

	eg.Go(func() error {
		slog.Info("Starting Silo HTTP server", "port", *ServerPortHttp)
		err := httpServer.ListenAndServe()
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}

		return nil
	})

	slog.Info("Silo Started")
	return eg.Wait()

}

func main() {
	if err := Run(context.Background()); err != nil {
		slog.Error("Silo exited with error", "error", err)
	}
}

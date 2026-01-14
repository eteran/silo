package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"silo/internal/core"
	"time"

	"github.com/charmbracelet/log"
	"golang.org/x/sync/errgroup"
)

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func Run(ctx context.Context) error {

	SILO_HTTP_PORT := getEnv("SILO_HTTP_PORT", "9000")
	SILO_HTTPS_PORT := getEnv("SILO_HTTPS_PORT", "9443")
	SILO_DATA_DIR := getEnv("SILO_DATA_DIR", "./data")
	ServerCrtFile := getEnv("SILO_SERVER_CRT_FILE", "")
	ServerKeyFile := getEnv("SILO_SERVER_KEY_FILE", "")

	handler := log.NewWithOptions(os.Stdout, log.Options{
		Level:           log.DebugLevel,
		TimeFormat:      time.RFC3339,
		ReportTimestamp: true,
		TimeFunction:    log.NowUTC,
		ReportCaller:    true,
	})

	slog.SetDefault(slog.New(handler))

	// Ensure data directory is absolute for easier debugging.
	absDataDir, err := filepath.Abs(SILO_DATA_DIR)
	if err != nil {
		return fmt.Errorf("failed to resolve data directory: %w", err)
	}

	if err := os.MkdirAll(absDataDir, 0o755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	cfg := core.Config{
		DataDir: absDataDir,
	}

	server, err := core.NewServer(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to create silo server: %w", err)
	}

	defer func() {
		_ = server.Close()
	}()

	router := server.Handler()

	httpServer := &http.Server{
		Addr:              ":" + SILO_HTTP_PORT,
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
		Addr:              ":" + SILO_HTTPS_PORT,
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

		slog.Info("Starting Silo HTTPS server", "port", SILO_HTTPS_PORT)
		err := httpsServer.ListenAndServeTLS(ServerCrtFile, ServerKeyFile)
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}

		return nil
	})

	eg.Go(func() error {
		slog.Info("Starting Silo HTTP server", "port", SILO_HTTP_PORT)
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

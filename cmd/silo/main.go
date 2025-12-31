package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"silo/internal/silo"
)

func main() {
	var (
		listenAddr = flag.String("listen", ":8080", "HTTP listen address")
		dataDir    = flag.String("data-dir", "./data", "directory to store object data")
		dbPath     = flag.String("db", "./metadata.sqlite", "path to SQLite metadata database")
	)

	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	// Ensure data directory is absolute for easier debugging.
	absDataDir, err := filepath.Abs(*dataDir)
	if err != nil {
		slog.Error("failed to resolve data directory", "err", err, "dataDir", *dataDir)
		os.Exit(1)
	}

	if err := os.MkdirAll(absDataDir, 0o755); err != nil {
		slog.Error("failed to create data directory", "err", err, "dataDir", absDataDir)
		os.Exit(1)
	}

	cfg := silo.Config{
		DataDir: absDataDir,
		DBPath:  *dbPath,
	}

	server, err := silo.NewServer(cfg)
	if err != nil {
		slog.Error("failed to create silo server", "err", err)
		os.Exit(1)
	}

	slog.Info("silo listening", "addr", *listenAddr, "dataDir", absDataDir, "dbPath", *dbPath)

	if err := http.ListenAndServe(*listenAddr, server.Handler()); err != nil {
		slog.Error("server exited", "err", err)
		os.Exit(1)
	}
}

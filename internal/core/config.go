package core

import (
	"silo/internal/auth"
	"silo/internal/storage"
)

type Config struct {
	DataDir       string
	Region        string
	Engine        storage.StorageEngine
	Authenticator auth.AuthEngine
}

type ConfigOption func(*Config)

func WithStorageEngine(engine storage.StorageEngine) ConfigOption {
	return func(cfg *Config) {
		cfg.Engine = engine
	}
}

func WithAuthEngine(authenticator auth.AuthEngine) ConfigOption {
	return func(cfg *Config) {
		cfg.Authenticator = authenticator
	}
}

func WithRegion(region string) ConfigOption {
	return func(cfg *Config) {
		cfg.Region = region
	}
}

func WithDataDir(dataDir string) ConfigOption {
	return func(cfg *Config) {
		cfg.DataDir = dataDir
	}
}

func NewConfig(opts ...ConfigOption) Config {
	cfg := Config{}
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

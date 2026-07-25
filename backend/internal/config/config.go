package config

import (
	"os"
	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddr  string `yaml:"listen_addr"`
	TargetURL   string `yaml:"target_url"`
	PolicyDir   string `yaml:"policy_dir"`
	NatsURL     string `yaml:"nats_url"`
	PostgresDSN string `yaml:"postgres_dsn"`
	LogLevel    string `yaml:"log_level"`
}

// Load loads the configuration from the specified file or environment variables.
func Load(path string) (*Config, error) {
	cfg := &Config{
		ListenAddr:  ":8080",
		PolicyDir:   "./policies",
		NatsURL:     "nats://localhost:4222",
		PostgresDSN: "postgres://kiterail:kiterail@localhost:5432/kiterail?sslmode=disable",
		LogLevel:    "info",
	}

	if path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			yaml.Unmarshal(data, cfg)
		}
	}

	if val := os.Getenv("KITERAIL_LISTEN_ADDR"); val != "" {
		cfg.ListenAddr = val
	}
	if val := os.Getenv("KITERAIL_TARGET_URL"); val != "" {
		cfg.TargetURL = val
	}
	if val := os.Getenv("KITERAIL_POLICY_DIR"); val != "" {
		cfg.PolicyDir = val
	}
	if val := os.Getenv("KITERAIL_NATS_URL"); val != "" {
		cfg.NatsURL = val
	}
	if val := os.Getenv("KITERAIL_POSTGRES_DSN"); val != "" {
		cfg.PostgresDSN = val
	}
	if val := os.Getenv("KITERAIL_LOG_LEVEL"); val != "" {
		cfg.LogLevel = val
	}

	return cfg, nil
}

package config

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddr     string            `yaml:"listen_addr"`
	TargetURL      string            `yaml:"target_url"`
	PolicyDir      string            `yaml:"policy_dir"`
	NatsURL        string            `yaml:"nats_url"`
	PostgresDSN    string            `yaml:"postgres_dsn"`
	LogLevel       string            `yaml:"log_level"`
	APIKeys        map[string]string `yaml:"api_keys"`
	AllowedOrigins []string          `yaml:"allowed_origins"`
}

// Load loads the configuration from the specified file or environment variables.
func Load(path string) (*Config, error) {
	cfg := &Config{
		ListenAddr:     ":8080",
		PolicyDir:      "./policies",
		NatsURL:        "nats://localhost:4222",
		PostgresDSN:    "postgres://kiterail:kiterail@localhost:5432/kiterail?sslmode=disable",
		LogLevel:       "info",
		APIKeys:        make(map[string]string),
		AllowedOrigins: []string{"*"},
	}

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, err
		}
	}

	if cfg.APIKeys == nil {
		cfg.APIKeys = make(map[string]string)
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
	if val := os.Getenv("KITERAIL_ALLOWED_ORIGINS"); val != "" {
		origins := strings.Split(val, ",")
		for i := range origins {
			origins[i] = strings.TrimSpace(origins[i])
		}
		cfg.AllowedOrigins = origins
	}
	if val := os.Getenv("KITERAIL_API_KEYS"); val != "" {
		pairs := strings.Split(val, ",")
		for _, pair := range pairs {
			parts := strings.SplitN(pair, ":", 2)
			if len(parts) == 2 {
				cfg.APIKeys[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	return cfg, nil
}

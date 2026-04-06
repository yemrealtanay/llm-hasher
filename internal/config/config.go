package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level application configuration.
type Config struct {
	Server  ServerConfig  `yaml:"server"`
	Ollama  OllamaConfig  `yaml:"ollama"`
	Vault   VaultConfig   `yaml:"vault"`
	General GeneralConfig `yaml:"general"`
}

type ServerConfig struct {
	Host         string        `yaml:"host"`
	Port         int           `yaml:"port"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
}

type OllamaConfig struct {
	BaseURL             string        `yaml:"base_url"`
	Model               string        `yaml:"model"`
	Timeout             time.Duration `yaml:"timeout"`
	ConfidenceThreshold float64       `yaml:"confidence_threshold"`
	// ChunkSize is the max word count per chunk before parallel processing kicks in.
	ChunkSize    int    `yaml:"chunk_size"`
	NumParallel  int    `yaml:"num_parallel"`
	EnabledTypes []string `yaml:"enabled_types"`
}

type VaultConfig struct {
	DBPath          string        `yaml:"db_path"`
	KeyFile         string        `yaml:"key_file"`
	DefaultTTL      time.Duration `yaml:"default_ttl"`
	CleanupInterval time.Duration `yaml:"cleanup_interval"`
}

type GeneralConfig struct {
	LogLevel string `yaml:"log_level"`
}

// Load reads the YAML config from path, expanding ${VAR} env-var references.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	expanded := expandEnvVars(string(raw))

	cfg := defaults()
	if err := yaml.Unmarshal([]byte(expanded), cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

// defaults returns a Config pre-filled with sensible defaults.
func defaults() *Config {
	return &Config{
		Server: ServerConfig{
			Host:         "0.0.0.0",
			Port:         8080,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 60 * time.Second,
		},
		Ollama: OllamaConfig{
			BaseURL:             "http://localhost:11434",
			Model:               "llama3.2:3b",
			Timeout:             20 * time.Second,
			ConfidenceThreshold: 0.7,
			ChunkSize:           800,
			NumParallel:         4,
		},
		Vault: VaultConfig{
			DBPath:          "data/vault.db",
			DefaultTTL:      24 * time.Hour,
			CleanupInterval: 1 * time.Hour,
		},
		General: GeneralConfig{
			LogLevel: "info",
		},
	}
}

var envVarRe = regexp.MustCompile(`\$\{([^}]+)\}`)

func expandEnvVars(s string) string {
	return envVarRe.ReplaceAllStringFunc(s, func(match string) string {
		key := strings.TrimSuffix(strings.TrimPrefix(match, "${"), "}")
		if val, ok := os.LookupEnv(key); ok {
			return val
		}
		return match
	})
}

func (c *Config) validate() error {
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port must be 1–65535")
	}
	if c.Ollama.BaseURL == "" {
		return fmt.Errorf("ollama.base_url is required")
	}
	if c.Ollama.ConfidenceThreshold < 0 || c.Ollama.ConfidenceThreshold > 1 {
		return fmt.Errorf("ollama.confidence_threshold must be 0.0–1.0")
	}
	return nil
}

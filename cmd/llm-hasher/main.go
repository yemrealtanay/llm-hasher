package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yemrealtanay/llm-hasher/internal/config"
	"github.com/yemrealtanay/llm-hasher/internal/detector"
	"github.com/yemrealtanay/llm-hasher/internal/server"
	"github.com/yemrealtanay/llm-hasher/pkg/hasher"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	// ── Config ────────────────────────────────────────────────────────────────
	cfgPath := os.Getenv("CONFIG_PATH")
	if cfgPath == "" {
		cfgPath = "configs/config.yaml"
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// ── Logger ────────────────────────────────────────────────────────────────
	logLevel := slog.LevelInfo
	switch cfg.General.LogLevel {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	logger.Info("starting llm-hasher",
		"config", cfgPath,
		"ollama_model", cfg.Ollama.Model,
		"vault_db", cfg.Vault.DBPath,
	)

	// ── Hasher ────────────────────────────────────────────────────────────────
	// Convert config enabled types to detector.PIIType slice
	var enabledTypes []detector.PIIType
	for _, t := range cfg.Ollama.EnabledTypes {
		enabledTypes = append(enabledTypes, detector.PIIType(t))
	}

	opts := []hasher.Option{
		hasher.WithOllama(cfg.Ollama.BaseURL, cfg.Ollama.Model),
		hasher.WithOllamaTimeout(cfg.Ollama.Timeout),
		hasher.WithConfidenceThreshold(cfg.Ollama.ConfidenceThreshold),
		hasher.WithChunking(cfg.Ollama.ChunkSize, cfg.Ollama.NumParallel),
		hasher.WithVault(cfg.Vault.DBPath, cfg.Vault.KeyFile),
		hasher.WithDefaultTTL(cfg.Vault.DefaultTTL),
		hasher.WithHTTPClient(&http.Client{Timeout: cfg.Ollama.Timeout}),
	}
	if len(enabledTypes) > 0 {
		opts = append(opts, hasher.WithEnabledTypes(enabledTypes...))
	}

	h, err := hasher.New(opts...)
	if err != nil {
		return fmt.Errorf("create hasher: %w", err)
	}
	defer h.Close()

	// ── Expiry cleanup goroutine ───────────────────────────────────────────────
	if cfg.Vault.CleanupInterval > 0 {
		go func() {
			ticker := time.NewTicker(cfg.Vault.CleanupInterval)
			defer ticker.Stop()
			for range ticker.C {
				if err := h.ExpireOld(context.Background()); err != nil {
					logger.Warn("expire old tokens", "error", err)
				} else {
					logger.Debug("expired old tokens")
				}
			}
		}()
	}

	// ── HTTP Server ───────────────────────────────────────────────────────────
	srv := server.New(cfg, h, logger)

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	serveErr := make(chan error, 1)
	go func() {
		if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()

	select {
	case err := <-serveErr:
		return fmt.Errorf("server error: %w", err)
	case sig := <-quit:
		logger.Info("shutting down", "signal", sig.String())
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		logger.Info("shutdown complete")
	}
	return nil
}

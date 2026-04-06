// Package hasher provides a PII tokenization API that detects sensitive data
// in text, replaces it with opaque tokens, and restores original values on demand.
//
// Basic usage:
//
//	h, err := hasher.New(
//	    hasher.WithOllama("http://localhost:11434", "llama3.2:3b"),
//	    hasher.WithVault("data/vault.db", ""),
//	)
//	if err != nil { ... }
//	defer h.Close()
//
//	result, err := h.Tokenize(ctx, "My card is 4111-1111-1111-1111", "conv_123", nil)
//	// result.Text == "My card is CREDIT_CARD_conv12_4f8a2b"
//
//	original, err := h.Detokenize(ctx, result.Text, "conv_123")
//	// original == "My card is 4111-1111-1111-1111"
package hasher

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"time"

	"github.com/yemrealtanay/llm-hasher/internal/detector"
	"github.com/yemrealtanay/llm-hasher/internal/tokenizer"
	"github.com/yemrealtanay/llm-hasher/internal/vault"
)

// Hasher is the main entry point for PII tokenization.
type Hasher struct {
	detector  *detector.Detector
	tokenizer *tokenizer.Tokenizer
	vault     *vault.Vault
	opts      options
}

// TokenizeResult is returned by Tokenize.
type TokenizeResult struct {
	// Text is the input with PII replaced by tokens.
	Text string
	// ContextID is the scope used for this tokenization (caller-provided or auto-generated).
	ContextID string
	// Entities describes each piece of PII that was found and tokenized.
	Entities []DetectedEntity
}

// DetectedEntity describes one tokenized PII entity.
type DetectedEntity struct {
	Token    string
	PIIType  string
	Original string
}

// New creates a Hasher with the given options.
func New(opts ...Option) (*Hasher, error) {
	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}

	v, err := vault.Open(o.vaultDBPath, o.vaultKeyFile)
	if err != nil {
		return nil, fmt.Errorf("open vault: %w", err)
	}

	httpClient := o.httpClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: o.ollamaTimeout}
	}

	det := detector.New(detector.Config{
		OllamaBaseURL:       o.ollamaBaseURL,
		Model:               o.ollamaModel,
		ConfidenceThreshold: o.confidenceThreshold,
		ChunkSize:           o.chunkSize,
		NumParallel:         o.numParallel,
		EnabledTypes:        o.enabledTypes,
		HTTPClient:          httpClient,
	})

	tok := tokenizer.New(v)

	return &Hasher{
		detector:  det,
		tokenizer: tok,
		vault:     v,
		opts:      o,
	}, nil
}

// Close releases resources held by the Hasher (vault DB connection).
func (h *Hasher) Close() error {
	return h.vault.Close()
}

// Tokenize detects PII in text and replaces it with vault-backed tokens.
//
// contextID scopes the token mappings — use a stable ID from your domain
// (e.g. a conversation ID, record ID). If empty, a random ID is generated
// and returned in the result.
//
// expiresAt controls when the vault mappings expire. nil means no expiry.
func (h *Hasher) Tokenize(ctx context.Context, text, contextID string, expiresAt *time.Time) (TokenizeResult, error) {
	if contextID == "" {
		contextID = generateContextID()
	}

	if expiresAt == nil && h.opts.defaultTTL > 0 {
		t := time.Now().Add(h.opts.defaultTTL)
		expiresAt = &t
	}

	detection, err := h.detector.Detect(ctx, text)
	if err != nil {
		return TokenizeResult{}, fmt.Errorf("detect PII: %w", err)
	}

	result, err := h.tokenizer.Tokenize(ctx, detection, contextID, expiresAt)
	if err != nil {
		return TokenizeResult{}, fmt.Errorf("tokenize: %w", err)
	}

	entities := make([]DetectedEntity, len(result.Entities))
	for i, e := range result.Entities {
		entities[i] = DetectedEntity{
			Token:    e.Token,
			PIIType:  string(e.PIIType),
			Original: e.OriginalValue,
		}
	}

	return TokenizeResult{
		Text:      result.Text,
		ContextID: contextID,
		Entities:  entities,
	}, nil
}

// Detokenize replaces all tokens in text with their original values.
func (h *Hasher) Detokenize(ctx context.Context, text, contextID string) (string, error) {
	result, err := h.tokenizer.Detokenize(ctx, text, contextID)
	if err != nil {
		return "", fmt.Errorf("detokenize: %w", err)
	}
	return result, nil
}

// DeleteContext removes all token mappings for a context (compliance/cleanup).
func (h *Hasher) DeleteContext(ctx context.Context, contextID string) error {
	return h.vault.DeleteContext(ctx, contextID)
}

// Ping checks that the Ollama service is reachable.
func (h *Hasher) Ping(ctx context.Context) error {
	return h.detector.Ping(ctx)
}

// ExpireOld removes contexts and tokens that have passed their TTL.
func (h *Hasher) ExpireOld(ctx context.Context) error {
	return h.vault.ExpireOld(ctx)
}

// PIITypes returns all supported PII type identifiers.
func PIITypes() []string {
	types := make([]string, len(detector.AllPIITypes))
	for i, t := range detector.AllPIITypes {
		types[i] = string(t)
	}
	return types
}

func generateContextID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

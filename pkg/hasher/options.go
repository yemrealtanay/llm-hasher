package hasher

import (
	"net/http"
	"time"

	"github.com/yemrealtanay/llm-hasher/internal/detector"
)

// Option configures a Hasher.
type Option func(*options)

type options struct {
	ollamaBaseURL       string
	ollamaModel         string
	ollamaTimeout       time.Duration
	confidenceThreshold float64
	chunkSize           int
	numParallel         int
	enabledTypes        []detector.PIIType
	vaultDBPath         string
	vaultKeyFile        string
	defaultTTL          time.Duration
	httpClient          *http.Client
}

func defaultOptions() options {
	return options{
		ollamaBaseURL:       "http://localhost:11434",
		ollamaModel:         "llama3.2:3b",
		ollamaTimeout:       20 * time.Second,
		confidenceThreshold: 0.7,
		chunkSize:           800,
		numParallel:         4,
		vaultDBPath:         "data/vault.db",
		defaultTTL:          24 * time.Hour,
	}
}

// WithOllama sets the Ollama base URL and model.
func WithOllama(baseURL, model string) Option {
	return func(o *options) {
		o.ollamaBaseURL = baseURL
		o.ollamaModel = model
	}
}

// WithOllamaTimeout sets the per-request Ollama timeout.
func WithOllamaTimeout(d time.Duration) Option {
	return func(o *options) { o.ollamaTimeout = d }
}

// WithConfidenceThreshold sets the minimum confidence for LLM-detected PII.
func WithConfidenceThreshold(t float64) Option {
	return func(o *options) { o.confidenceThreshold = t }
}

// WithChunking configures text chunking for large inputs.
func WithChunking(chunkSize, numParallel int) Option {
	return func(o *options) {
		o.chunkSize = chunkSize
		o.numParallel = numParallel
	}
}

// WithEnabledTypes restricts which PII types are detected.
func WithEnabledTypes(types ...detector.PIIType) Option {
	return func(o *options) { o.enabledTypes = types }
}

// WithVault configures the vault database path and key file.
func WithVault(dbPath, keyFile string) Option {
	return func(o *options) {
		o.vaultDBPath = dbPath
		o.vaultKeyFile = keyFile
	}
}

// WithDefaultTTL sets the default token TTL (0 = no expiry).
func WithDefaultTTL(d time.Duration) Option {
	return func(o *options) { o.defaultTTL = d }
}

// WithHTTPClient sets a custom HTTP client for Ollama requests.
func WithHTTPClient(c *http.Client) Option {
	return func(o *options) { o.httpClient = c }
}

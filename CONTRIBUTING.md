# Contributing to llm-hasher

Thank you for your interest in contributing. This document covers the most common contribution paths.

## Before You Start

- Open an issue before starting large changes — alignment saves everyone time
- For bug fixes and small improvements, a PR is enough without a prior issue
- Be respectful. We follow the [Contributor Covenant](https://www.contributor-covenant.org/)

## Development Setup

```bash
git clone https://github.com/yemrealtanay/llm-hasher
cd llm-hasher
make setup       # installs Ollama, pulls model, builds binary
make test        # run tests
make run         # start the server
```

## Project Structure

```
cmd/llm-hasher/      Binary entry point
pkg/hasher/          Public library API — stable interface, breaking changes need discussion
internal/
  config/            YAML config loading
  detector/          PII detection (regex + Ollama)
  tokenizer/         Token generation and text replacement
  vault/             Encrypted SQLite storage
  server/            HTTP handlers
```

## Good First Issues

These are well-defined, self-contained tasks ideal for first-time contributors:

### Adding a new LLM provider adapter (v2)

The v2 proxy feature will allow llm-hasher to handle the full tokenize→LLM→detokenize round trip automatically. Each LLM provider needs a small adapter.

To add support for a provider (e.g. Google Gemini, Mistral, Cohere):

1. Create `internal/proxy/your_provider.go`
2. Implement the `LLMProvider` interface (defined in `internal/proxy/provider.go` — to be created in v2)
3. Add it to the provider registry in `internal/proxy/registry.go`
4. Add integration tests using `net/http/httptest`

The interface will look like:

```go
type LLMProvider interface {
    Name() string
    Forward(ctx context.Context, req LLMRequest) (LLMResponse, error)
    ExtractContent(raw json.RawMessage) (string, error)
    InjectContent(raw json.RawMessage, content string) (json.RawMessage, error)
}
```

### Improving regex detection

Add or improve patterns in `internal/detector/regex.go`. Test cases are very welcome.

- Turkish TC Kimlik No (11-digit national ID)
- Date of birth formats (DD/MM/YYYY, MM-DD-YYYY, etc.)
- Improved phone number patterns for specific regions

### Adding more Ollama model presets

Update `configs/config.example.yaml` and README with tested model recommendations and their tradeoffs.

## Coding Style

- Standard Go: `gofmt`, `go vet` — no linter config, just the defaults
- Table-driven tests in `_test.go` files alongside the code they test
- No external test libraries — stdlib `testing` + `net/http/httptest` only
- Error messages lowercase, no trailing punctuation: `"open vault: %w"` not `"Open vault: %w."`
- New exported symbols need a doc comment

## Tests

```bash
make test            # all tests
make test-verbose    # with output
```

For vault tests, use `:memory:` as the db path — no files written:

```go
v, err := vault.Open(":memory:", "")
```

For Ollama tests, mock the HTTP endpoint with `net/http/httptest.NewServer`.

## Pull Request Checklist

- [ ] `go build ./...` passes
- [ ] `go vet ./...` passes
- [ ] New behavior is covered by tests
- [ ] `configs/config.example.yaml` updated if new config fields added
- [ ] README updated if API or behavior changes

## Release Process

Maintainers handle releases. Versioning follows [Semantic Versioning](https://semver.org).

<div align="center">

# 🔏 llm-hasher

**Privacy-first PII tokenization middleware for LLM pipelines.**

Replace sensitive data with opaque tokens before sending to any LLM.
Restore original values on the way back. Your vault, your keys.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go)](go.mod)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker)](docker-compose.yml)
[![Ollama](https://img.shields.io/badge/Powered%20by-Ollama-black)](https://ollama.ai)

[Quick Start](#quick-start) · [API Reference](#api-reference) · [How It Works](#how-it-works) · [Contributing](#contributing)

</div>

---

## The Problem

You send customer transcripts, support chats, or documents to LLMs for summarization, analysis, or classification. Those texts contain real credit card numbers, home addresses, names, and national IDs — sent in plaintext to a third-party API and potentially stored in your own database.

**llm-hasher sits between your app and the LLM.** It strips sensitive data, sends clean tokens, and puts the real values back in the response. The LLM never sees the actual PII. Your database stores tokens, not plaintext.

## How It Works

```
Your App ──► POST /v1/tokenize ──► llm-hasher ──► tokenized text
                                       │
                              detects PII locally
                              (Ollama, no cloud)
                              stores in encrypted vault

Your App ──► [your LLM call with tokenized text]

Your App ──► POST /v1/detokenize ──► llm-hasher ──► original text restored
```

**Example:**

```
Input:   "Hi, my card is 4111-1111-1111-1111 and email is john@example.com"

Output:  "Hi, my card is CREDIT_CARD_john12_4f8a2b and email is EMAIL_john12_9c3d1a"
```

The LLM receives the tokenized version — it still understands the context ("the user provided a CREDIT_CARD") but never sees the real number. When the LLM's response comes back, you send it through `/v1/detokenize` and get real values back.

## Features

- **Local PII detection** — uses [Ollama](https://ollama.ai) running on your own server, no data leaves your infra for detection
- **Hybrid detection** — fast regex for structured types (credit cards, emails, phone numbers, IBAN, IPs) + LLM for contextual types (names, addresses, national IDs, passports)
- **Encrypted vault** — token↔value mappings stored in SQLite with AES-256-GCM encryption, keys never leave the process
- **Your own IDs** — use `context_id` from your domain (`"zoom_call_789"`, `"contact_123"`) instead of tracking foreign UUIDs
- **Deduplication** — the same PII within a context always maps to the same token, so LLMs can reason consistently
- **Performance** — large texts are chunked and processed in parallel goroutines; detokenization uses a single-pass multi-string replace
- **Dual-use** — run as a standalone HTTP service or import as a Go library
- **Zero dependencies to run** — single binary + SQLite; Docker Compose includes Ollama

## Supported PII Types

| Type | Detection Method |
|---|---|
| `CREDIT_CARD` | Regex (Visa, Mastercard, Amex, Discover) |
| `EMAIL` | Regex |
| `PHONE_NUMBER` | Regex (international formats) |
| `IP_ADDRESS` | Regex (IPv4) |
| `BANK_ACCOUNT` | Regex (IBAN) |
| `PERSON_NAME` | Ollama LLM (context-aware) |
| `HOME_ADDRESS` | Ollama LLM (context-aware) |
| `NATIONAL_ID` | Ollama LLM (SSN, TC Kimlik, NIN, etc.) |
| `PASSPORT` | Ollama LLM |
| `DATE_OF_BIRTH` | Ollama LLM |

---

## Quick Start

### Docker (recommended)

```bash
git clone https://github.com/yemrealtanay/llm-hasher
cd llm-hasher
make docker-up
```

That's it. Docker Compose starts Ollama, pulls `llama3.2:3b` automatically (~2GB), and starts the service on port `8080`.

```bash
# Check it's running
curl http://localhost:8080/healthz
# {"status":"ok"}
```

> **Requirements:** Docker, ~4GB RAM, ~3GB disk

### Bare Metal

```bash
git clone https://github.com/yemrealtanay/llm-hasher
cd llm-hasher
make setup   # installs Ollama if missing, pulls model, builds binary
make run
```

> **Requirements:** Go 1.25+, ~4GB RAM

---

## API Reference

### `POST /v1/tokenize`

Detect and replace PII in text with vault-backed tokens.

**Request:**
```json
{
  "text": "My card is 4111-1111-1111-1111 and I live at 123 Main St, Boston",
  "context_id": "zoom_call_789",
  "ttl": "24h"
}
```

| Field | Required | Description |
|---|---|---|
| `text` | yes | The text to tokenize |
| `context_id` | no | Your own ID to scope the mappings. If omitted, a random one is generated and returned. Use a stable ID from your domain for later detokenization. |
| `ttl` | no | Token expiry duration (e.g. `"24h"`, `"7d"`). `"0"` or omitted = no expiry. |

**Response:**
```json
{
  "tokenized_text": "My card is CREDIT_CARD_zoomc7_4f8a2b and I live at HOME_ADDRESS_zoomc7_9c3d1a",
  "context_id": "zoom_call_789",
  "entities": [
    { "token": "CREDIT_CARD_zoomc7_4f8a2b", "pii_type": "CREDIT_CARD" },
    { "token": "HOME_ADDRESS_zoomc7_9c3d1a", "pii_type": "HOME_ADDRESS" }
  ]
}
```

---

### `POST /v1/detokenize`

Restore original values in a text that contains tokens.

**Request:**
```json
{
  "text": "The user provided CREDIT_CARD_zoomc7_4f8a2b as payment.",
  "context_id": "zoom_call_789"
}
```

**Response:**
```json
{
  "original_text": "The user provided 4111-1111-1111-1111 as payment."
}
```

---

### `POST /v1/tokenize/batch`

Tokenize multiple texts in a single request (processed in parallel).

**Request:**
```json
{
  "items": [
    { "text": "Call with John, card 4111-1111-1111-1111", "context_id": "call_1" },
    { "text": "Support ticket from jane@example.com",    "context_id": "ticket_42" }
  ]
}
```

---

### `DELETE /v1/contexts/{context_id}`

Hard-delete all token mappings for a context. Use for compliance/right-to-erasure scenarios.

```bash
curl -X DELETE http://localhost:8080/v1/contexts/zoom_call_789
# 204 No Content
```

---

## Real-World Usage Patterns

### Pattern 1: LLM Proxy (transcript analysis)

```python
# 1. Tokenize before sending to LLM
resp = requests.post("http://localhost:8080/v1/tokenize", json={
    "text": transcript,
    "context_id": f"zoom_{call_id}"
})
tokenized = resp.json()

# 2. Send tokenized text to your LLM
llm_response = openai.chat.completions.create(
    messages=[
        {"role": "system", "content": "Summarize this call transcript."},
        {"role": "user",   "content": tokenized["tokenized_text"]}
    ]
)

# 3. Detokenize the LLM response
final = requests.post("http://localhost:8080/v1/detokenize", json={
    "text": llm_response.choices[0].message.content,
    "context_id": f"zoom_{call_id}"
})
print(final.json()["original_text"])
```

### Pattern 2: Database Storage

```python
# Before saving to DB — tokenize with no expiry
resp = requests.post("http://localhost:8080/v1/tokenize", json={
    "text": transcript,
    "context_id": f"contact_{contact_id}",
    "ttl": "0"   # no expiry — lives as long as the record
})
db.save(contact_id=contact_id, transcript=resp.json()["tokenized_text"])

# When displaying to user — detokenize on the fly
row = db.get(contact_id)
resp = requests.post("http://localhost:8080/v1/detokenize", json={
    "text": row.transcript,
    "context_id": f"contact_{contact_id}"
})
show_to_user(resp.json()["original_text"])
```

### Pattern 3: Go Library

```go
import "github.com/yemrealtanay/llm-hasher/pkg/hasher"

h, err := hasher.New(
    hasher.WithOllama("http://localhost:11434", "llama3.2:3b"),
    hasher.WithVault("data/vault.db", ""),
)
defer h.Close()

result, err := h.Tokenize(ctx, transcript, "zoom_call_789", nil)
// result.Text contains tokenized transcript

original, err := h.Detokenize(ctx, llmResponse, "zoom_call_789")
```

---

## Configuration

Copy `configs/config.example.yaml` to `configs/config.yaml` and adjust:

```yaml
ollama:
  model: "llama3.2:3b"        # or llama3.1:8b for higher recall
  confidence_threshold: 0.7   # lower = more aggressive detection
  chunk_size: 800              # words before parallel chunking kicks in

vault:
  default_ttl: "24h"          # "0" for no expiry
```

**Encryption key** (production): set `VAULT_KEY` environment variable to 64 hex characters (32 bytes). If not set, a key is auto-generated and saved to `data/vault.key`.

```bash
# Generate a key
openssl rand -hex 32
# Add to .env:
# VAULT_KEY=<output>
```

---

## Performance

| Scenario | Typical Latency |
|---|---|
| Short text (< 800 words), regex PII only | < 5ms |
| Short text with LLM detection | 2–8s (model dependent) |
| Long text (5000 words), 6 parallel chunks | 3–10s |
| Detokenize (any size) | < 5ms |

Detection latency is dominated by Ollama inference. Using `llama3.2:3b` on a modern laptop typically takes 2–4 seconds per chunk. A GPU or a faster model reduces this significantly.

---

## Roadmap

- [x] **v1** — Tokenize / Detokenize API with local Ollama detection
- [ ] **v2** — Built-in LLM proxy endpoints (OpenAI-compatible, Anthropic)
- [ ] **v2** — Streaming tokenization (SSE) for large documents
- [ ] **v2** — OpenTelemetry tracing
- [ ] **v3** — Web UI for vault inspection
- [ ] **v3** — Multi-tenant support

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

The most impactful area for contributors right now is **v2 LLM provider adapters** — if you use a provider not listed, adding an adapter is a well-defined, self-contained task.

---

## Support the Project

If llm-hasher saves you time or helps protect your users' data, consider supporting its development:

[![Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/yemrealtanay)

---

## License

[MIT](LICENSE) — free to use, modify, and distribute.

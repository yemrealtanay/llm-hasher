package tokenizer

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yemrealtanay/llm-hasher/internal/detector"
	"github.com/yemrealtanay/llm-hasher/internal/vault"
)

// replacement is a token→value pair used by multiReplace.
type replacement struct {
	token string
	value string
}

// Tokenizer handles PII→token replacement and token→PII restoration.
type Tokenizer struct {
	vault *vault.Vault
}

// New creates a Tokenizer backed by the given vault.
func New(v *vault.Vault) *Tokenizer {
	return &Tokenizer{vault: v}
}

// TokenizeResult is the output of a Tokenize call.
type TokenizeResult struct {
	Text      string
	ContextID string
	Entities  []TokenizedEntity
}

// TokenizedEntity records what was found and what token replaced it.
type TokenizedEntity struct {
	Token      string
	PIIType    detector.PIIType
	OriginalValue string
}

// Tokenize replaces all detected PII entities in result.Text with vault tokens.
// contextID scopes the token mappings. expiresAt nil = no expiry.
func (t *Tokenizer) Tokenize(ctx context.Context, result detector.DetectionResult, contextID string, expiresAt *time.Time) (TokenizeResult, error) {
	if err := t.vault.EnsureContext(ctx, contextID, expiresAt, nil); err != nil {
		return TokenizeResult{}, fmt.Errorf("ensure context: %w", err)
	}

	// Sort entities in reverse offset order so substitutions don't shift offsets
	entities := make([]detector.PIIEntity, len(result.Entities))
	copy(entities, result.Entities)
	sort.Slice(entities, func(i, j int) bool {
		return entities[i].Start > entities[j].Start
	})

	text := result.Text
	var tokenized []TokenizedEntity

	// Track value→token within this call to handle same-value duplicates
	// before they hit the vault (avoids round trips for repeated values)
	localCache := make(map[string]string) // piiType+":"+value → token

	for _, entity := range entities {
		cacheKey := string(entity.Type) + ":" + entity.Value

		tokenVal, cached := localCache[cacheKey]
		if !cached {
			// Check vault for dedup
			existing, found, err := t.vault.LookupByValue(ctx, contextID, string(entity.Type), entity.Value)
			if err != nil {
				return TokenizeResult{}, fmt.Errorf("vault lookup: %w", err)
			}
			if found {
				tokenVal = existing.Token
			} else {
				// Generate new token
				tok, err := generate(entity.Type, contextID)
				if err != nil {
					return TokenizeResult{}, err
				}
				tokenVal = tok.Value

				// Compute value hash for dedup
				rec := vault.TokenRecord{
					Token:          tokenVal,
					ContextID:      contextID,
					PIIType:        string(entity.Type),
					EncryptedValue: []byte(entity.Value), // vault.Store encrypts + hashes
					ExpiresAt:      expiresAt,
				}
				if err := t.vault.Store(ctx, rec); err != nil {
					return TokenizeResult{}, fmt.Errorf("vault store: %w", err)
				}
			}
			localCache[cacheKey] = tokenVal
		}

		// Replace in text (byte offset replacement)
		text = text[:entity.Start] + tokenVal + text[entity.End:]

		tokenized = append(tokenized, TokenizedEntity{
			Token:         tokenVal,
			PIIType:       entity.Type,
			OriginalValue: entity.Value,
		})
	}

	return TokenizeResult{
		Text:      text,
		ContextID: contextID,
		Entities:  tokenized,
	}, nil
}

// Detokenize replaces all known tokens in text with their original values.
// Uses Aho-Corasick-style multi-pass with fuzzy fallback.
func (t *Tokenizer) Detokenize(ctx context.Context, text, contextID string) (string, error) {
	records, err := t.vault.ListByContext(ctx, contextID)
	if err != nil {
		return "", fmt.Errorf("list context tokens: %w", err)
	}
	if len(records) == 0 {
		return text, nil
	}

	// Build token→value list (and lowercase variants for fuzzy match)
	replacements := make([]replacement, 0, len(records)*2)
	for _, rec := range records {
		v := rec.ValueOf()
		replacements = append(replacements, replacement{rec.Token, v})
		lower := strings.ToLower(rec.Token)
		if lower != rec.Token {
			replacements = append(replacements, replacement{lower, v})
		}
	}

	// Sort by token length descending — replace longer tokens first to avoid
	// partial matches (e.g. replace CREDIT_CARD_... before CREDIT_).
	sort.Slice(replacements, func(i, j int) bool {
		return len(replacements[i].token) > len(replacements[j].token)
	})

	result := multiReplace(text, replacements)
	return result, nil
}

// multiReplace performs an efficient multi-string replacement in a single pass
// using a simple greedy scan (longest match at each position).
func multiReplace(text string, replacements []replacement) string {
	if len(replacements) == 0 {
		return text
	}

	// Build a quick-lookup map: token → value
	lookup := make(map[string]string, len(replacements))
	for _, r := range replacements {
		lookup[r.token] = r.value
	}

	var sb strings.Builder
	sb.Grow(len(text))

	i := 0
	for i < len(text) {
		matched := false
		for _, r := range replacements {
			if len(r.token) == 0 {
				continue
			}
			if strings.HasPrefix(text[i:], r.token) {
				sb.WriteString(lookup[r.token])
				i += len(r.token)
				matched = true
				break
			}
		}
		if !matched {
			sb.WriteByte(text[i])
			i++
		}
	}
	return sb.String()
}


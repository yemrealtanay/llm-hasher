package tokenizer

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/yemrealtanay/llm-hasher/internal/detector"
)

// Token represents a generated replacement token.
//
// Format: {ENTITY_TYPE}_{CONTEXT_SHORT}_{RANDOM_HEX}
// Example: CREDIT_CARD_a1b2c3_4f8a2b
type Token struct {
	Value      string
	EntityType detector.PIIType
	ContextID  string
}

// generate creates a new unique token for the given PII type and context.
func generate(piiType detector.PIIType, contextID string) (Token, error) {
	randBytes := make([]byte, 4)
	if _, err := rand.Read(randBytes); err != nil {
		return Token{}, fmt.Errorf("generate token random: %w", err)
	}

	// Use first 6 chars of contextID (or a hash) as the context short prefix
	contextShort := sanitizeContextShort(contextID)

	randomHex := hex.EncodeToString(randBytes)
	value := fmt.Sprintf("%s_%s_%s", string(piiType), contextShort, randomHex)

	return Token{
		Value:      value,
		EntityType: piiType,
		ContextID:  contextID,
	}, nil
}

// sanitizeContextShort derives a short, token-safe string from a contextID.
// It takes up to 6 alphanumeric characters from the ID.
func sanitizeContextShort(contextID string) string {
	var out strings.Builder
	for _, r := range contextID {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			out.WriteRune(r)
		} else if r >= 'A' && r <= 'Z' {
			out.WriteRune(r + 32) // lowercase
		}
		if out.Len() >= 6 {
			break
		}
	}
	// Pad with zeros if shorter than 6
	for out.Len() < 6 {
		out.WriteRune('0')
	}
	return out.String()
}

// IsToken returns true if s looks like an llm-hasher token (TYPE_xxxxxx_yyyyyyyy).
func IsToken(s string) bool {
	parts := strings.SplitN(s, "_", 3)
	if len(parts) < 3 {
		return false
	}
	// Check that the first part is a known PII type
	for _, t := range detector.AllPIITypes {
		if string(t) == parts[0] {
			return true
		}
	}
	// Multi-word types like CREDIT_CARD split into more parts
	if len(s) > 0 {
		for _, t := range detector.AllPIITypes {
			if strings.HasPrefix(s, string(t)+"_") {
				return true
			}
		}
	}
	return false
}

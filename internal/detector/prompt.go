package detector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

const systemPrompt = `You are a PII detection engine. You extract personally identifiable information from text and return ONLY valid JSON. You never explain your reasoning. You never add commentary.

Output must be a JSON array of entity objects with exactly these fields:
  "type"       - string, one of: PERSON_NAME, HOME_ADDRESS, NATIONAL_ID, PASSPORT
  "value"      - string, the exact substring as it appears in the text (case-preserving)
  "confidence" - number between 0.0 and 1.0

Rules:
- Only include entities with confidence >= 0.7
- PERSON_NAME: include full names or clearly identifiable names only; skip generic first names without context
- HOME_ADDRESS: include street+city combos, postal codes with city context, or clearly formatted addresses
- NATIONAL_ID: country-specific government ID numbers (SSN, TC Kimlik No, NIN, etc.)
- PASSPORT: passport numbers only
- The "value" field MUST be verbatim from the input text
- If no PII is found, return an empty JSON array: []
- Do not wrap the JSON in markdown code fences
- Do not include email, phone, credit card, IP address, or IBAN — those are handled separately`

const userPromptTemplate = `Detect all PII in the following text. Return only the JSON array.

Text:
"""
%s
"""`

// buildPromptMessages returns the Ollama chat messages for PII detection.
func buildPromptMessages(text string) []map[string]string {
	return []map[string]string{
		{"role": "system", "content": systemPrompt},
		{"role": "user", "content": fmt.Sprintf(userPromptTemplate, text)},
	}
}

// rawEntity is the JSON structure returned by the LLM.
type rawEntity struct {
	Type       string  `json:"type"`
	Value      string  `json:"value"`
	Confidence float64 `json:"confidence"`
}

// parseOllamaResponse parses and validates the LLM's JSON response.
// It verifies each entity's value actually exists in the original text
// to prevent hallucination issues.
func parseOllamaResponse(body []byte, originalText string, threshold float64) ([]PIIEntity, error) {
	// Strip markdown code fences if present
	cleaned := strings.TrimSpace(stripCodeFences(string(body)))
	if cleaned == "" || cleaned == "null" {
		return nil, nil
	}

	// LLMs sometimes return a single object {} instead of an array [{}].
	// Normalize to array form before unmarshalling.
	if strings.HasPrefix(cleaned, "{") {
		cleaned = "[" + cleaned + "]"
	}

	var raw []rawEntity
	if err := json.Unmarshal([]byte(cleaned), &raw); err != nil {
		return nil, fmt.Errorf("parse LLM JSON: %w (body: %.200s)", err, cleaned)
	}

	llmTypes := map[string]PIIType{
		"PERSON_NAME":  PIITypePersonName,
		"HOME_ADDRESS": PIITypeHomeAddress,
		"NATIONAL_ID":  PIITypeNationalID,
		"PASSPORT":     PIITypePassport,
	}

	var entities []PIIEntity
	for _, r := range raw {
		piiType, ok := llmTypes[strings.ToUpper(r.Type)]
		if !ok {
			continue // unknown type, skip
		}
		if r.Confidence < threshold {
			continue
		}
		if r.Value == "" {
			continue
		}

		// Hallucination guard: value must appear verbatim in original text
		idx := strings.Index(originalText, r.Value)
		if idx == -1 {
			continue
		}

		entities = append(entities, PIIEntity{
			Type:       piiType,
			Value:      r.Value,
			Start:      idx,
			End:        idx + len(r.Value),
			Confidence: r.Confidence,
		})
	}

	return entities, nil
}

func stripCodeFences(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		// find end of first line
		nl := strings.Index(s, "\n")
		if nl != -1 {
			s = s[nl+1:]
		}
		s = strings.TrimSuffix(strings.TrimSpace(s), "```")
	}
	return strings.TrimSpace(s)
}

// buildOllamaRequest serializes the Ollama /api/chat request body.
func buildOllamaRequest(model, text string) ([]byte, error) {
	req := map[string]any{
		"model":    model,
		"messages": buildPromptMessages(text),
		"stream":   false,
		"format":   "json",
		"options": map[string]any{
			"temperature": 0.0, // deterministic
		},
	}
	return json.Marshal(req)
}

// extractOllamaContent pulls the assistant message content from the response.
func extractOllamaContent(body []byte) (string, error) {
	var resp struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&resp); err != nil {
		return "", fmt.Errorf("decode ollama response: %w", err)
	}
	return resp.Message.Content, nil
}

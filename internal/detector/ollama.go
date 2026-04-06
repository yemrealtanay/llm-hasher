package detector

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"unicode"
)

// Detector detects PII entities in text using hybrid regex + Ollama LLM.
type Detector struct {
	ollamaURL   string
	model       string
	threshold   float64
	chunkSize   int    // max words per LLM chunk
	numParallel int    // max concurrent Ollama requests
	enabled     map[PIIType]bool
	httpClient  *http.Client
}

// Config configures a Detector.
type Config struct {
	OllamaBaseURL       string
	Model               string
	ConfidenceThreshold float64
	ChunkSize           int
	NumParallel         int
	EnabledTypes        []PIIType // nil = all types enabled
	HTTPClient          *http.Client
}

// New creates a Detector. If cfg.EnabledTypes is empty all types are enabled.
func New(cfg Config) *Detector {
	enabled := make(map[PIIType]bool)
	types := cfg.EnabledTypes
	if len(types) == 0 {
		types = AllPIITypes
	}
	for _, t := range types {
		enabled[t] = true
	}

	chunkSize := cfg.ChunkSize
	if chunkSize <= 0 {
		chunkSize = 800
	}
	numParallel := cfg.NumParallel
	if numParallel <= 0 {
		numParallel = 4
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 0} // timeout set per-request via context
	}

	return &Detector{
		ollamaURL:   strings.TrimRight(cfg.OllamaBaseURL, "/"),
		model:       cfg.Model,
		threshold:   cfg.ConfidenceThreshold,
		chunkSize:   chunkSize,
		numParallel: numParallel,
		enabled:     enabled,
		httpClient:  client,
	}
}

// Detect finds all PII entities in text using regex for structured types and
// Ollama for contextual types (names, addresses, IDs, passports).
func (d *Detector) Detect(ctx context.Context, text string) (DetectionResult, error) {
	// 1. Regex pass (fast, structured PII)
	regexEntities := detectWithRegex(text, d.enabled)

	// 2. Build a "masked" version of text with regex findings replaced,
	//    so the LLM doesn't double-detect already-found items.
	maskedText := maskEntities(text, regexEntities)

	// 3. LLM pass for contextual PII (names, addresses, national IDs, passports)
	needsLLM := false
	for t := range d.enabled {
		if !regexDetectedTypes[t] {
			needsLLM = true
			break
		}
	}

	var llmEntities []PIIEntity
	if needsLLM && maskedText != "" {
		var err error
		llmEntities, err = d.detectWithLLM(ctx, maskedText, text)
		if err != nil {
			return DetectionResult{}, fmt.Errorf("llm detection: %w", err)
		}
	}

	// 4. Merge and deduplicate
	all := deduplicateEntities(append(regexEntities, llmEntities...))

	return DetectionResult{Entities: all, Text: text}, nil
}

// detectWithLLM runs Ollama detection, chunking large texts in parallel.
func (d *Detector) detectWithLLM(ctx context.Context, maskedText, originalText string) ([]PIIEntity, error) {
	chunks := splitIntoChunks(maskedText, d.chunkSize)
	if len(chunks) == 0 {
		return nil, nil
	}

	sem := make(chan struct{}, d.numParallel)
	type result struct {
		entities []PIIEntity
		err      error
	}
	results := make([]result, len(chunks))
	var wg sync.WaitGroup

	for i, chunk := range chunks {
		wg.Add(1)
		go func(i int, chunk chunkInfo) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			entities, err := d.ollamaDetect(ctx, chunk.text)
			if err != nil {
				results[i] = result{err: err}
				return
			}

			// Re-map offsets from maskedText chunk to originalText positions
			adjusted := adjustOffsets(entities, originalText, chunk.startOffset)
			results[i] = result{entities: adjusted}
		}(i, chunk)
	}
	wg.Wait()

	var all []PIIEntity
	for _, r := range results {
		if r.err != nil {
			return nil, r.err
		}
		all = append(all, r.entities...)
	}
	return deduplicateEntities(all), nil
}

// ollamaDetect sends one chunk to Ollama and returns parsed entities.
func (d *Detector) ollamaDetect(ctx context.Context, text string) ([]PIIEntity, error) {
	body, err := buildOllamaRequest(d.model, text)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		d.ollamaURL+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ollama request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read ollama response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ollama returned %d: %.200s", resp.StatusCode, respBody)
	}

	content, err := extractOllamaContent(respBody)
	if err != nil {
		return nil, err
	}

	return parseOllamaResponse([]byte(content), text, d.threshold)
}

// chunkInfo holds a text chunk and its byte offset in the original masked text.
type chunkInfo struct {
	text        string
	startOffset int
}

// splitIntoChunks splits text into sentence-boundary chunks of ~chunkSize words,
// with a 50-word overlap to avoid missing PII that straddles a boundary.
func splitIntoChunks(text string, chunkSize int) []chunkInfo {
	words := strings.Fields(text)
	if len(words) <= chunkSize {
		return []chunkInfo{{text: text, startOffset: 0}}
	}

	const overlap = 50
	var chunks []chunkInfo
	step := chunkSize - overlap
	if step <= 0 {
		step = chunkSize
	}

	// Build word→byte-offset index
	offsets := wordOffsets(text, words)

	for start := 0; start < len(words); start += step {
		end := start + chunkSize
		if end > len(words) {
			end = len(words)
		}
		chunkWords := words[start:end]
		chunkText := strings.Join(chunkWords, " ")
		byteStart := offsets[start]
		chunks = append(chunks, chunkInfo{text: chunkText, startOffset: byteStart})
		if end == len(words) {
			break
		}
	}
	return chunks
}

// wordOffsets returns the byte offset of each word in text.
func wordOffsets(text string, words []string) []int {
	offsets := make([]int, len(words))
	pos := 0
	for i, w := range words {
		idx := strings.Index(text[pos:], w)
		if idx < 0 {
			offsets[i] = pos
		} else {
			offsets[i] = pos + idx
			pos = pos + idx + len(w)
		}
	}
	return offsets
}

// adjustOffsets re-finds each entity in the originalText starting near chunkOffset.
func adjustOffsets(entities []PIIEntity, originalText string, chunkOffset int) []PIIEntity {
	adjusted := make([]PIIEntity, 0, len(entities))
	for _, e := range entities {
		searchFrom := chunkOffset
		if searchFrom < 0 {
			searchFrom = 0
		}
		idx := strings.Index(originalText[searchFrom:], e.Value)
		if idx == -1 {
			// Fall back to full-text search
			idx = strings.Index(originalText, e.Value)
			if idx == -1 {
				continue // not found in original — hallucination
			}
			e.Start = idx
		} else {
			e.Start = searchFrom + idx
		}
		e.End = e.Start + len(e.Value)
		adjusted = append(adjusted, e)
	}
	return adjusted
}

// maskEntities replaces found entity values with placeholder spaces so the LLM
// doesn't re-detect already-found regex items.
func maskEntities(text string, entities []PIIEntity) string {
	if len(entities) == 0 {
		return text
	}
	runes := []rune(text)
	for _, e := range entities {
		// Convert byte offsets to rune offsets
		runeStart := len([]rune(text[:e.Start]))
		runeEnd := len([]rune(text[:e.End]))
		for i := runeStart; i < runeEnd && i < len(runes); i++ {
			runes[i] = unicode.ReplacementChar
		}
	}
	return string(runes)
}

// Ping checks that the Ollama service is reachable.
func (d *Detector) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.ollamaURL+"/api/tags", nil)
	if err != nil {
		return err
	}
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("ollama unreachable: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ollama returned %d", resp.StatusCode)
	}
	return nil
}

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/yemrealtanay/llm-hasher/internal/vault"
	"github.com/yemrealtanay/llm-hasher/pkg/hasher"
)

// ── Request / Response types ──────────────────────────────────────────────────

type tokenizeRequest struct {
	Text      string `json:"text"`
	ContextID string `json:"context_id,omitempty"`
	// TTL in duration string (e.g. "24h"). "0" or omitted = use server default.
	TTL string `json:"ttl,omitempty"`
}

type tokenizeResponse struct {
	TokenizedText string           `json:"tokenized_text"`
	ContextID     string           `json:"context_id"`
	Entities      []entityResponse `json:"entities,omitempty"`
}

type entityResponse struct {
	Token   string `json:"token"`
	PIIType string `json:"pii_type"`
}

type detokenizeRequest struct {
	Text      string `json:"text"`
	ContextID string `json:"context_id"`
}

type detokenizeResponse struct {
	OriginalText string `json:"original_text"`
}

type batchTokenizeRequest struct {
	Items []tokenizeRequest `json:"items"`
}

type batchTokenizeResponse struct {
	Items []tokenizeResponse `json:"items"`
}

type errResponse struct {
	Error string `json:"error"`
}

// ── Handlers ─────────────────────────────────────────────────────────────────

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if err := s.hasher.Ping(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, errResponse{Error: "ollama unreachable: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleTokenize(w http.ResponseWriter, r *http.Request) {
	var req tokenizeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Text == "" {
		writeJSON(w, http.StatusBadRequest, errResponse{Error: "text is required"})
		return
	}

	expiresAt := parseTTL(req.TTL)
	result, err := s.hasher.Tokenize(r.Context(), req.Text, req.ContextID, expiresAt)
	if err != nil {
		s.logger.Error("tokenize failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, errResponse{Error: err.Error()})
		return
	}

	resp := tokenizeResponse{
		TokenizedText: result.Text,
		ContextID:     result.ContextID,
		Entities:      toEntityResponses(result.Entities),
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleTokenizeBatch(w http.ResponseWriter, r *http.Request) {
	var req batchTokenizeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.Items) == 0 {
		writeJSON(w, http.StatusBadRequest, errResponse{Error: "items must not be empty"})
		return
	}

	results := make([]tokenizeResponse, len(req.Items))
	errs := make([]error, len(req.Items))

	var wg sync.WaitGroup
	for i, item := range req.Items {
		wg.Add(1)
		go func(i int, item tokenizeRequest) {
			defer wg.Done()
			if item.Text == "" {
				errs[i] = errors.New("text is required")
				return
			}
			expiresAt := parseTTL(item.TTL)
			result, err := s.hasher.Tokenize(r.Context(), item.Text, item.ContextID, expiresAt)
			if err != nil {
				errs[i] = err
				return
			}
			results[i] = tokenizeResponse{
				TokenizedText: result.Text,
				ContextID:     result.ContextID,
				Entities:      toEntityResponses(result.Entities),
			}
		}(i, item)
	}
	wg.Wait()

	// Collect first error
	for _, err := range errs {
		if err != nil {
			s.logger.Error("batch tokenize failed", "error", err)
			writeJSON(w, http.StatusInternalServerError, errResponse{Error: err.Error()})
			return
		}
	}

	writeJSON(w, http.StatusOK, batchTokenizeResponse{Items: results})
}

func (s *Server) handleDetokenize(w http.ResponseWriter, r *http.Request) {
	var req detokenizeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Text == "" {
		writeJSON(w, http.StatusBadRequest, errResponse{Error: "text is required"})
		return
	}
	if req.ContextID == "" {
		writeJSON(w, http.StatusBadRequest, errResponse{Error: "context_id is required"})
		return
	}

	original, err := s.hasher.Detokenize(r.Context(), req.Text, req.ContextID)
	if err != nil {
		s.logger.Error("detokenize failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, errResponse{Error: err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, detokenizeResponse{OriginalText: original})
}

func (s *Server) handleDeleteContext(w http.ResponseWriter, r *http.Request) {
	contextID := chi.URLParam(r, "contextID")
	if contextID == "" {
		writeJSON(w, http.StatusBadRequest, errResponse{Error: "context_id is required"})
		return
	}

	if err := s.hasher.DeleteContext(r.Context(), contextID); err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, errResponse{Error: "context not found"})
			return
		}
		s.logger.Error("delete context failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, errResponse{Error: err.Error()})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, errResponse{Error: "invalid JSON: " + err.Error()})
		return false
	}
	return true
}

func toEntityResponses(entities []hasher.DetectedEntity) []entityResponse {
	resp := make([]entityResponse, len(entities))
	for i, e := range entities {
		resp[i] = entityResponse{Token: e.Token, PIIType: e.PIIType}
	}
	return resp
}

// parseTTL converts a duration string to *time.Time (expiry).
// "0" or "" means no expiry (returns nil).
func parseTTL(ttl string) *time.Time {
	if ttl == "" || ttl == "0" {
		return nil
	}
	d, err := time.ParseDuration(ttl)
	if err != nil || d <= 0 {
		return nil
	}
	t := time.Now().Add(d)
	return &t
}

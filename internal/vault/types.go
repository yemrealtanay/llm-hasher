package vault

import "time"

// Context scopes a set of token mappings. The ID is caller-provided (e.g. a
// transcript ID) or auto-generated when the caller doesn't supply one.
type Context struct {
	ID        string
	CreatedAt time.Time
	ExpiresAt *time.Time // nil = no expiry
	Metadata  map[string]string
}

// TokenRecord is one token↔value mapping stored in the vault.
type TokenRecord struct {
	Token          string
	ContextID      string
	PIIType        string
	EncryptedValue []byte // AES-256-GCM: nonce(12B) || ciphertext
	ValueHash      string // HMAC-SHA256 for dedup without decryption
	CreatedAt      time.Time
	ExpiresAt      *time.Time
}

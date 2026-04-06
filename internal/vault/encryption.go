package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

const keySize = 32 // AES-256

// loadOrCreateKey returns the 32-byte master key. Priority:
//  1. VAULT_KEY env var (64 hex chars)
//  2. keyFile path (32 raw bytes or 64 hex chars)
//  3. Auto-generate and persist to keyFile
func loadOrCreateKey(keyFile string) ([keySize]byte, error) {
	var key [keySize]byte

	// 1. Env var
	if raw := os.Getenv("VAULT_KEY"); raw != "" {
		b, err := hex.DecodeString(raw)
		if err != nil || len(b) != keySize {
			return key, fmt.Errorf("VAULT_KEY must be 64 hex chars (32 bytes)")
		}
		copy(key[:], b)
		return key, nil
	}

	// 2. Key file
	if keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err == nil {
			b, hexErr := hex.DecodeString(string(data))
			if hexErr == nil && len(b) == keySize {
				copy(key[:], b)
				return key, nil
			}
			if len(data) == keySize {
				copy(key[:], data)
				return key, nil
			}
			return key, fmt.Errorf("key file %s: expected 32 raw bytes or 64 hex chars", keyFile)
		}
		if !os.IsNotExist(err) {
			return key, fmt.Errorf("read key file: %w", err)
		}
	}

	// 3. Auto-generate
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		return key, fmt.Errorf("generate key: %w", err)
	}

	if keyFile != "" {
		encoded := hex.EncodeToString(key[:])
		if err := os.WriteFile(keyFile, []byte(encoded), 0600); err != nil {
			return key, fmt.Errorf("persist generated key: %w", err)
		}
	}

	return key, nil
}

// encrypt encrypts plaintext with AES-256-GCM. Returns nonce(12B) || ciphertext.
func encrypt(key [keySize]byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decrypt decrypts data produced by encrypt.
func decrypt(key [keySize]byte, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// valueHash computes HMAC-SHA256(key, piiType+":"+value) for dedup lookups
// without requiring decryption of stored records.
func valueHash(key [keySize]byte, piiType, value string) string {
	h := hmac.New(sha256.New, key[:])
	h.Write([]byte(piiType + ":" + value))
	return hex.EncodeToString(h.Sum(nil))
}

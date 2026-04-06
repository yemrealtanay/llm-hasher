package vault

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a token or context does not exist.
var ErrNotFound = errors.New("not found")

// Vault stores and retrieves token↔value mappings.
type Vault struct {
	db  *sql.DB
	key [keySize]byte
}

// Open opens (or creates) a vault at dbPath using keyFile for encryption.
func Open(dbPath, keyFile string) (*Vault, error) {
	key, err := loadOrCreateKey(keyFile)
	if err != nil {
		return nil, fmt.Errorf("vault key: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath+"?_foreign_keys=on&_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate schema: %w", err)
	}

	return &Vault{db: db, key: key}, nil
}

// Close closes the underlying database.
func (v *Vault) Close() error {
	return v.db.Close()
}

// EnsureContext creates a context record if it doesn't exist. Idempotent.
func (v *Vault) EnsureContext(ctx context.Context, id string, expiresAt *time.Time, metadata map[string]string) error {
	meta, _ := json.Marshal(metadata)
	if meta == nil {
		meta = []byte("{}")
	}

	var expiresAtUnix *int64
	if expiresAt != nil {
		ts := expiresAt.UnixMilli()
		expiresAtUnix = &ts
	}

	_, err := v.db.ExecContext(ctx, `
		INSERT OR IGNORE INTO contexts (id, created_at, expires_at, metadata)
		VALUES (?, ?, ?, ?)`,
		id,
		time.Now().UnixMilli(),
		expiresAtUnix,
		string(meta),
	)
	return err
}

// GetContext retrieves a context by ID.
func (v *Vault) GetContext(ctx context.Context, id string) (*Context, error) {
	row := v.db.QueryRowContext(ctx,
		`SELECT id, created_at, expires_at, metadata FROM contexts WHERE id = ?`, id)

	var c Context
	var createdAtMs int64
	var expiresAtMs sql.NullInt64
	var metaJSON string

	if err := row.Scan(&c.ID, &createdAtMs, &expiresAtMs, &metaJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	c.CreatedAt = time.UnixMilli(createdAtMs)
	if expiresAtMs.Valid {
		t := time.UnixMilli(expiresAtMs.Int64)
		c.ExpiresAt = &t
	}
	_ = json.Unmarshal([]byte(metaJSON), &c.Metadata)

	return &c, nil
}

// DeleteContext hard-deletes a context and all its tokens (cascade).
func (v *Vault) DeleteContext(ctx context.Context, id string) error {
	res, err := v.db.ExecContext(ctx, `DELETE FROM contexts WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// Store saves a token mapping. The EncryptedValue field must contain the
// plaintext value — Store encrypts it and computes the dedup hash internally.
// Idempotent — duplicate token is a no-op.
func (v *Vault) Store(ctx context.Context, rec TokenRecord) error {
	plaintext := rec.EncryptedValue // caller passes plaintext; we encrypt here
	enc, err := encrypt(v.key, plaintext)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	hash := valueHash(v.key, rec.PIIType, string(plaintext))

	var expiresAtMs *int64
	if rec.ExpiresAt != nil {
		ts := rec.ExpiresAt.UnixMilli()
		expiresAtMs = &ts
	}

	_, err = v.db.ExecContext(ctx, `
		INSERT OR IGNORE INTO tokens
			(token, context_id, pii_type, encrypted_value, value_hash, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		rec.Token,
		rec.ContextID,
		rec.PIIType,
		enc,
		hash,
		time.Now().UnixMilli(),
		expiresAtMs,
	)
	return err
}

// LookupByToken retrieves a token record and decrypts its value.
func (v *Vault) LookupByToken(ctx context.Context, token string) (*TokenRecord, error) {
	row := v.db.QueryRowContext(ctx, `
		SELECT token, context_id, pii_type, encrypted_value, value_hash, created_at, expires_at
		FROM tokens WHERE token = ?`, token)

	rec, err := v.scanToken(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return rec, nil
}

// LookupByValue finds an existing token for the same context+type+value.
// Returns (record, true, nil) if found, (nil, false, nil) if not found.
func (v *Vault) LookupByValue(ctx context.Context, contextID, piiType, value string) (*TokenRecord, bool, error) {
	hash := valueHash(v.key, piiType, value)

	row := v.db.QueryRowContext(ctx, `
		SELECT token, context_id, pii_type, encrypted_value, value_hash, created_at, expires_at
		FROM tokens
		WHERE context_id = ? AND pii_type = ? AND value_hash = ?
		LIMIT 1`,
		contextID, piiType, hash)

	rec, err := v.scanToken(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return rec, true, nil
}

// ListByContext returns all token records for a context (for bulk detokenization).
func (v *Vault) ListByContext(ctx context.Context, contextID string) ([]TokenRecord, error) {
	rows, err := v.db.QueryContext(ctx, `
		SELECT token, context_id, pii_type, encrypted_value, value_hash, created_at, expires_at
		FROM tokens WHERE context_id = ?`, contextID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []TokenRecord
	for rows.Next() {
		rec, err := v.scanToken(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, *rec)
	}
	return records, rows.Err()
}

// ExpireOld deletes contexts and tokens that have passed their expiry time.
func (v *Vault) ExpireOld(ctx context.Context) error {
	now := time.Now().UnixMilli()
	_, err := v.db.ExecContext(ctx,
		`DELETE FROM contexts WHERE expires_at IS NOT NULL AND expires_at < ?`, now)
	return err
}

// scanner is satisfied by both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func (v *Vault) scanToken(s scanner) (*TokenRecord, error) {
	var rec TokenRecord
	var enc []byte
	var createdAtMs int64
	var expiresAtMs sql.NullInt64

	if err := s.Scan(
		&rec.Token, &rec.ContextID, &rec.PIIType,
		&enc, &rec.ValueHash,
		&createdAtMs, &expiresAtMs,
	); err != nil {
		return nil, err
	}

	plaintext, err := decrypt(v.key, enc)
	if err != nil {
		return nil, fmt.Errorf("decrypt token %s: %w", rec.Token, err)
	}
	rec.EncryptedValue = plaintext // re-use field to carry decrypted value
	rec.CreatedAt = time.UnixMilli(createdAtMs)
	if expiresAtMs.Valid {
		t := time.UnixMilli(expiresAtMs.Int64)
		rec.ExpiresAt = &t
	}
	return &rec, nil
}

// ValueOf returns the plaintext value stored in rec.EncryptedValue after a lookup.
// (After LookupByToken/LookupByValue the field contains the decrypted plaintext.)
func (rec *TokenRecord) ValueOf() string {
	return string(rec.EncryptedValue)
}

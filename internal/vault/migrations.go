package vault

const schema = `
CREATE TABLE IF NOT EXISTS contexts (
    id          TEXT    PRIMARY KEY,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER,
    metadata    TEXT    NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_contexts_expires ON contexts(expires_at)
    WHERE expires_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS tokens (
    token           TEXT    PRIMARY KEY,
    context_id      TEXT    NOT NULL REFERENCES contexts(id) ON DELETE CASCADE,
    pii_type        TEXT    NOT NULL,
    encrypted_value BLOB    NOT NULL,
    value_hash      TEXT    NOT NULL,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER
);

CREATE INDEX IF NOT EXISTS idx_tokens_context    ON tokens(context_id);
CREATE INDEX IF NOT EXISTS idx_tokens_value_hash ON tokens(context_id, pii_type, value_hash);
CREATE INDEX IF NOT EXISTS idx_tokens_expires    ON tokens(expires_at)
    WHERE expires_at IS NOT NULL;
`

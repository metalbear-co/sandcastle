-- Auth tokens (persistent, no expiry)
CREATE TABLE IF NOT EXISTS tokens (
    token TEXT PRIMARY KEY,
    owner_key TEXT NOT NULL,
    created_at BIGINT NOT NULL
);

-- Sandbox registry
CREATE TABLE IF NOT EXISTS sandboxes (
    id TEXT PRIMARY KEY,
    owner_key TEXT NOT NULL,
    provider TEXT NOT NULL,
    work_dir TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sandboxes_owner_key ON sandboxes(owner_key);

-- Active sandbox per owner (upsert-managed)
CREATE TABLE IF NOT EXISTS active_sandboxes (
    owner_key TEXT PRIMARY KEY,
    sandbox_id TEXT NOT NULL
);

-- Short-lived OAuth authorization codes (TTL ~5 min)
CREATE TABLE IF NOT EXISTS pending_codes (
    code TEXT PRIMARY KEY,
    owner_key TEXT NOT NULL,
    client_id TEXT NOT NULL,
    redirect_uri TEXT,
    expire_at BIGINT NOT NULL
);

-- Short-lived IdP redirect state (TTL ~10 min)
CREATE TABLE IF NOT EXISTS pending_auth (
    state TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    redirect_uri TEXT,
    client_state TEXT,
    expire_at BIGINT NOT NULL
);

-- Pending secret upload tokens (used by GCP Secret Manager backend)
CREATE TABLE IF NOT EXISTS secret_upload_tokens (
    token TEXT PRIMARY KEY,
    owner_key TEXT NOT NULL,
    name TEXT NOT NULL,
    expire_at BIGINT NOT NULL
);

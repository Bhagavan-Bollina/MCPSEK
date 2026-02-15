-- mcpsek database schema
-- Run this with: psql -d mcpsek -f migrations/001_initial.sql

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- SERVERS: Every MCP server we know about
-- ============================================================
CREATE TABLE IF NOT EXISTS servers (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name              TEXT NOT NULL,
    source_url        TEXT NOT NULL UNIQUE,    -- GitHub/GitLab repo URL (dedup key)
    package_registry  TEXT,                     -- 'npm', 'pypi', or NULL
    package_name      TEXT,                     -- npm/pypi package name
    description       TEXT,                     -- From package metadata
    author            TEXT,                     -- From package metadata
    license           TEXT,
    stars             INT DEFAULT 0,            -- GitHub stars at last check
    transport         TEXT,                     -- 'stdio', 'sse', 'http', 'unknown'
    tools_count       INT DEFAULT 0,
    trust_score       INT DEFAULT -1,           -- -1 = not yet scanned
    first_seen        TIMESTAMPTZ DEFAULT NOW(),
    last_scanned      TIMESTAMPTZ,
    scan_status       TEXT DEFAULT 'pending',   -- 'pending', 'scanning', 'completed', 'failed'
    scan_error        TEXT,                     -- Error message if scan failed
    created_at        TIMESTAMPTZ DEFAULT NOW(),
    updated_at        TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_servers_name ON servers(name);
CREATE INDEX IF NOT EXISTS idx_servers_trust_score ON servers(trust_score DESC);
CREATE INDEX IF NOT EXISTS idx_servers_scan_status ON servers(scan_status);
CREATE INDEX IF NOT EXISTS idx_servers_package ON servers(package_registry, package_name);

-- Full text search on name + description
CREATE INDEX IF NOT EXISTS idx_servers_search ON servers USING GIN (
    to_tsvector('english', coalesce(name, '') || ' ' || coalesce(description, ''))
);

-- ============================================================
-- SCANS: Each scan is a point-in-time snapshot
-- ============================================================
CREATE TABLE IF NOT EXISTS scans (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id                 UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    scanned_at                TIMESTAMPTZ DEFAULT NOW(),

    -- Check 1: Tool Integrity
    tool_integrity_status     TEXT NOT NULL,     -- 'pass', 'warning', 'critical', 'error'
    tool_integrity_details    JSONB DEFAULT '{}',
    -- Expected JSON structure:
    -- {
    --   "tools_found": 14,
    --   "hidden_instructions": [],        -- list of {tool_name, pattern_matched, snippet}
    --   "suspicious_parameters": [],      -- list of {tool_name, param_name, reason}
    --   "long_descriptions": [],          -- list of {tool_name, char_count}
    --   "cross_tool_references": []       -- list of {tool_name, references_tool}
    -- }

    -- Check 2: Authentication Posture
    auth_status               TEXT NOT NULL,
    auth_details              JSONB DEFAULT '{}',
    -- Expected JSON structure:
    -- {
    --   "method": "oauth2" | "static_key" | "none" | "unknown",
    --   "committed_secrets": [],          -- list of {file_path, secret_type, line_number}
    --   "token_refresh": true | false | null,
    --   "scoped_permissions": true | false | null,
    --   "env_vars_referenced": []         -- list of env var names found
    -- }

    -- Check 3: Endpoint Exposure
    exposure_status           TEXT NOT NULL,
    exposure_details          JSONB DEFAULT '{}',
    -- Expected JSON structure:
    -- {
    --   "transport": "stdio" | "sse" | "http" | "websocket",
    --   "bind_address": "127.0.0.1" | "0.0.0.0" | null,
    --   "tls_configured": true | false | null,
    --   "default_port": 8080 | null
    -- }

    trust_score               INT NOT NULL,      -- 0-100
    tool_definitions_hash     TEXT,               -- SHA256 of all tool defs concatenated
    scan_duration_ms          INT                 -- How long the scan took
);

CREATE INDEX IF NOT EXISTS idx_scans_server_id ON scans(server_id);
CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON scans(scanned_at DESC);

-- ============================================================
-- TOOL_DEFINITIONS: Every tool from every server
-- ============================================================
CREATE TABLE IF NOT EXISTS tool_definitions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id       UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    tool_name       TEXT NOT NULL,
    description     TEXT,
    parameters      JSONB,                    -- The inputSchema
    content_hash    TEXT NOT NULL,             -- SHA256(tool_name + description + parameters)
    first_seen      TIMESTAMPTZ DEFAULT NOW(),
    last_seen       TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(server_id, tool_name, content_hash)
);

CREATE INDEX IF NOT EXISTS idx_tool_defs_server ON tool_definitions(server_id);

-- ============================================================
-- MUTATIONS: When a tool definition changes between scans
-- ============================================================
CREATE TABLE IF NOT EXISTS mutations (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id         UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    tool_name         TEXT NOT NULL,
    old_hash          TEXT NOT NULL,
    new_hash          TEXT NOT NULL,
    old_description   TEXT,
    new_description   TEXT,
    old_parameters    JSONB,
    new_parameters    JSONB,
    severity          TEXT NOT NULL DEFAULT 'info',  -- 'info', 'warning', 'critical'
    severity_reason   TEXT,                           -- Why this severity was assigned
    detected_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mutations_server ON mutations(server_id);
CREATE INDEX IF NOT EXISTS idx_mutations_severity ON mutations(severity);
CREATE INDEX IF NOT EXISTS idx_mutations_detected ON mutations(detected_at DESC);

-- ============================================================
-- SCAN_QUEUE: Servers waiting to be scanned
-- ============================================================
CREATE TABLE IF NOT EXISTS scan_queue (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id       UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    priority        INT DEFAULT 0,            -- Higher = scan sooner
    queued_at       TIMESTAMPTZ DEFAULT NOW(),
    claimed_at      TIMESTAMPTZ,              -- NULL = not yet picked up
    UNIQUE(server_id)                         -- One queue entry per server
);

CREATE INDEX IF NOT EXISTS idx_queue_priority ON scan_queue(priority DESC, queued_at ASC);

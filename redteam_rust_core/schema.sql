-- Consolidada Postgres Schema for redteam_rust_core

CREATE TABLE IF NOT EXISTS scans (
    id SERIAL PRIMARY KEY,
    command_line TEXT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS targets (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    host TEXT NOT NULL,
    ip TEXT,
    status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id),
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence JSONB NOT NULL,
    enrichment JSONB NOT NULL,
    context JSONB NOT NULL,
    timestamps TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS objectives (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL,
    depends_on TEXT,
    priority INTEGER NOT NULL,
    agent_assigned TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS agent_sessions (
    id TEXT PRIMARY KEY,
    agent_role TEXT NOT NULL,
    target_id INTEGER NOT NULL REFERENCES targets(id),
    posture TEXT NOT NULL,
    memory_json TEXT NOT NULL,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS plugin_cache (
    cache_key TEXT PRIMARY KEY,
    output TEXT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS mcp_stats (
    stat_key TEXT PRIMARY KEY,
    stat_value BIGINT DEFAULT 0
);

CREATE TABLE IF NOT EXISTS checkpoints (
    trigger TEXT NOT NULL,
    digest TEXT NOT NULL,
    manifest TEXT NOT NULL,
    content TEXT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(trigger, digest)
);

CREATE TABLE IF NOT EXISTS deduplication (
    finding_hash BYTEA PRIMARY KEY,
    first_seen BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS cve_cache (
    cve_id TEXT PRIMARY KEY,
    json_data TEXT NOT NULL,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- V14.2: Distributed Worker Queue Schema
CREATE TABLE IF NOT EXISTS workers (
    id TEXT PRIMARY KEY,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL -- active, maintenance, offline
);

CREATE TABLE IF NOT EXISTS scan_queue (
    id SERIAL PRIMARY KEY,
    host TEXT NOT NULL,
    target_type TEXT NOT NULL,
    tactical_context JSONB DEFAULT '{}'::jsonb,
    priority INTEGER DEFAULT 1,
    status TEXT DEFAULT 'pending', -- pending, claimed, completed, failed
    claimed_by TEXT REFERENCES workers(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scan_queue_status_priority ON scan_queue(status, priority DESC);

-- V15: Bug Bounty Program Targets Schema
CREATE TABLE IF NOT EXISTS program_targets (
    id SERIAL PRIMARY KEY,
    program_name TEXT NOT NULL,
    platform TEXT NOT NULL, -- h1, bc, intigriti
    host TEXT NOT NULL,
    target_type TEXT NOT NULL,
    is_in_scope BOOLEAN DEFAULT TRUE,
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_program_targets_host ON program_targets(host);
CREATE INDEX IF NOT EXISTS idx_program_targets_program ON program_targets(program_name);

-- V15.1: Temporal Diff Mode Indexes
CREATE INDEX IF NOT EXISTS idx_findings_target_id ON findings(target_id);
CREATE INDEX IF NOT EXISTS idx_targets_host_scan ON targets(host, scan_id);

-- V14.7: Tracks findings already submitted to bug bounty platforms.
CREATE TABLE IF NOT EXISTS submitted_reports (
    id              BIGSERIAL   PRIMARY KEY,
    finding_hash    TEXT        NOT NULL,
    program_handle  TEXT        NOT NULL,
    platform        TEXT        NOT NULL,   -- 'hackerone' | 'bugcrowd' | 'intigriti'
    submission_url  TEXT,                   -- returned URL from platform API on success
    submitted_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_submitted_reports_hash_platform
    ON submitted_reports (finding_hash, platform);

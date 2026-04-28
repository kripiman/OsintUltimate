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

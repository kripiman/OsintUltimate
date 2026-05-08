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

CREATE INDEX idx_scan_queue_status_priority ON scan_queue(status, priority DESC);

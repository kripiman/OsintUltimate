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

CREATE INDEX idx_program_targets_host ON program_targets(host);
CREATE INDEX idx_program_targets_program ON program_targets(program_name);

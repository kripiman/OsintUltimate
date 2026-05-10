-- V14.7: Tracks findings already submitted to bug bounty platforms.
-- Prevents re-submission of the same vulnerability across scans (account ban risk).
-- finding_hash = SHA-256(finding.core.id || '|' || program_handle)

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

-- V15.1: Temporal Diff Mode Indexes
-- These indexes prevent full table scans when checking for historical findings.

CREATE INDEX IF NOT EXISTS idx_findings_target_id ON findings(target_id);
CREATE INDEX IF NOT EXISTS idx_targets_host_scan ON targets(host, scan_id);

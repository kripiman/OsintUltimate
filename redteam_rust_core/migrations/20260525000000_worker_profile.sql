-- V14.3: Add worker_profile to scan_queue for multi-profile worker dispatch (Sprint 10)
ALTER TABLE scan_queue
    ADD COLUMN IF NOT EXISTS worker_profile VARCHAR(32) NOT NULL DEFAULT 'scan';

-- Backward-compatible: existing rows keep 'scan' behavior
-- Rollback: ALTER TABLE scan_queue DROP COLUMN IF EXISTS worker_profile;

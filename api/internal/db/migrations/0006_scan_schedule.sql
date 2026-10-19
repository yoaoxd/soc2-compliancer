-- Scheduled re-scans for Type 2 operational evidence.
ALTER TABLE connections
    ADD COLUMN scan_interval_hours integer NOT NULL DEFAULT 0;

CREATE INDEX idx_connections_due ON connections (scan_interval_hours, last_scanned_at);

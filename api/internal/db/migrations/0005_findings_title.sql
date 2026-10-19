ALTER TABLE findings
    ADD COLUMN title text NOT NULL DEFAULT '';

CREATE INDEX idx_findings_severity ON findings (severity);

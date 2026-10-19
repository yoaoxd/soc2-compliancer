CREATE TABLE connections (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id               uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    provider             text NOT NULL,
    name                 text NOT NULL,
    project_id           text NOT NULL DEFAULT '',
    client_email         text NOT NULL DEFAULT '',
    credentials_encrypted text NOT NULL,
    last_scanned_at      timestamptz,
    created_at           timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_connections_org ON connections (org_id);

CREATE TABLE scans (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    connection_id uuid NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
    project_id    text NOT NULL,
    status        text NOT NULL DEFAULT 'running', -- running | completed | failed
    error         text NOT NULL DEFAULT '',
    findings_count int NOT NULL DEFAULT 0,
    created_at    timestamptz NOT NULL DEFAULT now(),
    completed_at  timestamptz
);

CREATE INDEX idx_scans_org ON scans (org_id, created_at DESC);

CREATE TABLE findings (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    scan_id       uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    connection_id uuid NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
    project_id    text NOT NULL,
    resource_type text NOT NULL,
    resource_name text NOT NULL,
    check_name    text NOT NULL,
    control_codes jsonb NOT NULL DEFAULT '[]'::jsonb,
    severity      text NOT NULL,
    status        text NOT NULL DEFAULT 'open', -- open | remediated | accepted
    evidence      jsonb NOT NULL DEFAULT '{}'::jsonb,
    remediation   jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_findings_scan ON findings (scan_id);
CREATE INDEX idx_findings_org ON findings (org_id, created_at DESC);
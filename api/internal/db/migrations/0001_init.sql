CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE orgs (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text NOT NULL,
    slug       text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email        text NOT NULL UNIQUE,
    display_name text NOT NULL DEFAULT '',
    password     text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE memberships (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       text NOT NULL CHECK (role IN ('admin', 'editor', 'viewer')),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, user_id)
);

-- Versioned SOC2 control catalogs (AICPA Trust Services Criteria).
-- We store our own original summaries of each control, never verbatim AICPA text.
CREATE TABLE controls (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    edition     text NOT NULL,              -- e.g. 'soc2_2017', 'soc2_2025'
    category    text NOT NULL,              -- security | availability | confidentiality | integrity | privacy
    code        text NOT NULL,              -- e.g. 'CC6.1', 'A1.1', 'C1.1'
    title       text NOT NULL,
    description text NOT NULL DEFAULT '',
    UNIQUE (edition, code)
);

-- Maps cloud resource guardrails to SOC2 controls.
CREATE TABLE mappings (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    control_id   uuid NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
    provider     text NOT NULL,             -- gcp | aws | azure
    resource_type text NOT NULL,            -- e.g. 'google_storage_bucket'
    guardrail    text NOT NULL,             -- requirement, e.g. "uniform bucket-level access enabled"
    evidence_type text NOT NULL DEFAULT 'config', -- config | policy | log
    UNIQUE (control_id, provider, resource_type, guardrail)
);

CREATE INDEX idx_mappings_provider ON mappings (provider);
CREATE INDEX idx_memberships_org ON memberships (org_id);
CREATE INDEX idx_memberships_user ON memberships (user_id);
-- CI hook reporting bundle policy results (Phase 3).
CREATE TABLE ci_runs (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    provider   text NOT NULL DEFAULT '',
    tool       text NOT NULL DEFAULT '',  -- checkov | tfsec | other
    status     text NOT NULL DEFAULT 'passed', -- passed | failed
    findings   jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_ci_runs_org ON ci_runs (org_id, created_at DESC);
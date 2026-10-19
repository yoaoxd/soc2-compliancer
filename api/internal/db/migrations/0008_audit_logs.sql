CREATE TABLE audit_logs (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id     uuid REFERENCES users(id) ON DELETE SET NULL,
    action      text NOT NULL,             -- e.g. connection.create, scan.run, org.member.add
    resource    text NOT NULL DEFAULT '',  -- e.g. connection id, scan id
    detail      jsonb NOT NULL DEFAULT '{}'::jsonb,
    ip          text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_org ON audit_logs (org_id, created_at DESC);
CREATE INDEX idx_audit_user ON audit_logs (user_id, created_at DESC);
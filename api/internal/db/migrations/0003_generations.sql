CREATE TABLE generations (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    provider   text NOT NULL,
    components jsonb NOT NULL DEFAULT '[]'::jsonb,
    controls   jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_generations_org ON generations (org_id, created_at DESC);
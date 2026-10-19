ALTER TABLE controls
    ADD COLUMN created_at timestamptz NOT NULL DEFAULT now();

ALTER TABLE mappings
    ADD COLUMN created_at timestamptz NOT NULL DEFAULT now();
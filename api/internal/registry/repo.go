package registry

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repo struct {
	pool *pgxpool.Pool
}

func NewRepo(pool *pgxpool.Pool) *Repo {
	return &Repo{pool: pool}
}

func (r *Repo) ListControls(ctx context.Context, edition, category string) ([]Control, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, edition, category, code, title, description, created_at
		FROM controls
		WHERE ($1 = '' OR edition = $1) AND ($2 = '' OR category = $2)
		ORDER BY case category
			WHEN 'security' THEN 1 WHEN 'availability' THEN 2
			WHEN 'confidentiality' THEN 3 WHEN 'integrity' THEN 4 ELSE 5 END,
			code`, edition, category)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Control
	for rows.Next() {
		var c Control
		if err := rows.Scan(&c.ID, &c.Edition, &c.Category, &c.Code, &c.Title, &c.Description, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (r *Repo) ControlByCode(ctx context.Context, edition, code string) (*Control, error) {
	var c Control
	err := r.pool.QueryRow(ctx, `
		SELECT id, edition, category, code, title, description, created_at
		FROM controls
		WHERE edition = $1 AND code = $2`, edition, code).
		Scan(&c.ID, &c.Edition, &c.Category, &c.Code, &c.Title, &c.Description, &c.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (r *Repo) ListMappings(ctx context.Context, provider string) ([]Mapping, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT m.id, m.control_id, c.code, m.provider, m.resource_type, m.guardrail, m.evidence_type
		FROM mappings m
		JOIN controls c ON c.id = m.control_id
		WHERE ($1 = '' OR m.provider = $1)
		ORDER BY m.provider, m.resource_type, c.code`, provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Mapping
	for rows.Next() {
		var m Mapping
		if err := rows.Scan(&m.ID, &m.ControlID, &m.ControlCode, &m.Provider, &m.ResourceType, &m.Guardrail, &m.EvidenceType); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (r *Repo) UpsertControl(ctx context.Context, edition, category, code, title, description string) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO controls (edition, category, code, title, description)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (edition, code) DO UPDATE SET
			category = EXCLUDED.category,
			title = EXCLUDED.title,
			description = EXCLUDED.description`,
		edition, category, code, title, description)
	return err
}

func (r *Repo) UpsertMapping(ctx context.Context, controlID, provider, resourceType, guardrail, evidenceType string) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO mappings (control_id, provider, resource_type, guardrail, evidence_type)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (control_id, provider, resource_type, guardrail) DO UPDATE SET
			evidence_type = EXCLUDED.evidence_type`,
		controlID, provider, resourceType, guardrail, evidenceType)
	return err
}

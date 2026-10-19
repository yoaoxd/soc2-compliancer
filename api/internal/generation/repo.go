package generation

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type GenerationRecord struct {
	ID         string    `json:"id"`
	OrgID      string    `json:"-"`
	Provider   string    `json:"provider"`
	Components []string  `json:"components"`
	Controls   []string  `json:"controls"`
	CreatedAt  time.Time `json:"created_at"`
}

type Repo struct {
	pool *pgxpool.Pool
}

func NewRepo(pool *pgxpool.Pool) *Repo {
	return &Repo{pool: pool}
}

func (r *Repo) Create(ctx context.Context, orgID, provider string, components, controls []string) (string, error) {
	var id string
	err := r.pool.QueryRow(ctx, `
		INSERT INTO generations (org_id, provider, components, controls)
		VALUES ($1, $2, $3::jsonb, $4::jsonb)
		RETURNING id`,
		orgID, provider, jsonStrings(components), jsonStrings(controls)).
		Scan(&id)
	return id, err
}

func (r *Repo) ListByOrg(ctx context.Context, orgID string) ([]GenerationRecord, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, provider, components, controls, created_at
		FROM generations WHERE org_id = $1
		ORDER BY created_at DESC LIMIT 50`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []GenerationRecord
	for rows.Next() {
		var g GenerationRecord
		g.OrgID = orgID
		if err := rows.Scan(&g.ID, &g.Provider, &g.Components, &g.Controls, &g.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

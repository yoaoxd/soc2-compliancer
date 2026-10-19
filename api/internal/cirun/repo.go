package cirun

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Repo struct {
	pool *pgxpool.Pool
}

func NewRepo(pool *pgxpool.Pool) *Repo {
	return &Repo{pool: pool}
}

func (r *Repo) Create(ctx context.Context, orgID string, in ReportInput) (*Run, error) {
	findings, err := json.Marshal(in.Findings)
	if err != nil {
		return nil, err
	}
	if in.Status == "" {
		in.Status = "passed"
		if len(in.Findings) > 0 {
			in.Status = "failed"
		}
	}
	var run Run
	err = r.pool.QueryRow(ctx, `
		INSERT INTO ci_runs (org_id, provider, tool, status, findings)
		VALUES ($1, $2, $3, $4, $5::jsonb)
		RETURNING id, provider, tool, status, findings, created_at`,
		orgID, in.Provider, in.Tool, in.Status, findings).
		Scan(&run.ID, &run.Provider, &run.Tool, &run.Status, &run.Findings, &run.CreatedAt)
	if err != nil {
		return nil, err
	}
	run.OrgID = orgID
	return &run, nil
}

func (r *Repo) List(ctx context.Context, orgID string, limit int) ([]Run, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, provider, tool, status, findings, created_at
		FROM ci_runs WHERE org_id = $1 ORDER BY created_at DESC LIMIT $2`, orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Run
	for rows.Next() {
		var run Run
		if err := rows.Scan(&run.ID, &run.Provider, &run.Tool, &run.Status, &run.Findings, &run.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, run)
	}
	return out, rows.Err()
}

package evidence

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type controlRow struct {
	Code          string
	Title         string
	Category      string
	EvidenceTypes []string
	Guardrails    int
}

type findingCount struct {
	Code     string
	Severity string
	Count    int
}

type Repo struct {
	pool *pgxpool.Pool
}

func NewRepo(pool *pgxpool.Pool) *Repo {
	return &Repo{pool: pool}
}

// Controls returns the catalog of controls (with their mapped guardrails) for
// the given edition. Edition may be empty to use the org's default.
func (r *Repo) Controls(ctx context.Context, edition string) ([]controlRow, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT c.code, c.title, c.category,
		       COALESCE(ARRAY_AGG(m.evidence_type) FILTER (WHERE m.id IS NOT NULL), '{}'::text[]) AS evidence_types,
		       COUNT(m.id)::int AS guardrails
		FROM controls c
		LEFT JOIN mappings m ON m.control_id = c.id
		WHERE c.edition = $1
		GROUP BY c.code, c.title, c.category, c.edition
		ORDER BY c.category, c.code`, edition)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []controlRow
	for rows.Next() {
		var c controlRow
		if err := rows.Scan(&c.Code, &c.Title, &c.Category, &c.EvidenceTypes, &c.Guardrails); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// FindingsByControl aggregates open findings from the LATEST completed scan per
// connection, so repeated scans don't double count the same posture.
func (r *Repo) FindingsByControl(ctx context.Context, orgID string) (map[string]map[string]int, error) {
	rows, err := r.pool.Query(ctx, `
		WITH latest AS (
			SELECT DISTINCT ON (connection_id) id
			FROM scans
			WHERE org_id = $1 AND status = 'completed'
			ORDER BY connection_id, created_at DESC
		)
		SELECT cc, severity, COUNT(*)::int
		FROM findings f
		JOIN latest l ON l.id = f.scan_id
		CROSS JOIN LATERAL jsonb_array_elements_text(f.control_codes) AS t(cc)
		GROUP BY cc, severity`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]map[string]int{}
	for rows.Next() {
		var code, severity string
		var n int
		if err := rows.Scan(&code, &severity, &n); err != nil {
			return nil, err
		}
		if out[code] == nil {
			out[code] = map[string]int{}
		}
		out[code][severity] = n
	}
	return out, rows.Err()
}

// HasScans reports whether the org has any completed scan on record.
func (r *Repo) HasScans(ctx context.Context, orgID string) (bool, error) {
	var n int
	err := r.pool.QueryRow(ctx, `
		SELECT COUNT(*)::int FROM scans WHERE org_id = $1 AND status = 'completed'`, orgID).Scan(&n)
	return n > 0, err
}

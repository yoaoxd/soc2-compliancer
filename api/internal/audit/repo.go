package audit

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Entry struct {
	ID        string         `json:"id"`
	OrgID     string         `json:"-"`
	UserID    string         `json:"user_id"`
	Action    string         `json:"action"`
	Resource  string         `json:"resource"`
	Detail    map[string]any `json:"detail"`
	IP        string         `json:"ip"`
	CreatedAt time.Time      `json:"created_at"`
}

type Repo struct {
	pool *pgxpool.Pool
}

func NewRepo(pool *pgxpool.Pool) *Repo {
	return &Repo{pool: pool}
}

func (r *Repo) Insert(ctx context.Context, orgID, userID, action, resource, ip string, detail map[string]any) error {
	if detail == nil {
		detail = map[string]any{}
	}
	detailJSON, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	var userIDArg any
	if userID != "" {
		userIDArg = userID
	}
	_, err = r.pool.Exec(ctx, `
		INSERT INTO audit_logs (org_id, user_id, action, resource, detail, ip)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6)`,
		orgID, userIDArg, action, resource, string(detailJSON), ip)
	return err
}

func (r *Repo) ListByOrg(ctx context.Context, orgID string, limit int) ([]Entry, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id, user_id, action, resource, detail, ip, created_at
		FROM audit_logs WHERE org_id = $1
		ORDER BY created_at DESC LIMIT $2`, orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Entry
	for rows.Next() {
		var e Entry
		var detail []byte
		var userID *string
		if err := rows.Scan(&e.ID, &userID, &e.Action, &e.Resource, &detail, &e.IP, &e.CreatedAt); err != nil {
			return nil, err
		}
		if userID != nil {
			e.UserID = *userID
		}
		_ = json.Unmarshal(detail, &e.Detail)
		out = append(out, e)
	}
	return out, rows.Err()
}

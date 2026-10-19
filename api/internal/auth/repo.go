package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("already exists")
)

type Repo struct {
	pool *pgxpool.Pool
}

func NewRepo(pool *pgxpool.Pool) *Repo {
	return &Repo{pool: pool}
}

func (r *Repo) CreateUser(ctx context.Context, email, displayName, passwordHash, ssoProvider string) (*User, error) {
	var pw any
	if passwordHash != "" {
		pw = passwordHash
	}
	row := r.pool.QueryRow(ctx, `
		INSERT INTO users (email, display_name, password, sso_provider)
		VALUES ($1, $2, $3, $4)
		RETURNING id, email, display_name, created_at`,
		email, displayName, pw, ssoProvider)
	return scanUser(row)
}

// CreateSSOUser is an alias used by OAuth flows to keep intent explicit.
func (r *Repo) CreateSSOUser(ctx context.Context, email, displayName, provider string) (*User, error) {
	return r.CreateUser(ctx, email, displayName, "", provider)
}

func (r *Repo) UserByEmail(ctx context.Context, email string) (user *User, passwordHash string, err error) {
	var u User
	var pw *string
	err = r.pool.QueryRow(ctx, `
		SELECT id, email, display_name, created_at, password, sso_provider
		FROM users WHERE email = $1`, email).
		Scan(&u.ID, &u.Email, &u.DisplayName, &u.CreatedAt, &pw, &u.SSOProvider)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", ErrNotFound
	}
	if err != nil {
		return nil, "", err
	}
	if pw != nil {
		passwordHash = *pw
	}
	return &u, passwordHash, nil
}

func (r *Repo) UserByID(ctx context.Context, id string) (*User, error) {
	var u User
	err := r.pool.QueryRow(ctx, `
		SELECT id, email, display_name, created_at, sso_provider FROM users WHERE id = $1`, id).
		Scan(&u.ID, &u.Email, &u.DisplayName, &u.CreatedAt, &u.SSOProvider)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *Repo) CreateOrg(ctx context.Context, name, slug string) (*Org, error) {
	var o Org
	err := r.pool.QueryRow(ctx, `
		INSERT INTO orgs (name, slug) VALUES ($1, $2)
		RETURNING id, name, slug, created_at`, name, slug).
		Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt)
	return &o, err
}

func (r *Repo) AddMembership(ctx context.Context, orgID, userID string, role Role) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO memberships (org_id, user_id, role)
		VALUES ($1, $2, $3)
		ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role`,
		orgID, userID, string(role))
	return err
}

func (r *Repo) Memberships(ctx context.Context, userID string) ([]Membership, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT o.id, o.name, o.slug, o.created_at, m.role, m.created_at
		FROM memberships m
		JOIN orgs o ON o.id = m.org_id
		WHERE m.user_id = $1
		ORDER BY o.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Membership
	for rows.Next() {
		var m Membership
		if err := rows.Scan(&m.Org.ID, &m.Org.Name, &m.Org.Slug, &m.Org.CreatedAt, &m.Role, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (r *Repo) Membership(ctx context.Context, userID, orgID string) (*Membership, error) {
	var m Membership
	err := r.pool.QueryRow(ctx, `
		SELECT o.id, o.name, o.slug, o.created_at, m.role, m.created_at
		FROM memberships m
		JOIN orgs o ON o.id = m.org_id
		WHERE m.user_id = $1 AND m.org_id = $2`, userID, orgID).
		Scan(&m.Org.ID, &m.Org.Name, &m.Org.Slug, &m.Org.CreatedAt, &m.Role, &m.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (r *Repo) SaveOAuthState(ctx context.Context, state, provider string, expiresAt time.Time) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO oauth_states (state, provider, expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (state) DO UPDATE SET expires_at = EXCLUDED.expires_at`,
		state, provider, expiresAt)
	return err
}

// ConsumeOAuthState atomically claims and deletes an unexpired state token.
func (r *Repo) ConsumeOAuthState(ctx context.Context, state string) (bool, error) {
	tag, err := r.pool.Exec(ctx, `
		DELETE FROM oauth_states
		WHERE state = $1 AND expires_at > now()`, state)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (r *Repo) OrgByID(ctx context.Context, orgID string) (*Org, error) {
	var o Org
	err := r.pool.QueryRow(ctx, `SELECT id, name, slug, created_at FROM orgs WHERE id = $1`, orgID).
		Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &o, nil
}

func scanUser(row pgx.Row) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.DisplayName, &u.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: user", ErrConflict)
		}
		return nil, err
	}
	return &u, nil
}

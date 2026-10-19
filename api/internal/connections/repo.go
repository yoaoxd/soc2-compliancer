package connections

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("not found")

type Connection struct {
	ID                string     `json:"id"`
	OrgID             string     `json:"-"`
	Provider          string     `json:"provider"`
	Name              string     `json:"name"`
	ProjectID         string     `json:"project_id"`
	ClientEmail       string     `json:"client_email"`
	ScanIntervalHours int        `json:"scan_interval_hours"`
	LastScannedAt     *time.Time `json:"last_scanned_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
}

type Scan struct {
	ID            string     `json:"id"`
	OrgID         string     `json:"-"`
	ConnectionID  string     `json:"connection_id"`
	ProjectID     string     `json:"project_id"`
	Status        string     `json:"status"`
	Error         string     `json:"error,omitempty"`
	FindingsCount int        `json:"findings_count"`
	CreatedAt     time.Time  `json:"created_at"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
}

type FindingRecord struct {
	ID           string         `json:"id"`
	ScanID       string         `json:"scan_id"`
	ConnectionID string         `json:"connection_id"`
	ProjectID    string         `json:"project_id"`
	ResourceType string         `json:"resource_type"`
	ResourceName string         `json:"resource_name"`
	CheckName    string         `json:"check_name"`
	Title        string         `json:"title"`
	ControlCodes []string       `json:"controls"`
	Severity     string         `json:"severity"`
	Status       string         `json:"status"`
	Evidence     map[string]any `json:"evidence"`
	Remediation  map[string]any `json:"remediation"`
	CreatedAt    time.Time      `json:"created_at"`
}

type Repo struct {
	pool *pgxpool.Pool
}

func NewRepo(pool *pgxpool.Pool) *Repo {
	return &Repo{pool: pool}
}

func (r *Repo) CreateConnection(ctx context.Context, orgID, provider, name, projectID, clientEmail, credentialsEncrypted string, scanIntervalHours int) (*Connection, error) {
	var c Connection
	err := r.pool.QueryRow(ctx, `
		INSERT INTO connections (org_id, provider, name, project_id, client_email, credentials_encrypted, scan_interval_hours)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, provider, name, project_id, client_email, scan_interval_hours, last_scanned_at, created_at`,
		orgID, provider, name, projectID, clientEmail, credentialsEncrypted, scanIntervalHours).
		Scan(&c.ID, &c.Provider, &c.Name, &c.ProjectID, &c.ClientEmail, &c.ScanIntervalHours, &c.LastScannedAt, &c.CreatedAt)
	if err != nil {
		return nil, err
	}
	c.OrgID = orgID
	return &c, nil
}

func (r *Repo) ConnectionByID(ctx context.Context, orgID, id string) (*Connection, error) {
	var c Connection
	err := r.pool.QueryRow(ctx, `
		SELECT id, provider, name, project_id, client_email, scan_interval_hours, last_scanned_at, created_at
		FROM connections WHERE org_id = $1 AND id = $2`, orgID, id).
		Scan(&c.ID, &c.Provider, &c.Name, &c.ProjectID, &c.ClientEmail, &c.ScanIntervalHours, &c.LastScannedAt, &c.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c.OrgID = orgID
	return &c, nil
}

func (r *Repo) ListConnections(ctx context.Context, orgID string) ([]Connection, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, provider, name, project_id, client_email, scan_interval_hours, last_scanned_at, created_at
		FROM connections WHERE org_id = $1 ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Connection
	for rows.Next() {
		var c Connection
		if err := rows.Scan(&c.ID, &c.Provider, &c.Name, &c.ProjectID, &c.ClientEmail, &c.ScanIntervalHours, &c.LastScannedAt, &c.CreatedAt); err != nil {
			return nil, err
		}
		c.OrgID = orgID
		out = append(out, c)
	}
	return out, rows.Err()
}

func (r *Repo) UpdateScanInterval(ctx context.Context, orgID, id string, hours int) (*Connection, error) {
	var c Connection
	err := r.pool.QueryRow(ctx, `
		UPDATE connections SET scan_interval_hours = $3
		WHERE org_id = $1 AND id = $2
		RETURNING id, provider, name, project_id, client_email, scan_interval_hours, last_scanned_at, created_at`,
		orgID, id, hours).
		Scan(&c.ID, &c.Provider, &c.Name, &c.ProjectID, &c.ClientEmail, &c.ScanIntervalHours, &c.LastScannedAt, &c.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c.OrgID = orgID
	return &c, nil
}

// DueConnections lists connections scheduled for a re-scan whose interval has
// elapsed since last_scanned_at (or which have never been scanned).
func (r *Repo) DueConnections(ctx context.Context, now time.Time) ([]Connection, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, org_id, name, project_id, client_email, scan_interval_hours, last_scanned_at
		FROM connections
		WHERE scan_interval_hours > 0
		  AND (last_scanned_at IS NULL OR last_scanned_at <= $1 - make_interval(hours => scan_interval_hours))
		ORDER BY created_at DESC`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Connection
	for rows.Next() {
		var c Connection
		if err := rows.Scan(&c.ID, &c.OrgID, &c.Name, &c.ProjectID, &c.ClientEmail, &c.ScanIntervalHours, &c.LastScannedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (r *Repo) CountConnections(ctx context.Context, orgID string) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx, `SELECT count(*) FROM connections WHERE org_id = $1`, orgID).Scan(&n)
	return n, err
}

// CountScansToday counts scan rows created for the org since local midnight.
func (r *Repo) CountScansToday(ctx context.Context, orgID string) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx, `
		SELECT count(*) FROM scans
		WHERE org_id = $1 AND created_at >= date_trunc('day', now())`, orgID).Scan(&n)
	return n, err
}

// TouchScannedAt records last_scanned_at on a connection.
func (r *Repo) TouchScannedAt(ctx context.Context, id string) error {
	_, err := r.pool.Exec(ctx, `UPDATE connections SET last_scanned_at = now() WHERE id = $1`, id)
	return err
}

func (r *Repo) DeleteConnection(ctx context.Context, orgID, id string) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM connections WHERE org_id = $1 AND id = $2`, orgID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *Repo) DecryptCredentials(ctx context.Context, orgID, id string) (string, error) {
	var enc string
	err := r.pool.QueryRow(ctx, `
		SELECT credentials_encrypted FROM connections WHERE org_id = $1 AND id = $2`, orgID, id).
		Scan(&enc)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return enc, err
}

func (r *Repo) CreateScan(ctx context.Context, orgID, connectionID, projectID string) (*Scan, error) {
	var s Scan
	err := r.pool.QueryRow(ctx, `
		INSERT INTO scans (org_id, connection_id, project_id)
		VALUES ($1, $2, $3)
		RETURNING id, project_id, status, error, findings_count, created_at, completed_at`,
		orgID, connectionID, projectID).
		Scan(&s.ID, &s.ProjectID, &s.Status, &s.Error, &s.FindingsCount, &s.CreatedAt, &s.CompletedAt)
	if err != nil {
		return nil, err
	}
	s.OrgID, s.ConnectionID = orgID, connectionID
	return &s, nil
}

func (r *Repo) FinishScan(ctx context.Context, id string, status, errMsg string, findingsCount int) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE scans SET status = $2, error = $3, findings_count = $4, completed_at = now()
		WHERE id = $1`, id, status, errMsg, findingsCount)
	return err
}

func (r *Repo) InsertFindings(ctx context.Context, orgID, scanID, connectionID, projectID string, findings []FindingRecord) error {
	if len(findings) == 0 {
		return nil
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	for _, f := range findings {
		if _, err := tx.Exec(ctx, `
			INSERT INTO findings (org_id, scan_id, connection_id, project_id, resource_type, resource_name,
				check_name, title, control_codes, severity, status, evidence, remediation)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12::jsonb,$13::jsonb)`,
			orgID, scanID, connectionID, projectID, f.ResourceType, f.ResourceName,
			f.CheckName, f.Title, jsonStrings(f.ControlCodes), f.Severity, "open",
			jsonMap(f.Evidence), jsonMap(f.Remediation)); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (r *Repo) ScanByID(ctx context.Context, orgID, id string) (*Scan, error) {
	var s Scan
	err := r.pool.QueryRow(ctx, `
		SELECT id, connection_id, project_id, status, error, findings_count, created_at, completed_at
		FROM scans WHERE org_id = $1 AND id = $2`, orgID, id).
		Scan(&s.ID, &s.ConnectionID, &s.ProjectID, &s.Status, &s.Error, &s.FindingsCount, &s.CreatedAt, &s.CompletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	s.OrgID = orgID
	return &s, nil
}

func (r *Repo) ListScans(ctx context.Context, orgID string, limit int) ([]Scan, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, connection_id, project_id, status, error, findings_count, created_at, completed_at
		FROM scans WHERE org_id = $1 ORDER BY created_at DESC LIMIT $2`, orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Scan
	for rows.Next() {
		var s Scan
		if err := rows.Scan(&s.ID, &s.ConnectionID, &s.ProjectID, &s.Status, &s.Error, &s.FindingsCount, &s.CreatedAt, &s.CompletedAt); err != nil {
			return nil, err
		}
		s.OrgID = orgID
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *Repo) ListFindings(ctx context.Context, orgID, scanID string, severity string, limit int) ([]FindingRecord, error) {
	query := `
		SELECT id, scan_id, connection_id, project_id, resource_type, resource_name, check_name,
			title, control_codes, severity, status, evidence, remediation, created_at
		FROM findings WHERE org_id = $1 AND scan_id = $2`
	args := []any{orgID, scanID}
	if severity != "" {
		query += ` AND severity = $3`
		args = append(args, severity)
	}
	query += ` ORDER BY created_at DESC LIMIT $4`
	args = append(args, limit)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []FindingRecord
	for rows.Next() {
		var f FindingRecord
		if err := rows.Scan(&f.ID, &f.ScanID, &f.ConnectionID, &f.ProjectID, &f.ResourceType, &f.ResourceName,
			&f.CheckName, &f.Title, &f.ControlCodes, &f.Severity, &f.Status, &f.Evidence, &f.Remediation, &f.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

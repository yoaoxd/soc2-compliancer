package connections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/soc2-compliancer/app/internal/analysis"
	"github.com/soc2-compliancer/app/internal/audit"
	"github.com/soc2-compliancer/app/internal/encrypt"
)

var ErrQuotaExceeded = errors.New("resource quota exceeded")

type Service struct {
	repo              *Repo
	cryp              encrypt.Crypter
	audit             audit.Recorder
	maxConnections    int
	maxScansPerOrgDay int
}

func NewService(repo *Repo, cryp encrypt.Crypter, audit audit.Recorder, maxConnections, maxScansPerOrgDay int) *Service {
	return &Service{
		repo:              repo,
		cryp:              cryp,
		audit:             audit,
		maxConnections:    maxConnections,
		maxScansPerOrgDay: maxScansPerOrgDay,
	}
}

type CreateConnectionInput struct {
	Provider           string `json:"provider"`
	Name               string `json:"name"`
	ServiceAccountJSON string `json:"service_account_json"`
	AWSCredentials     *analysis.AWSCredentials   `json:"aws_credentials"`
	AzureCredentials   *analysis.AzureCredentials `json:"azure_credentials"`
	ScanIntervalHours  int    `json:"scan_interval_hours"`
}

// CreateConnection validates the provider credentials, encrypts them at rest,
// and stores the connection metadata.
func (s *Service) CreateConnection(ctx context.Context, orgID string, in CreateConnectionInput) (*Connection, error) {
	if in.Provider == "" {
		return nil, fmt.Errorf("provider is required")
	}
	if in.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if in.ScanIntervalHours < 0 {
		return nil, fmt.Errorf("scan_interval_hours must be >= 0")
	}
	if s.maxConnections > 0 {
		n, err := s.repo.CountConnections(ctx, orgID)
		if err != nil {
			return nil, err
		}
		if n >= s.maxConnections {
			return nil, ErrQuotaExceeded
		}
	}
	if in.Provider == "aws" {
		if in.AWSCredentials == nil {
			return nil, fmt.Errorf("aws_credentials is required")
		}
		if err := in.AWSCredentials.Valid(); err != nil {
			return nil, err
		}
		raw, err := json.Marshal(in.AWSCredentials)
		if err != nil {
			return nil, err
		}
		enc, err := s.cryp.Encrypt(ctx, raw)
		if err != nil {
			return nil, fmt.Errorf("encrypt credentials: %w", err)
		}
		return s.repo.CreateConnection(ctx, orgID, in.Provider, in.Name, "aws:"+in.AWSCredentials.Region, in.AWSCredentials.AccessKeyID, enc, in.ScanIntervalHours)
	}
	if in.Provider == "azure" {
		if in.AzureCredentials == nil {
			return nil, fmt.Errorf("azure_credentials is required")
		}
		if err := in.AzureCredentials.Valid(); err != nil {
			return nil, err
		}
		raw, err := json.Marshal(in.AzureCredentials)
		if err != nil {
			return nil, err
		}
		enc, err := s.cryp.Encrypt(ctx, raw)
		if err != nil {
			return nil, fmt.Errorf("encrypt credentials: %w", err)
		}
		return s.repo.CreateConnection(ctx, orgID, in.Provider, in.Name, in.AzureCredentials.SubscriptionID, in.AzureCredentials.ClientID, enc, in.ScanIntervalHours)
	}
	sa, err := analysis.ParseServiceAccount([]byte(in.ServiceAccountJSON))
	if err != nil {
		return nil, err
	}
	enc, err := s.cryp.Encrypt(ctx, []byte(in.ServiceAccountJSON))
	if err != nil {
		return nil, fmt.Errorf("encrypt credentials: %w", err)
	}
	return s.repo.CreateConnection(ctx, orgID, in.Provider, in.Name, sa.ProjectID, sa.ClientEmail, enc, in.ScanIntervalHours)
}

func (s *Service) ListConnections(ctx context.Context, orgID string) ([]Connection, error) {
	return s.repo.ListConnections(ctx, orgID)
}

func (s *Service) UpdateScanInterval(ctx context.Context, orgID, id string, hours int) (*Connection, error) {
	if hours < 0 {
		return nil, fmt.Errorf("scan_interval_hours must be >= 0")
	}
	return s.repo.UpdateScanInterval(ctx, orgID, id, hours)
}

func (s *Service) DeleteConnection(ctx context.Context, orgID, id string) error {
	return s.repo.DeleteConnection(ctx, orgID, id)
}

// RunScan decrypts the connection credentials, collects GCP resources, evaluates
// them, and persists the scan + findings. Returns the stored scan record.
func (s *Service) RunScan(ctx context.Context, orgID, connectionID string) (*Scan, error) {
	conn, err := s.repo.ConnectionByID(ctx, orgID, connectionID)
	if err != nil {
		return nil, err
	}
	return s.runScan(ctx, conn)
}

// runScan is the shared scan path used by the API and the scheduler. On failure
// the scan row is recorded as failed for history/evidence.
func (s *Service) runScan(ctx context.Context, conn *Connection) (*Scan, error) {
	if s.maxScansPerOrgDay > 0 {
		n, err := s.repo.CountScansToday(ctx, conn.OrgID)
		if err != nil {
			return nil, err
		}
		if n >= s.maxScansPerOrgDay {
			return nil, ErrQuotaExceeded
		}
	}
	enc, err := s.repo.DecryptCredentials(ctx, conn.OrgID, conn.ID)
	if err != nil {
		return nil, err
	}
	raw, err := s.cryp.Decrypt(ctx, enc)
	if err != nil {
		return nil, fmt.Errorf("decrypt credentials: %w", err)
	}

	scan, err := s.repo.CreateScan(ctx, conn.OrgID, conn.ID, conn.ProjectID)
	if err != nil {
		return nil, err
	}

	var rs *analysis.ResourceSet
	switch conn.Provider {
	case "aws":
		var creds analysis.AWSCredentials
		if err := json.Unmarshal(raw, &creds); err != nil {
			_ = s.repo.FinishScan(ctx, scan.ID, "failed", "invalid aws credentials: "+err.Error(), 0)
			return scan, err
		}
		rs, err = analysis.CollectAWS(ctx, &creds)
	case "azure":
		var creds analysis.AzureCredentials
		if err := json.Unmarshal(raw, &creds); err != nil {
			_ = s.repo.FinishScan(ctx, scan.ID, "failed", "invalid azure credentials: "+err.Error(), 0)
			return scan, err
		}
		rs, err = analysis.CollectAzure(ctx, &creds)
	default:
		sa, perr := analysis.ParseServiceAccount(raw)
		if perr != nil {
			_ = s.repo.FinishScan(ctx, scan.ID, "failed", perr.Error(), 0)
			return scan, perr
		}
		rs, err = analysis.Collect(ctx, sa)
	}
	if err != nil {
		_ = s.repo.FinishScan(ctx, scan.ID, "failed", err.Error(), 0)
		return scan, err
	}

	projectID := rs.ProjectID
	if projectID == "" {
		projectID = rs.AccountID
	}
	findings := analysis.Evaluate(rs)
	records := make([]FindingRecord, 0, len(findings))
	for _, f := range findings {
		records = append(records, FindingRecord{
			ScanID:       scan.ID,
			ConnectionID: conn.ID,
			ProjectID:    projectID,
			ResourceType: f.ResourceType,
			ResourceName: f.ResourceName,
			CheckName:    f.CheckName,
			Title:        f.Title,
			ControlCodes: f.Controls,
			Severity:     f.Severity,
			Evidence:     f.Evidence,
			Remediation: map[string]any{
				"import_command":   f.Remediation.ImportCommand,
				"resource_address": f.Remediation.ResourceAddress,
				"resource_type":    f.Remediation.ResourceType,
				"terraform_config": f.Remediation.TerraformConfig,
				"notes":            f.Remediation.Notes,
			},
		})
	}

	if err := s.repo.InsertFindings(ctx, conn.OrgID, scan.ID, conn.ID, projectID, records); err != nil {
		_ = s.repo.FinishScan(ctx, scan.ID, "failed", err.Error(), 0)
		return scan, err
	}
	if err := s.repo.FinishScan(ctx, scan.ID, "completed", "", len(records)); err != nil {
		return scan, err
	}
	if err := s.repo.TouchScannedAt(ctx, conn.ID); err != nil {
		return scan, err
	}
	if s.audit != nil {
		_ = s.audit.Record(ctx, conn.OrgID, "", "scan.run", scan.ID, map[string]any{
			"connection_id":   conn.ID,
			"provider":        conn.Provider,
			"findings_count":  len(records),
			"result":          "completed",
		})
	}
	return s.repo.ScanByID(ctx, conn.OrgID, scan.ID)
}

func (s *Service) ScanByID(ctx context.Context, orgID, id string) (*Scan, error) {
	return s.repo.ScanByID(ctx, orgID, id)
}

func (s *Service) ListScans(ctx context.Context, orgID string) ([]Scan, error) {
	return s.repo.ListScans(ctx, orgID, 50)
}

func (s *Service) Findings(ctx context.Context, orgID, scanID, severity string) ([]FindingRecord, error) {
	return s.repo.ListFindings(ctx, orgID, scanID, severity, 200)
}

// ScanDue runs one scheduler pass: finds connections whose re-scan interval has
// elapsed and kicks off background scans. Returns how many were started.
func (s *Service) ScanDue(ctx context.Context) (int, error) {
	due, err := s.repo.DueConnections(ctx, time.Now())
	if err != nil {
		return 0, err
	}
	for _, conn := range due {
		conn := conn
		go func() {
			runCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			_, _ = s.runScan(runCtx, &conn)
		}()
	}
	return len(due), nil
}

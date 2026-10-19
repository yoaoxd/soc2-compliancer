package tests

import (
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/soc2-compliancer/app/internal/config"
	"github.com/soc2-compliancer/app/internal/server"
)

func newHandlerWithConfig(t *testing.T, pool *pgxpool.Pool, cfg *config.Config) (http.Handler, func()) {
	t.Helper()
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = "127.0.0.1:0"
	}
	if cfg.TemplatesDir == "" {
		cfg.TemplatesDir = "testdata/templates"
	}
	if cfg.JWTSecret == "" {
		cfg.JWTSecret = "test-secret"
	}
	srv, err := server.New(cfg, pool)
	if err != nil {
		t.Fatalf("build server: %v", err)
	}
	return srv.Handler(), nil
}

// Quota: with MAX_CONNECTIONS_PER_ORG=1 the second connection is rejected 429.
func TestConnectionQuota(t *testing.T) {
	pool := testDB(t)
	cfg := testConfig()
	cfg.MaxConnectionsPerOrg = 1
	h, _ := newHandlerWithConfig(t, pool, cfg)
	token, orgID := registerAndGetOrg(t, h, "quota@example.com")

	rr, _ := doJSON(t, h, http.MethodPost, "/api/v1/orgs/"+orgID+"/connections", map[string]any{
		"provider": "gcp", "name": "one", "service_account_json": fakeSA,
	}, token)
	if rr.Code != http.StatusCreated {
		t.Fatalf("first connection: want 201, got %d: %s", rr.Code, rr.Body.String())
	}

	rr, _ = doJSON(t, h, http.MethodPost, "/api/v1/orgs/"+orgID+"/connections", map[string]any{
		"provider": "gcp", "name": "two", "service_account_json": fakeSA,
	}, token)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second connection: want 429, got %d: %s", rr.Code, rr.Body.String())
	}
}

// Audit: creating a connection and running a scan records audit_logs rows that
// the org can read back through /audit.
func TestAuditTrail(t *testing.T) {
	pool := testDB(t)
	h := newHandler(t, pool)
	token, orgID := registerAndGetOrg(t, h, "audit@example.com")

	rr, out := doJSON(t, h, http.MethodPost, "/api/v1/orgs/"+orgID+"/connections", map[string]any{
		"provider": "gcp", "name": "audit-conn", "service_account_json": fakeSA,
	}, token)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create connection: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	connID, _ := out["id"].(string)

	rr, _ = doJSON(t, h, http.MethodPost, "/api/v1/orgs/"+orgID+"/connections/"+connID+"/scan", nil, token)
	if rr.Code != http.StatusCreated {
		t.Fatalf("run scan: want 201, got %d: %s", rr.Code, rr.Body.String())
	}

	rr, out = doJSON(t, h, http.MethodGet, "/api/v1/orgs/"+orgID+"/audit", nil, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("audit list: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	logs, _ := out["audit_logs"].([]any)
	if len(logs) < 2 {
		t.Fatalf("expected >=2 audit entries (connection.create, scan.run_api), got %d", len(logs))
	}
	// Newest first: scan.run_api then connection.create.
	first := logs[0].(map[string]any)
	if first["action"] != "scan.run_api" && first["action"] != "scan.run" {
		t.Fatalf("expected scan-related action first, got %v", first["action"])
	}
}

// Robustness: a nil-pool handler list should not be required for non-DB paths.
func TestAuditRequiresMembership(t *testing.T) {
	pool := testDB(t)
	h := newHandler(t, pool)
	token, _ := registerAndGetOrg(t, h, "audit2@example.com")
	_, orgID2 := registerAndGetOrg(t, h, "audit3@example.com")

	rr, _ := doJSON(t, h, http.MethodGet, "/api/v1/orgs/"+orgID2+"/audit", nil, token)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("cross-org audit access: want 403, got %d", rr.Code)
	}
}
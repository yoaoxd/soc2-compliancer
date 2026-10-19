package tests

import (
	"context"
	"net/http"
	"testing"
)

const fakeSA = `{
  "type": "service_account",
  "project_id": "soc2-test-project",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQ\n-----END PRIVATE KEY-----\n",
  "client_email": "analyzer@soc2-test-project.iam.gserviceaccount.com",
  "token_uri": "https://oauth2.googleapis.com/token"
}`

func TestConnectionLifecycle(t *testing.T) {
	pool := testDB(t)
	h := newHandler(t, pool)
	token, orgID := registerAndGetOrg(t, h, "conn@example.com")

	// invalid credentials -> 400, no connection created
	rr, _ := doJSON(t, h, http.MethodPost, "/api/v1/orgs/"+orgID+"/connections", map[string]any{
		"provider": "gcp", "name": "prod-gcp", "service_account_json": "not-json",
	}, token)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("create with bad creds: want 400, got %d", rr.Code)
	}

	// valid credentials -> 201
	rr, out := doJSON(t, h, http.MethodPost, "/api/v1/orgs/"+orgID+"/connections", map[string]any{
		"provider": "gcp", "name": "prod-gcp", "service_account_json": fakeSA,
	}, token)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	connID, _ := out["id"].(string)
	if connID == "" {
		t.Fatal("expected connection id")
	}
	if out["project_id"] != "soc2-test-project" {
		t.Fatalf("expected project_id decoded from SA, got %v", out["project_id"])
	}

	// list
	rr, out = doJSON(t, h, http.MethodGet, "/api/v1/orgs/"+orgID+"/connections", nil, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("list: want 200, got %d", rr.Code)
	}
	if arr, _ := out["connections"].([]any); len(arr) != 1 {
		t.Fatalf("expected 1 connection, got %d", len(arr))
	}

	// scan: credentials are structurally valid but not usable -> scan recorded as failed
	rr, out = doJSON(t, h, http.MethodPost, "/api/v1/orgs/"+orgID+"/connections/"+connID+"/scan", nil, token)
	if rr.Code != http.StatusCreated {
		t.Fatalf("scan: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	scanID, _ := out["id"].(string)
	if scanID == "" {
		t.Fatal("expected scan id")
	}

	// delete connection (cascades scans + findings)
	rr, _ = doJSON(t, h, http.MethodDelete, "/api/v1/orgs/"+orgID+"/connections/"+connID, nil, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("delete: want 200, got %d", rr.Code)
	}
}

func TestConnectionNotFound(t *testing.T) {
	pool := testDB(t)
	h := newHandler(t, pool)
	token, orgID := registerAndGetOrg(t, h, "conn2@example.com")

	rr, _ := doJSON(t, h, http.MethodPost, "/api/v1/orgs/"+orgID+"/connections/00000000-0000-0000-0000-000000000000/scan", nil, token)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("scan unknown connection: want 404, got %d", rr.Code)
	}
}

func TestFindingsPersistenceWithTitle(t *testing.T) {
	pool := testDB(t)
	h := newHandler(t, pool)
	token, orgID := registerAndGetOrg(t, h, "findings@example.com")

	rr, out := doJSON(t, h, http.MethodPost, "/api/v1/orgs/"+orgID+"/connections", map[string]any{
		"provider": "gcp", "name": "findings", "service_account_json": fakeSA,
	}, token)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	connID, _ := out["id"].(string)

	// run a scan to get a real scan row (fake SA fails during collect, but the
	// scan record is created and persisted with status=failed)
	rr, out = doJSON(t, h, http.MethodPost, "/api/v1/orgs/"+orgID+"/connections/"+connID+"/scan", nil, token)
	if rr.Code != http.StatusCreated {
		t.Fatalf("scan: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	scanID, _ := out["id"].(string)
	if scanID == "" {
		t.Fatal("expected scan id")
	}

	// insert a finding directly at the repo level (a fake SA never yields findings)
	var findingID string
	err := pool.QueryRow(context.Background(), `
		INSERT INTO findings (org_id, scan_id, connection_id, project_id, resource_type, resource_name,
			check_name, title, control_codes, severity, status, evidence, remediation)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12::jsonb, $13::jsonb)
		RETURNING id`,
		orgID, scanID, connID, "p",
		"google_storage_bucket", "open-bucket", "storage_bucket_public_binding",
		"Bucket grants public access to allUsers", `["CC6.6"]`, "critical", "open",
		`{"bucket":"open-bucket"}`, `{"import_command":"terraform import x y"}`,
	).Scan(&findingID)
	if err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	if findingID == "" {
		t.Fatal("expected finding id")
	}

	// read back through the API with a severity filter
	rr, out = doJSON(t, h, http.MethodGet,
		"/api/v1/orgs/"+orgID+"/connections/"+connID+"/scans/"+scanID+"/findings?severity=critical",
		nil, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("findings: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	arr, _ := out["findings"].([]any)
	if len(arr) != 1 {
		t.Fatalf("expected 1 critical finding, got %d", len(arr))
	}
	f := arr[0].(map[string]any)
	if f["title"] != "Bucket grants public access to allUsers" {
		t.Fatalf("title mismatch: %v", f["title"])
	}
	if f["severity"] != "critical" || f["check_name"] != "storage_bucket_public_binding" {
		t.Fatalf("unexpected finding fields: %v", f)
	}
	if _, ok := f["remediation"].(map[string]any); !ok {
		t.Fatal("expected remediation object")
	}

	// severity filter excludes medium findings
	rr, out = doJSON(t, h, http.MethodGet,
		"/api/v1/orgs/"+orgID+"/connections/"+connID+"/scans/"+scanID+"/findings?severity=medium",
		nil, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("findings: want 200, got %d", rr.Code)
	}
	arr, _ = out["findings"].([]any)
	if len(arr) != 0 {
		t.Fatalf("expected 0 medium findings, got %d", len(arr))
	}
}

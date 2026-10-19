package tests

import (
	"context"
	"net/http"
	"testing"
)

// TestEvidenceMatrix checks the org-scoped control coverage endpoint, including
// the not_assessed -> gaps transition once a scan exists with findings.
func TestEvidenceMatrix(t *testing.T) {
	pool := testDB(t)
	h := newHandler(t, pool)
	token, orgID := registerAndGetOrg(t, h, "evidence@example.com")

	// never scanned -> every control is not_assessed
	rr, out := doJSON(t, h, http.MethodGet, "/api/v1/orgs/"+orgID+"/evidence/matrix", nil, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("matrix: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if out["scanned"] != false {
		t.Fatalf("expected scanned=false before any scan, got %v", out["scanned"])
	}
	controls, _ := out["controls"].([]any)
	if len(controls) == 0 {
		t.Fatal("expected non-empty control matrix")
	}
	first := controls[0].(map[string]any)
	if first["coverage"] != "not_assessed" {
		t.Fatalf("expected not_assessed, got %v", first["coverage"])
	}

	// create a connection + scan (fake SA -> failed scan record, still a completed-less scan)
	rr, out = doJSON(t, h, http.MethodPost, "/api/v1/orgs/"+orgID+"/connections", map[string]any{
		"provider": "gcp", "name": "evidence", "service_account_json": fakeSA,
	}, token)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	connID, _ := out["id"].(string)
	rr, out = doJSON(t, h, http.MethodPost, "/api/v1/orgs/"+orgID+"/connections/"+connID+"/scan", nil, token)
	if rr.Code != http.StatusCreated {
		t.Fatalf("scan: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	scanID, _ := out["id"].(string)

	// mark the scan completed and add a finding for CC6.6 directly
	if _, err := pool.Exec(context.Background(),
		`UPDATE scans SET status='completed', completed_at=now() WHERE id=$1`, scanID); err != nil {
		t.Fatalf("complete scan: %v", err)
	}
	_, err := pool.Exec(context.Background(), `
		INSERT INTO findings (org_id, scan_id, connection_id, project_id, resource_type, resource_name,
			check_name, title, control_codes, severity, status, evidence, remediation)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12::jsonb,$13::jsonb)`,
		orgID, scanID, connID, "p", "google_storage_bucket", "public-bucket",
		"storage_bucket_public_binding", "Bucket is public", `["CC6.6"]`, "critical", "open",
		`{}`, `{}`)
	if err != nil {
		t.Fatalf("insert finding: %v", err)
	}

	// matrix now shows coverage + gaps with CC6.6 containing a critical finding
	rr, out = doJSON(t, h, http.MethodGet, "/api/v1/orgs/"+orgID+"/evidence/matrix", nil, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("matrix: want 200, got %d", rr.Code)
	}
	if out["scanned"] != true {
		t.Fatalf("expected scanned=true after a completed scan")
	}
	var cc66 map[string]any
	for _, mayberow := range out["controls"].([]any) {
		row := mayberow.(map[string]any)
		if row["code"] == "CC6.6" {
			cc66 = row
		}
	}
	if cc66 == nil {
		t.Fatal("expected CC6.6 in matrix")
	}
	if cc66["coverage"] != "gaps" {
		t.Fatalf("expected CC6.6 gaps, got %v", cc66["coverage"])
	}
	findings := cc66["findings"].(map[string]any)
	if findings["critical"] != float64(1) {
		t.Fatalf("expected 1 critical finding for CC6.6, got %v", findings)
	}
}

func TestCIRunLifecycle(t *testing.T) {
	pool := testDB(t)
	h := newHandler(t, pool)
	token, orgID := registerAndGetOrg(t, h, "ci@example.com")

	// report a failing run
	rr, out := doJSON(t, h, http.MethodPost, "/api/v1/orgs/"+orgID+"/ci-runs", map[string]any{
		"provider": "gcp",
		"tool":     "checkov",
		"findings": []map[string]any{
			{"policy_id": "CKV_GCP_5", "severity": "HIGH", "title": "Bucket not encrypted"},
		},
	}, token)
	if rr.Code != http.StatusCreated {
		t.Fatalf("report: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	if out["status"] != "failed" {
		t.Fatalf("expected default status failed with findings, got %v", out["status"])
	}
	if out["tool"] != "checkov" {
		t.Fatalf("expected tool preserved, got %v", out["tool"])
	}

	// report a passing run (no findings)
	rr, out = doJSON(t, h, http.MethodPost, "/api/v1/orgs/"+orgID+"/ci-runs", map[string]any{
		"provider": "gcp", "tool": "tfsec", "status": "passed",
	}, token)
	if rr.Code != http.StatusCreated {
		t.Fatalf("report pass: want 201, got %d: %s", rr.Code, rr.Body.String())
	}

	// list back newest-first
	rr, out = doJSON(t, h, http.MethodGet, "/api/v1/orgs/"+orgID+"/ci-runs", nil, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("list: want 200, got %d", rr.Code)
	}
	runs := out["runs"].([]any)
	if len(runs) != 2 {
		t.Fatalf("expected 2 runs, got %d", len(runs))
	}
	if runs[0].(map[string]any)["status"] != "passed" {
		t.Fatalf("expected newest (passed) first, got %v", runs[0])
	}
}

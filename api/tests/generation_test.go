package tests

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/soc2-compliancer/app/internal/generation"
)

type sessionResp struct {
	Token       string `json:"token"`
	Memberships []struct {
		Org struct {
			ID string `json:"id"`
		} `json:"org"`
	} `json:"memberships"`
}

func registerAndGetOrg(t *testing.T, h http.Handler, email string) (token, orgID string) {
	t.Helper()
	rr, _ := doJSON(t, h, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"email": email, "password": "supersecret", "display_name": "Tester", "org_name": "Test Org",
	}, "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("register: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var sess sessionResp
	if err := json.Unmarshal(rr.Body.Bytes(), &sess); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	if len(sess.Memberships) == 0 {
		t.Fatal("expected at least one membership")
	}
	return sess.Token, sess.Memberships[0].Org.ID
}

func TestGenerateAPI(t *testing.T) {
	pool := testDB(t)
	h := newHandler(t, pool)
	token, orgID := registerAndGetOrg(t, h, "gen@example.com")

	rr, _ := doJSON(t, h, http.MethodPost, "/api/v1/orgs/"+orgID+"/generations/generate", map[string]any{
		"provider": "gcp",
		"components": []map[string]any{
			{"name": "storage_bucket", "variables": map[string]string{"bucket_name": "my-bucket"}},
		},
	}, token)
	if rr.Code != http.StatusCreated {
		t.Fatalf("generate: want 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var result struct {
		Provider   string   `json:"provider"`
		Components []string `json:"components"`
		Controls   []string `json:"controls"`
		Files      []struct {
			Path    string `json:"path"`
			Content string `json:"content"`
		} `json:"files"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.Provider != "gcp" {
		t.Fatalf("want provider gcp, got %s", result.Provider)
	}
	paths := map[string]bool{}
	for _, f := range result.Files {
		paths[f.Path] = true
		if f.Path == "main.tf" && !strings.Contains(f.Content, `module "storage_bucket"`) {
			t.Fatalf("main.tf missing storage_bucket module:\n%s", f.Content)
		}
		if f.Path == "variables.tf" && !strings.Contains(f.Content, `variable "storage_bucket_bucket_name"`) {
			t.Fatalf("variables.tf missing storage_bucket_bucket_name:\n%s", f.Content)
		}
	}
	for _, want := range []string{"versions.tf", "variables.tf", "main.tf", "outputs.tf", "README.md", "tests/run-checks.sh"} {
		if !paths[want] {
			t.Fatalf("bundle missing %s", want)
		}
	}
	if len(result.Controls) == 0 {
		t.Fatal("expected mapped controls in result")
	}

	rr, _ = doJSON(t, h, http.MethodPost, "/api/v1/orgs/"+orgID+"/generations/generate?format=zip", map[string]any{
		"provider":   "gcp",
		"components": []map[string]any{{"name": "storage_bucket"}},
	}, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("zip generate: want 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/zip") {
		t.Fatalf("want zip content type, got %s", ct)
	}
	if !strings.HasPrefix(rr.Body.String(), "PK") {
		t.Fatal("zip payload does not start with PK magic")
	}

	rr, _ = doJSON(t, h, http.MethodPost, "/api/v1/orgs/"+orgID+"/generations/generate", map[string]any{
		"provider":   "aws",
		"components": []map[string]any{{"name": "storage_bucket"}},
	}, token)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unsupported provider: want 400, got %d", rr.Code)
	}

	rr, _ = doJSON(t, h, http.MethodPost, "/api/v1/orgs/"+orgID+"/generations/generate", map[string]any{
		"provider":   "gcp",
		"components": []map[string]any{{"name": "nonexistent"}},
	}, token)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown component: want 400, got %d", rr.Code)
	}

	rr, _ = doJSON(t, h, http.MethodPost, "/api/v1/orgs/"+orgID+"/generations/generate", map[string]any{
		"provider":   "gcp",
		"components": []map[string]any{},
	}, token)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty selection: want 400, got %d", rr.Code)
	}

	rr, _ = doJSON(t, h, http.MethodGet, "/api/v1/orgs/"+orgID+"/generations", nil, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("list generations: want 200, got %d", rr.Code)
	}
	var records []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &records); err != nil {
		t.Fatalf("decode generations: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 recorded generation, got %d", len(records))
	}
}

// TestGenerateCore validates dependency auto-inclusion and wiring against the
// real template library (no database needed).
func TestGenerateCore(t *testing.T) {
	svc := generation.NewService("../../templates")
	res, err := svc.Generate(t.Context(), generation.Request{
		Provider: "gcp",
		Components: []generation.ComponentInput{
			{Name: "sql_postgres", Variables: map[string]string{"instance_name": "db-1"}},
		},
	})
	if err != nil {
		t.Fatalf("generate sql_postgres: %v", err)
	}

	// kms_key must be auto-included as a dependency.
	hasKMS := false
	for _, c := range res.Components {
		if c == "kms_key" {
			hasKMS = true
		}
	}
	if !hasKMS {
		t.Fatalf("expected kms_key auto-included, got %v", res.Components)
	}
	var warned bool
	for _, w := range res.Warnings {
		if strings.Contains(w, "auto-included") && strings.Contains(w, "kms_key") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("expected auto-include warning, got %v", res.Warnings)
	}

	// kms_key must appear before sql_postgres in the dependency order.
	ki, si := -1, -1
	for i, c := range res.Components {
		if c == "kms_key" {
			ki = i
		}
		if c == "sql_postgres" {
			si = i
		}
	}
	if ki == -1 || si == -1 || ki > si {
		t.Fatalf("kms_key should precede sql_postgres, order=%v", res.Components)
	}

	// wiring: sql_postgres kms_key var must reference module.kms_key.key_id.
	for _, f := range res.Files {
		if f.Path == "main.tf" && !strings.Contains(f.Content, "module.kms_key.key_id") {
			t.Fatalf("expected wired kms reference in main.tf:\n%s", f.Content)
		}
	}

	data, err := res.Zip()
	if err != nil {
		t.Fatalf("zip: %v", err)
	}
	if len(data) < 4 || string(data[0:2]) != "PK" {
		t.Fatal("zip magic missing")
	}
}

// TestGenerateMultiProvider builds one bundle from components across gcp and
// aws, asserting providers are merged, namespaces are prefixed to avoid
// collisions, and both provider blocks land in versions.tf.
func TestGenerateMultiProvider(t *testing.T) {
	svc := generation.NewService("../../templates")
	res, err := svc.Generate(t.Context(), generation.Request{
		Providers: []string{"gcp", "aws"},
		Components: []generation.ComponentInput{
			{Provider: "gcp", Name: "storage_bucket", Variables: map[string]string{"bucket_name": "g-b"}},
			{Provider: "aws", Name: "s3_bucket", Variables: map[string]string{"bucket_name": "a-b"}},
		},
	})
	if err != nil {
		t.Fatalf("generate multi-provider: %v", err)
	}

	if res.Provider != "gcp,aws" {
		t.Fatalf("want provider gcp,aws, got %q", res.Provider)
	}
	if len(res.Providers) != 2 || res.Providers[0] != "gcp" || res.Providers[1] != "aws" {
		t.Fatalf("unexpected providers: %v", res.Providers)
	}

	var versions, main, variables string
	var mods []string
	for _, f := range res.Files {
		switch f.Path {
		case "versions.tf":
			versions = f.Content
		case "main.tf":
			main = f.Content
		case "variables.tf":
			variables = f.Content
		}
		if strings.HasPrefix(f.Path, "modules/") {
			mods = append(mods, f.Path)
		}
	}

	for _, want := range []string{`source  = "hashicorp/google"`, `source  = "hashicorp/aws"`} {
		if !strings.Contains(versions, want) {
			t.Fatalf("versions.tf missing %s:\n%s", want, versions)
		}
	}

	// Module + variable identities must be namespaced to avoid collisions.
	for _, want := range []string{
		`module "gcp_storage_bucket"`,
		`module "aws_s3_bucket"`,
		"var.gcp_storage_bucket_bucket_name",
		"var.aws_s3_bucket_bucket_name",
	} {
		if !strings.Contains(main+"\n"+variables, want) {
			t.Fatalf("bundle missing %s\nmain:\n%s\nvariables:\n%s", want, main, variables)
		}
	}

	// Vendored modules must live under provider-scoped directories.
	if !hasPath(mods, "modules/gcp/storage_bucket/main.tf") || !hasPath(mods, "modules/aws/s3_bucket/main.tf") {
		t.Fatalf("missing provider-scoped vendored modules: %v", mods)
	}
}

func hasPath(paths []string, want string) bool {
	for _, p := range paths {
		if p == want {
			return true
		}
	}
	return false
}

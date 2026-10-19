package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/soc2-compliancer/app/internal/config"
	"github.com/soc2-compliancer/app/internal/db"
	"github.com/soc2-compliancer/app/internal/registry"
	"github.com/soc2-compliancer/app/internal/server"
)

func testConfig() *config.Config {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		url = "postgres://soc2:soc2@localhost:5433/soc2?sslmode=disable"
	}
	return &config.Config{
		HTTPAddr:     "127.0.0.1:0",
		DatabaseURL:  url,
		JWTSecret:    "test-secret",
		JWTTTL:       1,
		TemplatesDir: "testdata/templates",
		LogLevel:     "error",
	}
}

func testDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	cfg := testConfig()
	pool, err := db.Connect(context.Background(), cfg.DatabaseURL)
	if err != nil {
		t.Skipf("database unavailable, skipping test: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := db.RunMigrations(context.Background(), pool); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`TRUNCATE findings, scans, connections, memberships, mappings, controls, orgs, users,
		 audit_logs, oauth_states RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if err := registry.Seed(context.Background(), pool); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return pool
}

func newHandler(t *testing.T, pool *pgxpool.Pool) http.Handler {
	t.Helper()
	srv, err := server.New(testConfig(), pool)
	if err != nil {
		t.Fatalf("build server: %v", err)
	}
	return srv.Handler()
}

func doJSON(t *testing.T, h http.Handler, method, path string, body any, token string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var rd bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = *bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, &rd)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	var out map[string]any
	if rr.Body.Len() > 0 {
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
	}
	return rr, out
}

// TestHealth passes a nil pool because the health endpoint never touches the DB.
func TestHealth(t *testing.T) {
	h := newHandler(t, nil)
	rr, _ := doJSON(t, h, http.MethodGet, "/api/v1/health", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestControlRegistry(t *testing.T) {
	pool := testDB(t)
	h := newHandler(t, pool)

	rr, _ := doJSON(t, h, http.MethodGet, "/api/v1/registry/controls?edition=soc2_2017&category=security", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	var arr []any
	if err := json.Unmarshal(rr.Body.Bytes(), &arr); err != nil {
		t.Fatalf("decode controls: %v", err)
	}
	if len(arr) == 0 {
		t.Fatal("expected a non-empty security control list")
	}

	rr, _ = doJSON(t, h, http.MethodGet, "/api/v1/registry/controls/CC6.1", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200 for CC6.1, got %d", rr.Code)
	}

	rr, _ = doJSON(t, h, http.MethodGet, "/api/v1/registry/mappings?provider=gcp", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200 for mappings, got %d", rr.Code)
	}
}

func TestRegisterLoginFlow(t *testing.T) {
	pool := testDB(t)
	h := newHandler(t, pool)

	email := "tester@example.com"
	rr, out := doJSON(t, h, http.MethodPost, "/api/v1/auth/register", map[string]string{
		"email": email, "password": "supersecret", "display_name": "Tester", "org_name": "Test Org",
	}, "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("register: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	token, _ := out["token"].(string)
	if token == "" {
		t.Fatal("expected a token on register")
	}

	rr, _ = doJSON(t, h, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"email": email, "password": "supersecret",
	}, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("login: want 200, got %d", rr.Code)
	}

	rr, _ = doJSON(t, h, http.MethodGet, "/api/v1/auth/me", nil, token)
	if rr.Code != http.StatusOK {
		t.Fatalf("me: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	rr, _ = doJSON(t, h, http.MethodGet, "/api/v1/auth/me", nil, "invalid.token.value")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("me with bad token: want 401, got %d", rr.Code)
	}
}

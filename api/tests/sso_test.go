package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/soc2-compliancer/app/internal/config"
	"github.com/soc2-compliancer/app/internal/server"
)

// fakeIdP spins up a minimal Google-compatible OAuth server: /auth issues an
// auth URL containing state, /token exchanges code for an access token, and
// /userinfo returns a verified profile.
func fakeIdP(t *testing.T, email string) (srv *httptest.Server, authURL, tokenURL, userinfoURL string) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/auth", func(w http.ResponseWriter, r *http.Request) {
		state := r.URL.Query().Get("state")
		redirect := r.URL.Query().Get("redirect_uri")
		// IdP bounces the browser back to the app's callback with a code.
		http.Redirect(w, r, redirect+"?state="+url.QueryEscape(state)+"&code=fake-code", http.StatusFound)
	})
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fake-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"email":          email,
			"email_verified": true,
			"name":           "OAuth Tester",
		})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, srv.URL + "/oauth2/auth", srv.URL + "/oauth2/token", srv.URL + "/userinfo"
}

func ssoConfig(clientID, clientSecret, redirectURL, webappURL string, domains []string, authURL, tokenURL, userinfoURL string) *config.Config {
	cfg := testConfig()
	cfg.GoogleClientID = clientID
	cfg.GoogleClientSecret = clientSecret
	cfg.OAuthRedirectURL = redirectURL
	cfg.WebappURL = webappURL
	cfg.AllowedDomains = domains
	cfg.GoogleAuthURL = authURL
	cfg.GoogleTokenURL = tokenURL
	cfg.GoogleUserinfoURL = userinfoURL
	return cfg
}

// Full browser flow: /google/start redirects to the IdP, the IdP redirects back
// to /google/callback, and the callback redirects to the webapp with a token.
func TestGoogleSSOFullFlow(t *testing.T) {
	pool := testDB(t)
	_, authURL, tokenURL, userinfoURL := fakeIdP(t, "alice@gmail.com")

	webapp := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(webapp.Close)

	cfg := ssoConfig("test-client", "test-secret", "http://app.test/api/v1/auth/google/callback", webapp.URL, []string{"gmail.com"}, authURL, tokenURL, userinfoURL)
	cfg.EncryptionKey = "sso-test-key"
	srv, err := server.New(cfg, pool)
	if err != nil {
		t.Fatalf("build server: %v", err)
	}
	h := srv.Handler()

	// Step 1: start.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/google/start", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("start: want 302, got %d", rr.Code)
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil || loc.Host == "" {
		t.Fatalf("start: missing redirect location: %v", rr.Header().Get("Location"))
	}
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatal("start: expected state param")
	}

	// Step 2: simulate IdP bounce to the callback.
	cbReq := httptest.NewRequest(http.MethodGet,
		"/api/v1/auth/google/callback?state="+url.QueryEscape(state)+"&code=fake-code", nil)
	cbRR := httptest.NewRecorder()
	h.ServeHTTP(cbRR, cbReq)
	if cbRR.Code != http.StatusFound {
		t.Fatalf("callback: want 302, got %d: %s", cbRR.Code, cbRR.Body.String())
	}
	cbLoc, _ := url.Parse(cbRR.Header().Get("Location"))
	if cbLoc.Host == "" || !strings.HasPrefix(cbLoc.Host, "127.0.0.1") {
		t.Fatalf("callback: expected webapp redirect, got %q", cbRR.Header().Get("Location"))
	}
	token := cbLoc.Query().Get("token")
	if token == "" {
		t.Fatalf("callback: expected token in webapp redirect, got %q", cbRR.Header().Get("Location"))
	}

	// Step 3: token works against /auth/me.
	meRR, meOut := doJSON(t, h, http.MethodGet, "/api/v1/auth/me", nil, token)
	if meRR.Code != http.StatusOK {
		t.Fatalf("me: want 200, got %d: %s", meRR.Code, meRR.Body.String())
	}
	user, _ := meOut["user"].(map[string]any)
	if user["email"] != "alice@gmail.com" {
		t.Fatalf("me: expected alice@gmail.com, got %v", user["email"])
	}
	if user["sso_provider"] != "google" {
		t.Fatalf("me: expected sso_provider google, got %v", user["sso_provider"])
	}
}

// Reuse: a returning SSO user must not get a duplicate org.
func TestGoogleSSOReuseExistingUser(t *testing.T) {
	pool := testDB(t)
	h := newHandler(t, pool)
	_, orgID := registerAndGetOrg(t, h, "bob@gmail.com")

	_, authURL, tokenURL, userinfoURL := fakeIdP(t, "bob@gmail.com")
	webapp := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(webapp.Close)

	cfg := ssoConfig("test-client", "test-secret", "http://app.test/api/v1/auth/google/callback", webapp.URL, []string{"gmail.com"}, authURL, tokenURL, userinfoURL)
	cfg.EncryptionKey = "sso-test-key"
	srv, err := server.New(cfg, pool)
	if err != nil {
		t.Fatalf("build server: %v", err)
	}
	h2 := srv.Handler()

	// Start + callback for the existing user.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/google/start", nil)
	rr := httptest.NewRecorder()
	h2.ServeHTTP(rr, req)
	loc, _ := url.Parse(rr.Header().Get("Location"))
	state := loc.Query().Get("state")

	cbReq := httptest.NewRequest(http.MethodGet,
		"/api/v1/auth/google/callback?state="+url.QueryEscape(state)+"&code=fake-code", nil)
	cbRR := httptest.NewRecorder()
	h2.ServeHTTP(cbRR, cbReq)
	cbLoc, _ := url.Parse(cbRR.Header().Get("Location"))
	token := cbLoc.Query().Get("token")

	meRR, meOut := doJSON(t, h2, http.MethodGet, "/api/v1/auth/me", nil, token)
	if meRR.Code != http.StatusOK {
		t.Fatalf("me: want 200, got %d: %s", meRR.Code, meRR.Body.String())
	}
	orgs, _ := meOut["orgs"].([]any)
	if len(orgs) != 1 {
		t.Fatalf("expected exactly 1 org (no dup), got %d", len(orgs))
	}
	first := orgs[0].(map[string]any)
	if first["id"] != orgID {
		t.Fatalf("expected org id %s preserved, got %v", orgID, first["id"])
	}
}

// Domain allowlist rejects sign-in from a disallowed email.
func TestGoogleSSODomainRejected(t *testing.T) {
	pool := testDB(t)
	_, authURL, tokenURL, userinfoURL := fakeIdP(t, "hacker@evil.com")

	webapp := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(webapp.Close)

	cfg := ssoConfig("test-client", "test-secret", "http://app.test/api/v1/auth/google/callback", webapp.URL, []string{"gmail.com"}, authURL, tokenURL, userinfoURL)
	cfg.EncryptionKey = "sso-test-key"
	srv, err := server.New(cfg, pool)
	if err != nil {
		t.Fatalf("build server: %v", err)
	}
	h := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/google/start", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	loc, _ := url.Parse(rr.Header().Get("Location"))
	state := loc.Query().Get("state")

	cbReq := httptest.NewRequest(http.MethodGet,
		"/api/v1/auth/google/callback?state="+url.QueryEscape(state)+"&code=fake-code", nil)
	cbRR := httptest.NewRecorder()
	h.ServeHTTP(cbRR, cbReq)
	cbLoc, _ := url.Parse(cbRR.Header().Get("Location"))
	if cbLoc.Query().Get("token") != "" {
		t.Fatalf("expected no token for disallowed domain, got %q", cbRR.Header().Get("Location"))
	}
	if cbLoc.Query().Get("error") == "" {
		t.Fatalf("expected error param for disallowed domain, got %q", cbRR.Header().Get("Location"))
	}
}

// CSRF: a callback with an unknown state is rejected.
func TestGoogleSSOInvalidState(t *testing.T) {
	pool := testDB(t)
	_, authURL, tokenURL, userinfoURL := fakeIdP(t, "x@gmail.com")
	webapp := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(webapp.Close)

	cfg := ssoConfig("test-client", "test-secret", "http://app.test/api/v1/auth/google/callback", webapp.URL, nil, authURL, tokenURL, userinfoURL)
	cfg.EncryptionKey = "sso-test-key"
	srv, err := server.New(cfg, pool)
	if err != nil {
		t.Fatalf("build server: %v", err)
	}
	h := srv.Handler()

	cbReq := httptest.NewRequest(http.MethodGet,
		"/api/v1/auth/google/callback?state=forged&code=fake-code", nil)
	cbRR := httptest.NewRecorder()
	h.ServeHTTP(cbRR, cbReq)
	if cbRR.Code != http.StatusFound {
		t.Fatalf("callback: want 302 to webapp, got %d", cbRR.Code)
	}
	loc, _ := url.Parse(cbRR.Header().Get("Location"))
	if loc.Query().Get("error") == "" {
		t.Fatalf("expected error for forged state, got %q", cbRR.Header().Get("Location"))
	}
}
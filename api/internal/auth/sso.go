package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

// ProviderConfig holds everything needed to run one SSO provider flow.
type ProviderConfig struct {
	Name          string // "google"
	ClientID      string
	ClientSecret  string
	RedirectURL   string
	AuthCodeURL   func(state string) string
	ExchangeCode  func(ctx context.Context, code string) (*oauth2.Token, error)
	AllowsEmail   func(email string) bool
	UserinfoURL   string // overrideable for tests
}

// GoogleUser is the verified profile returned by Google's userinfo endpoint.
type GoogleUser struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

var errEmailNotAllowed = errors.New("email domain not allowed")

// googleProvider builds the oauth2 config for Google sign-in.
func (s *Service) googleProvider() (ProviderConfig, error) {
	if s.googleClientID == "" || s.googleClientSecret == "" {
		return ProviderConfig{}, errors.New("google oauth not configured")
	}
	authURL := "https://accounts.google.com/o/oauth2/auth"
	tokenURL := "https://oauth2.googleapis.com/token"
	if s.oauthAuthURL != "" {
		authURL = s.oauthAuthURL
	}
	if s.oauthTokenURL != "" {
		tokenURL = s.oauthTokenURL
	}
	cfg := &oauth2.Config{
		ClientID:     s.googleClientID,
		ClientSecret: s.googleClientSecret,
		RedirectURL:  s.googleRedirect,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		Scopes: []string{"email", "profile"},
	}
	userinfoURL := "https://www.googleapis.com/oauth2/v2/userinfo"
	if s.userinfoURL != "" {
		userinfoURL = s.userinfoURL
	}
	return ProviderConfig{
		Name:         "google",
		AuthCodeURL:  func(state string) string { return cfg.AuthCodeURL(state, oauth2.AccessTypeOffline) },
		ExchangeCode: func(ctx context.Context, code string) (*oauth2.Token, error) { return cfg.Exchange(ctx, code) },
		AllowsEmail:  s.allowsEmail,
		UserinfoURL:  userinfoURL,
	}, nil
}

// allowsEmail is the production allowlist check: empty list allows everyone,
// otherwise the domain (or an exact email) must match an entry, case-insensitive.
func (s *Service) allowsEmail(email string) bool {
	if len(s.allowedDomains) == 0 {
		return true
	}
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	d := strings.ToLower(email[at+1:])
	for _, a := range s.allowedDomains {
		entry := strings.ToLower(strings.TrimPrefix(a, "."))
		if entry == d || strings.EqualFold(a, email) {
			return true
		}
	}
	return false
}

// GoogleAuthURL returns the URL to send the user to and stores CSRF state.
func (s *Service) GoogleAuthURL(ctx context.Context) (string, error) {
	prov, err := s.googleProvider()
	if err != nil {
		return "", err
	}
	state := uuid.NewString()
	if err := s.repo.SaveOAuthState(ctx, state, prov.Name, time.Now().Add(10*time.Minute)); err != nil {
		return "", fmt.Errorf("save oauth state: %w", err)
	}
	return prov.AuthCodeURL(state), nil
}

// GoogleCallback exchanges the authorization code, verifies the email, and
// returns a session for the (existing or newly created) user.
func (s *Service) GoogleCallback(ctx context.Context, state, code string) (*UserSession, error) {
	prov, err := s.googleProvider()
	if err != nil {
		return nil, err
	}
	ok, err := s.repo.ConsumeOAuthState(ctx, state)
	if err != nil {
		return nil, fmt.Errorf("oauth state: %w", err)
	}
	if !ok {
		return nil, errors.New("invalid or expired oauth state")
	}
	tok, err := prov.ExchangeCode(ctx, code)
	if err != nil {
		return nil, errors.New("failed to exchange authorization code")
	}
	gu, err := fetchGoogleUser(ctx, prov.UserinfoURL, tok.AccessToken)
	if err != nil {
		return nil, errors.New("failed to fetch profile")
	}
	if !gu.EmailVerified {
		return nil, errors.New("email not verified by google")
	}
	if prov.AllowsEmail != nil && !prov.AllowsEmail(gu.Email) {
		return nil, errEmailNotAllowed
	}
	return s.sessionForEmail(ctx, gu.Email, gu.Name, "google")
}

// sessionForEmail finds or creates a user by verified email, ensuring they
// belong to at least one org, and returns their session.
func (s *Service) sessionForEmail(ctx context.Context, email, displayName, provider string) (*UserSession, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	user, _, err := s.repo.UserByEmail(ctx, email)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		if displayName == "" {
			displayName = email
		}
		user, err = s.repo.CreateSSOUser(ctx, email, displayName, provider)
		if err != nil {
			if errors.Is(err, ErrConflict) {
				u, _, e := s.repo.UserByEmail(ctx, email)
				if e != nil {
					return nil, e
				}
				user = u
			} else {
				return nil, fmt.Errorf("create sso user: %w", err)
			}
		}
	}
	if err := s.ensureMembership(ctx, user); err != nil {
		return nil, err
	}
	return s.Me(ctx, user.ID)
}

// ensureMembership gives a new SSO user at least one org so the dashboard has
// somewhere to land; rejoining users keep their existing orgs.
func (s *Service) ensureMembership(ctx context.Context, user *User) error {
	memberships, err := s.repo.Memberships(ctx, user.ID)
	if err != nil {
		return err
	}
	if len(memberships) > 0 {
		return nil
	}
	org, err := s.createOrgUnique(ctx, displayOrgName(user.DisplayName, user.Email))
	if err != nil {
		return fmt.Errorf("create org: %w", err)
	}
	return s.repo.AddMembership(ctx, org.ID, user.ID, RoleAdmin)
}

func displayOrgName(displayName, email string) string {
	if strings.TrimSpace(displayName) == "" {
		return strings.Split(email, "@")[0] + "'s Org"
	}
	return displayName + "'s Org"
}

// fetchGoogleUser calls the userinfo endpoint with the access token.
func fetchGoogleUser(ctx context.Context, userinfoURL, accessToken string) (*GoogleUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		return nil, fmt.Errorf("userinfo endpoint returned %d: %s", res.StatusCode, string(b))
	}
	var gu GoogleUser
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&gu); err != nil {
		return nil, err
	}
	return &gu, nil
}
package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type Service struct {
	repo             *Repo
	jwtSecret        []byte
	ttl              time.Duration
	googleClientID   string
	googleClientSecret string
	googleRedirect   string
	webappURL        string
	allowedDomains   []string
	oauthAuthURL     string // test overrides (Google endpoints)
	oauthTokenURL    string
	userinfoURL      string
}

type Claims struct {
	UserID string `json:"uid"`
	jwt.RegisteredClaims
}

func NewService(repo *Repo, jwtSecret string, ttlHours int) *Service {
	return &Service{
		repo:      repo,
		jwtSecret: []byte(jwtSecret),
		ttl:       time.Duration(ttlHours) * time.Hour,
	}
}

// WithSSO wires optional Google OAuth provider settings into the service.
func (s *Service) WithSSO(clientID, clientSecret, redirectURL, webappURL string, allowedDomains []string) *Service {
	s.googleClientID = clientID
	s.googleClientSecret = clientSecret
	s.googleRedirect = redirectURL
	s.webappURL = webappURL
	s.allowedDomains = allowedDomains
	return s
}

func (s *Service) Register(ctx context.Context, email, password, displayName, orgName string) (*UserSession, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || len(password) < 8 {
		return nil, errors.New("invalid email or password (min 8 chars)")
	}
	if displayName == "" {
		displayName = email
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	if orgName == "" {
		orgName = displayName + "'s Org"
	}

	user, err := s.repo.CreateUser(ctx, email, displayName, string(hash), "")
	if err != nil {
		if errors.Is(err, ErrConflict) {
			return nil, fmt.Errorf("email already registered")
		}
		return nil, err
	}

	org, err := s.createOrgUnique(ctx, orgName)
	if err != nil {
		return nil, fmt.Errorf("create org: %w", err)
	}
	if err := s.repo.AddMembership(ctx, org.ID, user.ID, RoleAdmin); err != nil {
		return nil, fmt.Errorf("add membership: %w", err)
	}
	return s.session(ctx, user, org)
}

func (s *Service) Login(ctx context.Context, email, password string) (*UserSession, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	user, hash, err := s.repo.UserByEmail(ctx, email)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}
	if hash == "" {
		return nil, errors.New("use google sign-in for this account")
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return nil, errors.New("invalid credentials")
	}
	memberships, err := s.repo.Memberships(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	return s.buildSession(user, memberships)
}

func (s *Service) Me(ctx context.Context, userID string) (*UserSession, error) {
	user, err := s.repo.UserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	memberships, err := s.repo.Memberships(ctx, userID)
	if err != nil {
		return nil, err
	}
	return s.buildSession(user, memberships)
}

func (s *Service) CreateOrg(ctx context.Context, userID, name string) (*Membership, error) {
	org, err := s.createOrgUnique(ctx, name)
	if err != nil {
		return nil, err
	}
	if err := s.repo.AddMembership(ctx, org.ID, userID, RoleAdmin); err != nil {
		return nil, err
	}
	return s.repo.Membership(ctx, userID, org.ID)
}

// createOrgUnique creates an org, de-duplicating the slug on unique-violation.
func (s *Service) createOrgUnique(ctx context.Context, name string) (*Org, error) {
	slug := slugify(name)
	for i := 0; i < 5; i++ {
		candidate := slug
		if i > 0 {
			candidate = fmt.Sprintf("%s-%d", slug, i+1)
		}
		org, err := s.repo.CreateOrg(ctx, name, candidate)
		if err == nil {
			return org, nil
		}
		if !strings.Contains(err.Error(), "23505") {
			return nil, err
		}
	}
	return s.repo.CreateOrg(ctx, name, slug+"-"+uuid.NewString()[:6])
}

func (s *Service) AddMember(ctx context.Context, userID, orgID, email string, role Role) error {
	membership, err := s.repo.Membership(ctx, userID, orgID)
	if err != nil {
		return err
	}
	if membership.Role != RoleAdmin {
		return errors.New("admin role required")
	}
	if role != RoleAdmin && role != RoleEditor && role != RoleViewer {
		return errors.New("invalid role")
	}
	target, _, err := s.repo.UserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return errors.New("user not found")
		}
		return err
	}
	return s.repo.AddMembership(ctx, orgID, target.ID, role)
}

// WithOAuthEndpoints overrides the default Google authorization/token/userinfo
// endpoints. Intended for tests (httptest servers) and self-hosted IdPs.
func (s *Service) WithOAuthEndpoints(authURL, tokenURL, userinfoURL string) *Service {
	s.oauthAuthURL = authURL
	s.oauthTokenURL = tokenURL
	s.userinfoURL = userinfoURL
	return s
}

func (s *Service) session(ctx context.Context, user *User, org *Org) (*UserSession, error) {
	memberships, err := s.repo.Memberships(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	sess, err := s.buildSession(user, memberships)
	if err != nil {
		return nil, err
	}
	return sess, nil
}

func (s *Service) buildSession(user *User, memberships []Membership) (*UserSession, error) {
	token, err := s.issueToken(user.ID)
	if err != nil {
		return nil, err
	}
	orgs := make([]Org, 0, len(memberships))
	for _, m := range memberships {
		orgs = append(orgs, m.Org)
	}
	return &UserSession{User: *user, Orgs: orgs, Memberships: memberships, Token: token}, nil
}

func (s *Service) issueToken(userID string) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.ttl)),
			ID:        uuid.NewString(),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.jwtSecret)
}

// ParseToken validates a bearer token and returns the user id.
func (s *Service) ParseToken(tokenString string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return s.jwtSecret, nil
	})
	if err != nil {
		return "", err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return "", errors.New("invalid token")
	}
	return claims.UserID, nil
}

func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_':
			b.WriteByte('-')
		}
	}
	slug := strings.Trim(b.String(), "-")
	if slug == "" {
		slug = uuid.NewString()[:8]
	}
	return slug
}

package audit

import (
	"context"
	"net"
	"net/http"
	"strings"
)

// Recorder writes audit trail entries. Services depend on this interface so
// tests can pass a no-op recorder.
type Recorder interface {
	// Record logs an action performed by a user (may be empty for system
	// actions, e.g. scheduled scans) within orgID.
	Record(ctx context.Context, orgID, userID, action, resource string, detail map[string]any) error
}

type Service struct {
	repo *Repo
}

func NewService(repo *Repo) *Service {
	return &Service{repo: repo}
}

func (s *Service) Record(ctx context.Context, orgID, userID, action, resource string, detail map[string]any) error {
	if s == nil || s.repo == nil || orgID == "" || action == "" {
		return nil
	}
	return s.repo.Insert(ctx, orgID, userID, action, resource, "", detail)
}

// RecordReq records an action for the org/user in the request context.
func (s *Service) RecordReq(r *http.Request, orgID, userID, action, resource string, detail map[string]any) error {
	if s == nil || s.repo == nil {
		return nil
	}
	return s.repo.Insert(r.Context(), orgID, userID, action, resource, ClientIP(r), detail)
}

func (s *Service) List(ctx context.Context, orgID string, limit int) ([]Entry, error) {
	return s.repo.ListByOrg(ctx, orgID, limit)
}

// ClientIP derives the remote address from the request, falling back to the
// X-Forwarded-For / X-Real-IP headers when behind a proxy.
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if first := strings.TrimSpace(strings.Split(xff, ",")[0]); first != "" {
			return first
		}
	}
	if xr := r.Header.Get("X-Real-IP"); xr != "" {
		return strings.TrimSpace(xr)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
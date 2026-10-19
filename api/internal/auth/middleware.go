package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/soc2-compliancer/app/internal/web"
)

type ctxKey string

const (
	ctxUserID ctxKey = "user_id"
	ctxOrgID  ctxKey = "org_id"
	roleKey   ctxKey = "role"
)

func UserID(ctx context.Context) string {
	v, _ := ctx.Value(ctxUserID).(string)
	return v
}

func OrgID(ctx context.Context) string {
	v, _ := ctx.Value(ctxOrgID).(string)
	return v
}

func RoleFromContext(ctx context.Context) Role {
	v, _ := ctx.Value(roleKey).(Role)
	return v
}

// Middleware validates the bearer JWT and injects the user id into the context.
func (s *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if header == "" || !strings.HasPrefix(header, "Bearer ") {
			web.WriteError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		userID, err := s.ParseToken(strings.TrimPrefix(header, "Bearer "))
		if err != nil {
			web.WriteError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		ctx := context.WithValue(r.Context(), ctxUserID, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// OrgMiddleware resolves the org from the request path and verifies membership.
// It must be mounted under a route with an {orgID} path parameter.
func (s *Service) OrgMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		orgID := web.PathValue(r, "orgID")
		userID := UserID(r.Context())
		if orgID == "" {
			web.WriteError(w, http.StatusBadRequest, "missing org id")
			return
		}
		m, err := s.repo.Membership(r.Context(), userID, orgID)
		if err != nil {
			if err == ErrNotFound {
				web.WriteError(w, http.StatusForbidden, "not a member of this org")
				return
			}
			web.WriteError(w, http.StatusInternalServerError, "internal error")
			return
		}
		ctx := context.WithValue(r.Context(), ctxOrgID, m.Org.ID)
		ctx = context.WithValue(ctx, roleKey, m.Role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

package auth

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
	"github.com/soc2-compliancer/app/internal/web"
)

func (s *Service) Routes() http.Handler {
	r := chi.NewRouter()
	r.Post("/register", s.handleRegister)
	r.Post("/login", s.handleLogin)
	r.Get("/google/start", s.handleGoogleStart)
	r.Get("/google/callback", s.handleGoogleCallback)
	r.Group(func(r chi.Router) {
		r.Use(s.Middleware)
		r.Get("/me", s.handleMe)
		r.Post("/orgs", s.handleCreateOrg)
		r.Route("/orgs/{orgID}", func(r chi.Router) {
			r.Use(s.OrgMiddleware)
			r.Post("/members", s.handleAddMember)
		})
	})
	return r
}

type registerRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
	OrgName     string `json:"org_name"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type addMemberRequest struct {
	Email string `json:"email"`
	Role  Role   `json:"role"`
}

func (s *Service) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := decode(w, r, &req); err != nil {
		return
	}
	sess, err := s.Register(r.Context(), req.Email, req.Password, req.DisplayName, req.OrgName)
	if err != nil {
		web.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	web.WriteJSON(w, http.StatusCreated, sess)
}

func (s *Service) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decode(w, r, &req); err != nil {
		return
	}
	sess, err := s.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		web.WriteError(w, http.StatusUnauthorized, err.Error())
		return
	}
	web.WriteJSON(w, http.StatusOK, sess)
}

func (s *Service) handleGoogleStart(w http.ResponseWriter, r *http.Request) {
	url, err := s.GoogleAuthURL(r.Context())
	if err != nil {
		web.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	http.Redirect(w, r, url, http.StatusFound)
}

func (s *Service) handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		s.redirectToWebapp(w, r, "?error="+url.QueryEscape("missing state or code"))
		return
	}
	sess, err := s.GoogleCallback(r.Context(), state, code)
	if err != nil {
		s.redirectToWebapp(w, r, "?error="+url.QueryEscape(err.Error()))
		return
	}
	s.redirectToWebapp(w, r, "?token="+url.QueryEscape(sess.Token))
}

// redirectToWebapp bounces the browser back to the configured webapp URL with
// the session token (or error) as query params. Falls back to JSON when no
// webapp URL is configured (headless/API use).
func (s *Service) redirectToWebapp(w http.ResponseWriter, r *http.Request, query string) {
	if s.webappURL == "" {
		web.WriteError(w, http.StatusBadRequest, "oauth callback failed or webapp url unset")
		return
	}
	http.Redirect(w, r, s.webappURL+query, http.StatusFound)
}

func (s *Service) handleMe(w http.ResponseWriter, r *http.Request) {
	sess, err := s.Me(r.Context(), UserID(r.Context()))
	if err != nil {
		web.WriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	web.WriteJSON(w, http.StatusOK, sess)
}

func (s *Service) handleCreateOrg(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := decode(w, r, &req); err != nil {
		return
	}
	m, err := s.CreateOrg(r.Context(), UserID(r.Context()), req.Name)
	if err != nil {
		web.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	web.WriteJSON(w, http.StatusCreated, m)
}

func (s *Service) handleAddMember(w http.ResponseWriter, r *http.Request) {
	var req addMemberRequest
	if err := decode(w, r, &req); err != nil {
		return
	}
	err := s.AddMember(r.Context(), UserID(r.Context()), OrgID(r.Context()), req.Email, req.Role)
	if err != nil {
		web.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	web.WriteJSON(w, http.StatusOK, map[string]string{"status": "added"})
}

func decode(w http.ResponseWriter, r *http.Request, dst any) error {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		web.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return err
	}
	return nil
}

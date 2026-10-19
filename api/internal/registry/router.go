package registry

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/soc2-compliancer/app/internal/web"
)

type Service struct {
	repo *Repo
}

func NewService(repo *Repo) *Service {
	return &Service{repo: repo}
}

func (s *Service) Routes() http.Handler {
	r := chi.NewRouter()
	r.Get("/controls", s.handleListControls)
	r.Get("/controls/{code}", s.handleGetControl)
	r.Get("/mappings", s.handleListMappings)
	return r
}

func (s *Service) handleListControls(w http.ResponseWriter, r *http.Request) {
	edition := r.URL.Query().Get("edition")
	category := r.URL.Query().Get("category")
	controls, err := s.repo.ListControls(r.Context(), edition, category)
	if err != nil {
		web.WriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	web.WriteJSON(w, http.StatusOK, controls)
}

func (s *Service) handleGetControl(w http.ResponseWriter, r *http.Request) {
	edition := r.URL.Query().Get("edition")
	if edition == "" {
		edition = Edition2017
	}
	code := chi.URLParam(r, "code")
	c, err := s.repo.ControlByCode(r.Context(), edition, code)
	if err != nil {
		if err == ErrNotFound {
			web.WriteError(w, http.StatusNotFound, "control not found")
			return
		}
		web.WriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	web.WriteJSON(w, http.StatusOK, c)
}

func (s *Service) handleListMappings(w http.ResponseWriter, r *http.Request) {
	provider := r.URL.Query().Get("provider")
	mappings, err := s.repo.ListMappings(r.Context(), provider)
	if err != nil {
		web.WriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	web.WriteJSON(w, http.StatusOK, mappings)
}

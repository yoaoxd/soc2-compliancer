package catalog

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/soc2-compliancer/app/internal/web"
)

type Service struct {
	templatesDir string
}

func NewService(templatesDir string) *Service {
	return &Service{templatesDir: templatesDir}
}

func (s *Service) Routes() http.Handler {
	r := chi.NewRouter()
	r.Get("/providers", s.handleListProviders)
	return r
}

func (s *Service) handleListProviders(w http.ResponseWriter, r *http.Request) {
	providers, err := Load(s.templatesDir)
	if err != nil {
		web.WriteError(w, http.StatusInternalServerError, "failed to load template catalog")
		return
	}
	providers = Filter(providers, r.URL.Query().Get("category"), r.URL.Query().Get("resource_type"))
	web.WriteJSON(w, http.StatusOK, providers)
}

package generation

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/soc2-compliancer/app/internal/auth"
	"github.com/soc2-compliancer/app/internal/web"
)

type Handler struct {
	gen  *Service
	repo *Repo
}

func NewHandler(templatesDir string, repo *Repo) *Handler {
	return &Handler{gen: NewService(templatesDir), repo: repo}
}

func (h *Handler) Routes() http.Handler {
	r := chi.NewRouter()
	r.Post("/generations/generate", h.handleGenerate)
	r.Get("/generations", h.handleList)
	return r
}

func (h *Handler) handleGenerate(w http.ResponseWriter, r *http.Request) {
	orgID := auth.OrgID(r.Context())
	var req Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		web.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	result, err := h.gen.Generate(r.Context(), req)
	if err != nil {
		web.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	if r.URL.Query().Get("format") == "zip" {
		data, err := result.Zip()
		if err != nil {
			web.WriteError(w, http.StatusInternalServerError, "failed to build zip")
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", "attachment; filename=soc2-bundle.zip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
		return
	}

	if _, err := h.repo.Create(r.Context(), orgID, result.Provider, result.Components, result.Controls); err != nil {
		web.WriteError(w, http.StatusInternalServerError, "failed to record generation")
		return
	}
	web.WriteJSON(w, http.StatusCreated, result)
}

func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	orgID := auth.OrgID(r.Context())
	records, err := h.repo.ListByOrg(r.Context(), orgID)
	if err != nil {
		web.WriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	web.WriteJSON(w, http.StatusOK, records)
}

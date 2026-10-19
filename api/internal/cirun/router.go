package cirun

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/soc2-compliancer/app/internal/auth"
	"github.com/soc2-compliancer/app/internal/web"
)

type Handler struct {
	repo *Repo
}

func NewHandler(repo *Repo) *Handler {
	return &Handler{repo: repo}
}

func (h *Handler) Routes() http.Handler {
	r := chi.NewRouter()
	r.Post("/", h.handleReport)
	r.Get("/", h.handleList)
	return r
}

func (h *Handler) handleReport(w http.ResponseWriter, r *http.Request) {
	var in ReportInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		web.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if in.Provider == "" {
		web.WriteError(w, http.StatusBadRequest, "provider is required")
		return
	}
	orgID := auth.OrgID(r.Context())
	run, err := h.repo.Create(r.Context(), orgID, in)
	if err != nil {
		web.WriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	web.WriteJSON(w, http.StatusCreated, run)
}

func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	orgID := auth.OrgID(r.Context())
	runs, err := h.repo.List(r.Context(), orgID, 50)
	if err != nil {
		web.WriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	web.WriteJSON(w, http.StatusOK, map[string]any{"runs": runs})
}

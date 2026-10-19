package audit

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/soc2-compliancer/app/internal/auth"
	"github.com/soc2-compliancer/app/internal/web"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) Routes() http.Handler {
	r := chi.NewRouter()
	r.Get("/", h.handleList)
	return r
}

func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	orgID := auth.OrgID(r.Context())
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	entries, err := h.svc.List(r.Context(), orgID, limit)
	if err != nil {
		web.WriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	web.WriteJSON(w, http.StatusOK, map[string]any{"audit_logs": entries})
}
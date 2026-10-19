package connections

import (
	"encoding/json"
	"net/http"

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
	r.Post("/", h.handleCreate)
	r.Patch("/{connectionID}", h.handleUpdateInterval)
	r.Post("/{connectionID}/scan", h.handleRunScan)
	r.Delete("/{connectionID}", h.handleDelete)
	r.Get("/{connectionID}/scans", h.handleScans)
	r.Get("/{connectionID}/scans/{scanID}", h.handleScan)
	r.Get("/{connectionID}/scans/{scanID}/findings", h.handleFindings)
	return r
}

func (h *Handler) auditReq(r *http.Request, action, resource string, detail map[string]any) {
	if h.svc.audit == nil {
		return
	}
	_ = h.svc.audit.Record(r.Context(), auth.OrgID(r.Context()), auth.UserID(r.Context()), action, resource, detail)
}

func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	orgID := auth.OrgID(r.Context())
	conns, err := h.svc.ListConnections(r.Context(), orgID)
	if err != nil {
		web.WriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	web.WriteJSON(w, http.StatusOK, map[string]any{"connections": conns})
}

func (h *Handler) handleCreate(w http.ResponseWriter, r *http.Request) {
	var in CreateConnectionInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		web.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	orgID := auth.OrgID(r.Context())
	conn, err := h.svc.CreateConnection(r.Context(), orgID, in)
	if err != nil {
		if err == ErrQuotaExceeded {
			web.WriteError(w, http.StatusTooManyRequests, err.Error())
			return
		}
		web.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	web.WriteJSON(w, http.StatusCreated, conn)
	h.auditReq(r, "connection.create", conn.ID, map[string]any{"provider": conn.Provider, "name": conn.Name})
}

func (h *Handler) handleUpdateInterval(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ScanIntervalHours int `json:"scan_interval_hours"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		web.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	orgID := auth.OrgID(r.Context())
	connID := web.PathValue(r, "connectionID")
	conn, err := h.svc.UpdateScanInterval(r.Context(), orgID, connID, in.ScanIntervalHours)
	if err != nil {
		if err == ErrNotFound {
			web.WriteError(w, http.StatusNotFound, "connection not found")
			return
		}
		web.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	web.WriteJSON(w, http.StatusOK, conn)
}

func (h *Handler) handleRunScan(w http.ResponseWriter, r *http.Request) {
	orgID := auth.OrgID(r.Context())
	connID := web.PathValue(r, "connectionID")
	scan, err := h.svc.RunScan(r.Context(), orgID, connID)
	if err != nil {
		if err == ErrQuotaExceeded {
			web.WriteError(w, http.StatusTooManyRequests, err.Error())
			return
		}
		if err == ErrNotFound {
			web.WriteError(w, http.StatusNotFound, "connection not found")
			return
		}
		// The scan may still exist but failed; surface the error message.
		web.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	web.WriteJSON(w, http.StatusCreated, scan)
	h.auditReq(r, "scan.run_api", scan.ID, map[string]any{"connection_id": connID})
}

func (h *Handler) handleDelete(w http.ResponseWriter, r *http.Request) {
	orgID := auth.OrgID(r.Context())
	connID := web.PathValue(r, "connectionID")
	if err := h.svc.DeleteConnection(r.Context(), orgID, connID); err != nil {
		if err == ErrNotFound {
			web.WriteError(w, http.StatusNotFound, "connection not found")
			return
		}
		web.WriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	web.WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	h.auditReq(r, "connection.delete", connID, nil)
}

func (h *Handler) handleScans(w http.ResponseWriter, r *http.Request) {
	orgID := auth.OrgID(r.Context())
	scans, err := h.svc.ListScans(r.Context(), orgID)
	if err != nil {
		web.WriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	web.WriteJSON(w, http.StatusOK, map[string]any{"scans": scans})
}

func (h *Handler) handleScan(w http.ResponseWriter, r *http.Request) {
	orgID := auth.OrgID(r.Context())
	scanID := web.PathValue(r, "scanID")
	scan, err := h.svc.ScanByID(r.Context(), orgID, scanID)
	if err != nil {
		if err == ErrNotFound {
			web.WriteError(w, http.StatusNotFound, "scan not found")
			return
		}
		web.WriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	web.WriteJSON(w, http.StatusOK, scan)
}

func (h *Handler) handleFindings(w http.ResponseWriter, r *http.Request) {
	orgID := auth.OrgID(r.Context())
	scanID := web.PathValue(r, "scanID")
	severity := r.URL.Query().Get("severity")
	findings, err := h.svc.Findings(r.Context(), orgID, scanID, severity)
	if err != nil {
		web.WriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	web.WriteJSON(w, http.StatusOK, map[string]any{"findings": findings})
}

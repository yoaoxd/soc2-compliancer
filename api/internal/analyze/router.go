package analyze

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/soc2-compliancer/app/internal/analysis"
	"github.com/soc2-compliancer/app/internal/web"
)

type Request struct {
	Provider           string `json:"provider"`
	ServiceAccountJSON string `json:"service_account_json"`
	AWSCredentials     *analysis.AWSCredentials     `json:"aws_credentials"`
	AzureCredentials   *analysis.AzureCredentials   `json:"azure_credentials"`
}

type FindingResponse struct {
	ResourceType string              `json:"resource_type"`
	ResourceName string              `json:"resource_name"`
	CheckName    string              `json:"check_name"`
	Title        string              `json:"title"`
	Controls     []string            `json:"controls"`
	Severity     string              `json:"severity"`
	EvidenceType string              `json:"evidence_type"`
	Evidence     map[string]any      `json:"evidence"`
	Remediation  analysis.Remediation `json:"remediation"`
}

type Response struct {
	ProjectID string           `json:"project_id"`
	ScannedAt time.Time        `json:"scanned_at"`
	Warnings  []string         `json:"warnings"`
	Counts    map[string]int   `json:"counts"`
	Findings  []FindingResponse `json:"findings"`
}

type Handler struct{}

func NewHandler() *Handler {
	return &Handler{}
}

func (h *Handler) Routes() http.Handler {
	r := chi.NewRouter()
	r.Post("/analyze", h.handleAnalyze)
	return r
}

func (h *Handler) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	var req Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		web.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	var rs *analysis.ResourceSet
	switch req.Provider {
	case "aws":
		if req.AWSCredentials == nil {
			web.WriteError(w, http.StatusBadRequest, "aws_credentials is required")
			return
		}
		if err := req.AWSCredentials.Valid(); err != nil {
			web.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		analyzeAWS(w, r, req)
		return
	case "azure":
		if req.AzureCredentials == nil {
			web.WriteError(w, http.StatusBadRequest, "azure_credentials is required")
			return
		}
		if err := req.AzureCredentials.Valid(); err != nil {
			web.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		analyzeAzure(w, r, req)
		return
	case "", "gcp":
		if req.ServiceAccountJSON == "" {
			web.WriteError(w, http.StatusBadRequest, "service_account_json is required for gcp")
			return
		}
		sa, err := analysis.ParseServiceAccount([]byte(req.ServiceAccountJSON))
		if err != nil {
			web.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		rs, err = analysis.Collect(r.Context(), sa)
		if err != nil {
			web.WriteError(w, http.StatusBadRequest, "failed to collect resources: "+err.Error())
			return
		}
	default:
		web.WriteError(w, http.StatusBadRequest, "unsupported provider "+req.Provider)
		return
	}

	writeFindings(w, rs)
}

func analyzeAWS(w http.ResponseWriter, r *http.Request, req Request) {
	rs, err := analysis.CollectAWS(r.Context(), req.AWSCredentials)
	if err != nil {
		web.WriteError(w, http.StatusBadRequest, "failed to collect resources: "+err.Error())
		return
	}
	writeFindings(w, rs)
}

func analyzeAzure(w http.ResponseWriter, r *http.Request, req Request) {
	rs, err := analysis.CollectAzure(r.Context(), req.AzureCredentials)
	if err != nil {
		web.WriteError(w, http.StatusBadRequest, "failed to collect resources: "+err.Error())
		return
	}
	writeFindings(w, rs)
}

func writeFindings(w http.ResponseWriter, rs *analysis.ResourceSet) {
	findings := analysis.Evaluate(rs)

	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	projectID := rs.ProjectID
	if projectID == "" {
		projectID = rs.AccountID
	}

	resp := Response{
		ProjectID: projectID,
		ScannedAt: time.Now().UTC(),
		Warnings:  rs.Warnings,
		Counts:    counts,
		Findings:  make([]FindingResponse, 0, len(findings)),
	}
	for _, f := range findings {
		resp.Findings = append(resp.Findings, FindingResponse{
			ResourceType: f.ResourceType,
			ResourceName: f.ResourceName,
			CheckName:    f.CheckName,
			Title:        f.Title,
			Controls:     f.Controls,
			Severity:     f.Severity,
			EvidenceType: f.EvidenceType,
			Evidence:     f.Evidence,
			Remediation:  f.Remediation,
		})
	}

	web.WriteJSON(w, http.StatusOK, resp)
}

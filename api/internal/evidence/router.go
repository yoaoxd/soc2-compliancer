package evidence

import (
	"net/http"
	"sort"

	"github.com/go-chi/chi/v5"
	"github.com/soc2-compliancer/app/internal/auth"
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
	r.Get("/matrix", s.handleMatrix)
	return r
}

// handleMatrix builds the evidence matrix for the current org.
func (s *Service) handleMatrix(w http.ResponseWriter, r *http.Request) {
	edition := r.URL.Query().Get("edition")
	if edition == "" {
		edition = "soc2_2017"
	}
	orgID := auth.OrgID(r.Context())

	controls, err := s.repo.Controls(r.Context(), edition)
	if err != nil {
		web.WriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	findings, err := s.repo.FindingsByControl(r.Context(), orgID)
	if err != nil {
		web.WriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	scanned, err := s.repo.HasScans(r.Context(), orgID)
	if err != nil {
		web.WriteError(w, http.StatusInternalServerError, "internal error")
		return
	}

	rows := make([]ControlRow, 0, len(controls))
	for _, c := range controls {
		bySeverity := findings[c.Code]
		row := ControlRow{
			Code:          c.Code,
			Title:         c.Title,
			Category:      c.Category,
			EvidenceTypes: c.EvidenceTypes,
			Guardrails:    c.Guardrails,
			Findings:      bySeverity,
			OpenFindings:  total(bySeverity),
			Coverage:      "covered",
		}
		if !scanned {
			row.Coverage = "not_assessed"
		} else if row.OpenFindings > 0 {
			row.Coverage = "gaps"
		}
		rows = append(rows, row)
	}

	// stable ordering for the UI
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Category == rows[j].Category {
			return rows[i].Code < rows[j].Code
		}
		return rows[i].Category < rows[j].Category
	})

	web.WriteJSON(w, http.StatusOK, Matrix{Edition: edition, Scanned: scanned, Controls: rows})
}

func total(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

package cirun

import "time"

// Run is one reported CI/policy result for a bundle.
type Run struct {
	ID        string           `json:"id"`
	OrgID     string           `json:"-"`
	Provider  string           `json:"provider"`
	Tool      string           `json:"tool"`
	Status    string           `json:"status"`
	Findings  []map[string]any `json:"findings"`
	CreatedAt time.Time        `json:"created_at"`
}

type ReportInput struct {
	Provider string           `json:"provider"`
	Tool     string           `json:"tool"`
	Status   string           `json:"status"`
	Findings []map[string]any `json:"findings"`
}

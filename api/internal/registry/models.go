package registry

import "time"

type Control struct {
	ID          string    `json:"id"`
	Edition     string    `json:"edition"`
	Category    string    `json:"category"`
	Code        string    `json:"code"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

type Mapping struct {
	ID           string `json:"id"`
	ControlID    string `json:"control_id"`
	ControlCode  string `json:"control_code,omitempty"`
	Provider     string `json:"provider"`
	ResourceType string `json:"resource_type"`
	Guardrail    string `json:"guardrail"`
	EvidenceType string `json:"evidence_type"`
}

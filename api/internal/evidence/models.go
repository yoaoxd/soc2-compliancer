package evidence

// ControlRow is one row of the evidence matrix: a SOC2 control with the
// guardrails/evidence types mapped to it and the org's current finding posture.
type ControlRow struct {
	Code          string         `json:"code"`
	Title         string         `json:"title"`
	Category      string         `json:"category"`
	EvidenceTypes []string       `json:"evidence_types"`
	Guardrails    int            `json:"guardrails"`
	Findings      map[string]int `json:"findings"` // severity -> count (latest scans)
	OpenFindings  int            `json:"open_findings"`
	Coverage      string         `json:"coverage"` // covered | gaps | not_assessed
}

// Matrix aggregates per-control coverage across the org's latest scans.
type Matrix struct {
	Edition  string       `json:"edition"`
	Scanned  bool         `json:"scanned"`
	Controls []ControlRow `json:"controls"`
}

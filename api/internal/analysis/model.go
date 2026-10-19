package analysis

import "encoding/json"

// Remediation describes how to fix a finding with Terraform.
type Remediation struct {
	ImportCommand   string `json:"import_command"`   // terraform import <address> <id>
	ResourceAddress string `json:"resource_address"` // e.g. google_storage_bucket.soc2_bucket
	ResourceType    string `json:"resource_type"`    // e.g. google_storage_bucket
	TerraformConfig string `json:"terraform_config"` // compliant .tf snippet
	Notes           string `json:"notes"`
}

type Finding struct {
	ResourceType string
	ResourceName string
	CheckName    string
	Title        string
	Controls     []string
	Severity     string // critical | high | medium | low | info
	EvidenceType string // config | policy | log
	Evidence     map[string]any
	Remediation  Remediation
}

func (f *Finding) EvidenceJSON() string {
	b, _ := json.Marshal(f.Evidence)
	return string(b)
}

func (f *Finding) ControlsJSON() string {
	if len(f.Controls) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(f.Controls)
	return string(b)
}

func (f *Finding) RemediationJSON() string {
	b, _ := json.Marshal(f.Remediation)
	return string(b)
}

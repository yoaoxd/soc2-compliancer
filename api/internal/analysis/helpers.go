package analysis

import (
	"strings"

	compute "google.golang.org/api/compute/v1"
	secretmanager "google.golang.org/api/secretmanager/v1"
	storage "google.golang.org/api/storage/v1"
)

func valueOf(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func contains0(list []string, candidates ...string) bool {
	for _, l := range list {
		for _, c := range candidates {
			if strings.EqualFold(strings.TrimSpace(l), c) {
				return true
			}
		}
	}
	return false
}

func bindingMembersStr(bindings []*secretmanager.Binding) []string {
	var out []string
	for _, b := range bindings {
		out = append(out, b.Members...)
	}
	return out
}

func computeFinding(inst *compute.Instance, checkName, title string, controls []string, sev, note string) Finding {
	zone := inst.Zone
	if idx := strings.LastIndex(zone, "/"); idx >= 0 {
		zone = zone[idx+1:]
	}
	return Finding{
		ResourceType: "google_compute_instance",
		ResourceName: inst.Name,
		CheckName:    checkName,
		Title:        title,
		Controls:     controls,
		Severity:     sev,
		EvidenceType: "config",
		Evidence:     map[string]any{"zone": zone, "machine_type": inst.MachineType},
		Remediation:  computeRemediation(zone, inst.Name, checkName, note),
	}
}

func firewallFinding(fw *compute.Firewall, checkName, title string, controls []string, sev, note string) Finding {
	return Finding{
		ResourceType: "google_compute_firewall",
		ResourceName: fw.Name,
		CheckName:    checkName,
		Title:        title,
		Controls:     controls,
		Severity:     sev,
		EvidenceType: "policy",
		Evidence:     map[string]any{"direction": fw.Direction, "source_ranges": fw.SourceRanges},
		Remediation:  firewallRemediation(fw.Name, checkName, note),
	}
}

// re-exports for convenience
type fwAllowed = compute.FirewallAllowed
type storagePolicyBindings = storage.PolicyBindings

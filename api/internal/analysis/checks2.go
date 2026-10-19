package analysis

import "strings"

// --- Compute instances ---

func checkComputeShielded(rs *ResourceSet) []Finding {
	var out []Finding
	for _, inst := range rs.ComputeInstances {
		shielded := inst.ShieldedInstanceConfig != nil && inst.ShieldedInstanceConfig.EnableSecureBoot
		if !shielded {
			out = append(out, computeFinding(inst, "compute_shielded_vm",
				"VM does not use Shielded VM secure boot",
				[]string{"CC6.1"}, "high",
				"Enable Shielded VM (secure boot, vTPM, integrity monitoring)."))
		}
	}
	return out
}

func checkComputePublicIP(rs *ResourceSet) []Finding {
	var out []Finding
	for _, inst := range rs.ComputeInstances {
		for _, ni := range inst.NetworkInterfaces {
			if len(ni.AccessConfigs) > 0 {
				out = append(out, computeFinding(inst, "compute_public_ip",
					"VM has an external public IP address",
					[]string{"CC6.6"}, "high",
					"Remove external IPs; use Cloud NAT + private networking."))
				break
			}
		}
	}
	return out
}

func checkComputeSerialPort(rs *ResourceSet) []Finding {
	var out []Finding
	for _, inst := range rs.ComputeInstances {
		enabled := false
		if inst.Metadata != nil {
			for _, item := range inst.Metadata.Items {
				if item.Key == "serial-port-enable" && strings.EqualFold(valueOf(item.Value), "1") {
					enabled = true
				}
			}
		}
		if enabled {
			out = append(out, computeFinding(inst, "compute_serial_port",
				"VM serial port access is enabled",
				[]string{"CC6.1"}, "medium",
				"Disable serial port access on the instance."))
		}
	}
	return out
}

// --- Firewalls & subnets ---

func checkFirewallBroadIngress(rs *ResourceSet) []Finding {
	var out []Finding
	for _, fw := range rs.Firewalls {
		if fw.Disabled || fw.Direction != "INGRESS" {
			continue
		}
		for _, allowed := range fw.Allowed {
			bad, proto := isBroadIngress(allowed, fw.SourceRanges)
			if bad {
				sev := "high"
				if proto == "all" {
					sev = "critical"
				}
				out = append(out, firewallFinding(fw, "firewall_http_ingress_broad",
					"Firewall allows broad ingress from 0.0.0.0/0 on a sensitive port/protocol",
					[]string{"CC6.6"}, sev,
					"Tighten source ranges; never allow 0.0.0.0/0 on management/database ports."))
				break
			}
		}
	}
	return out
}

func isBroadIngress(allowed *fwAllowed, ranges []string) (bool, string) {
	proto := strings.ToLower(allowed.IPProtocol)
	if proto != "tcp" && proto != "udp" && proto != "all" {
		return false, proto
	}
	if !contains0(ranges, "0.0.0.0/0", "::/0") {
		return false, proto
	}
	if proto == "all" {
		return true, proto
	}
	for _, p := range allowed.Ports {
		if highRiskDBPorts[p] || p == "*" {
			return true, proto
		}
	}
	return false, proto
}

func checkFirewallLogging(rs *ResourceSet) []Finding {
	var out []Finding
	for _, fw := range rs.Firewalls {
		if fw.Disabled {
			continue
		}
		for _, allowed := range fw.Allowed {
			proto := strings.ToLower(allowed.IPProtocol)
			if (proto == "tcp" || proto == "udp" || proto == "all") && contains0(fw.SourceRanges, "0.0.0.0/0", "::/0") {
				if fw.LogConfig == nil || !fw.LogConfig.Enable {
					out = append(out, firewallFinding(fw, "firewall_logging",
						"Allow rule is not logged (no VPC firewall logging)",
						[]string{"CC7.2"}, "low",
						"Enable log_config.enabled on the firewall rule."))
				}
				break
			}
		}
	}
	return out
}

func checkSubnetFlowLogs(rs *ResourceSet) []Finding {
	var out []Finding
	for _, sub := range rs.Subnets {
		enabled := sub.LogConfig != nil && sub.LogConfig.Enable
		if !enabled {
			out = append(out, Finding{
				ResourceType: "google_compute_subnetwork",
				ResourceName: sub.Name,
				CheckName:    "subnet_flow_logs",
				Title:        "Subnet VPC flow logs are disabled",
				Controls:     []string{"CC7.2"},
				Severity:     "medium",
				EvidenceType: "log",
				Evidence:     map[string]any{"region": sub.Region},
				Remediation: subnetRemediation(sub.Name, "subnet_flow_logs",
					"Enable VPC flow logs on the subnetwork."),
			})
		}
	}
	return out
}

// --- IAM ---

func checkProjectPrimitiveRoles(rs *ResourceSet) []Finding {
	var out []Finding
	primitive := map[string]string{
		"roles/owner":  "high",
		"roles/editor": "medium",
		"roles/viewer": "low",
	}
	for _, b := range rs.ProjectIAM {
		sev, ok := primitive[b.Role]
		if !ok {
			continue
		}
		for _, m := range b.Members {
			if strings.HasPrefix(m, "serviceAccount:") {
				continue // service accounts commonly need these; still worth review but not a hard finding
			}
			out = append(out, Finding{
				ResourceType: "google_project_iam_member",
				ResourceName: b.Role,
				CheckName:    "project_primitive_roles",
				Title:        "Project grants primitive role " + b.Role + " to " + m,
				Controls:     []string{"CC6.2"},
				Severity:     sev,
				EvidenceType: "policy",
				Evidence:     map[string]any{"member": m, "role": b.Role},
				Remediation: projectIAMRemediation(m, b.Role,
					"Replace primitive roles with least-privilege custom or predefined roles."),
			})
		}
	}
	return out
}

func checkProjectPublicBindings(rs *ResourceSet) []Finding {
	var out []Finding
	for _, b := range rs.ProjectIAM {
		for _, m := range b.Members {
			if m == "allUsers" || m == "allAuthenticatedUsers" {
				out = append(out, Finding{
					ResourceType: "google_project_iam_member",
					ResourceName: b.Role,
					CheckName:    "project_public_bindings",
					Title:        "Project grants " + m + " role " + b.Role,
					Controls:     []string{"CC6.6"},
					Severity:     "critical",
					EvidenceType: "policy",
					Evidence:     map[string]any{"member": m, "role": b.Role},
					Remediation: projectIAMRemediation(m, b.Role,
						"Remove public principals from project IAM."),
				})
			}
		}
	}
	return out
}

func checkSAUserManagedKeys(rs *ResourceSet) []Finding {
	if rs.SAKeysWarn != "" {
		return nil
	}
	var out []Finding
	for email, keys := range rs.SAKeys {
		if len(keys) > 0 {
			out = append(out, Finding{
				ResourceType: "google_service_account_key",
				ResourceName: email,
				CheckName:    "sa_user_managed_keys",
				Title:        "Service account has user-managed keys",
				Controls:     []string{"CC6.2", "CC6.4"},
				Severity:     "medium",
				EvidenceType: "policy",
				Evidence:     map[string]any{"key_count": len(keys)},
				Remediation: saKeyRemediation(email,
					"Rotate and remove user-managed keys; prefer Workload Identity."),
			})
		}
	}
	return out
}

// --- Logging ---

func checkLoggingAuditSink(rs *ResourceSet) []Finding {
	if len(rs.Sinks) > 0 {
		for _, s := range rs.Sinks {
			if s.Destination != "" && containsFilter(s.Filter, "AUDIT") {
				return nil // an audit sink exists
			}
		}
	}
	return []Finding{{
		ResourceType: "google_logging_project_sink",
		ResourceName: rs.ProjectID,
		CheckName:    "logging_audit_sink",
		Title:        "No audit log sink exporting admin/data-access logs",
		Controls:     []string{"CC7.2", "CC7.3"},
		Severity:     "high",
		EvidenceType: "log",
		Evidence:     map[string]any{"sink_count": len(rs.Sinks)},
		Remediation: loggingSinkRemediation("logging_audit_sink",
			"Export AUDIT (admin + data access) logs to a storage sink with >= 365 day retention."),
	}}
}

// --- KMS ---

func checkKMSRotation(rs *ResourceSet) []Finding {
	var out []Finding
	for _, k := range rs.CryptoKeys {
		if k.RotationPeriod == "" {
			out = append(out, Finding{
				ResourceType: "google_kms_crypto_key",
				ResourceName: k.Name,
				CheckName:    "kms_key_rotation",
				Title:        "KMS key has no automatic rotation",
				Controls:     []string{"CC6.1"},
				Severity:     "medium",
				EvidenceType: "config",
				Evidence:     map[string]any{},
				Remediation: kmsRemediation(k.Name, "kms_key_rotation",
					"Configure rotation_period (e.g. 90d) on the key."),
			})
		}
	}
	return out
}

// --- Secret Manager ---

func checkSecretPublicBinding(rs *ResourceSet) []Finding {
	var out []Finding
	for name, bindings := range rs.SecretPolicies {
		if member, ok := hasPublicMember(bindingMembersStr(bindings)); ok {
			out = append(out, Finding{
				ResourceType: "google_secret_manager_secret",
				ResourceName: name,
				CheckName:    "secret_public_binding",
				Title:        "Secret grants public access to " + member,
				Controls:     []string{"CC6.6", "C1.1"},
				Severity:     "critical",
				EvidenceType: "policy",
				Evidence:     map[string]any{"public_member": member},
				Remediation: secretRemediation(name, "secret_public_binding",
					"Remove public principals from the secret IAM policy."),
			})
		}
	}
	return out
}

func checkSecretRotation(rs *ResourceSet) []Finding {
	var out []Finding
	for _, s := range rs.Secrets {
		if s.Rotation == nil || s.Rotation.RotationPeriod == "" {
			name := s.Name
			out = append(out, Finding{
				ResourceType: "google_secret_manager_secret",
				ResourceName: name,
				CheckName:    "secret_rotation_period",
				Title:        "Secret has no automatic rotation period",
				Controls:     []string{"CC6.1"},
				Severity:     "medium",
				EvidenceType: "config",
				Evidence:     map[string]any{},
				Remediation: secretRemediation(name, "secret_rotation_period",
					"Configure rotation_period (e.g. 30d) and next_rotation_time."),
			})
		}
	}
	return out
}

// --- Extra SQL guards ---

func checkSQLPITR(rs *ResourceSet) []Finding {
	var out []Finding
	for _, i := range rs.SQLInstances {
		cfg := i.Settings
		pitr := cfg != nil && cfg.BackupConfiguration != nil && cfg.BackupConfiguration.PointInTimeRecoveryEnabled
		if !pitr {
			out = append(out, sqlFinding(i, "sql_pitr_enabled",
				"Cloud SQL point-in-time recovery is disabled",
				[]string{"A1.2"}, "medium",
				"Enable pointInTimeRecoveryEnabled for PITR."))
		}
	}
	return out
}

func checkSQLBroadAuthorizedNetworks(rs *ResourceSet) []Finding {
	var out []Finding
	for _, i := range rs.SQLInstances {
		cfg := i.Settings
		if cfg == nil || cfg.IpConfiguration == nil {
			continue
		}
		for _, net := range cfg.IpConfiguration.AuthorizedNetworks {
			if net.Value == "0.0.0.0/0" || net.Value == "::/0" {
				out = append(out, sqlFinding(i, "sql_broad_authorized_networks",
					"Cloud SQL allows connections from 0.0.0.0/0 (authorized network)",
					[]string{"CC6.6"}, "critical",
					"Remove open authorized networks; use private networking or tight CIDRs."))
				break
			}
		}
	}
	return out
}

// --- Extra bucket guard ---

func checkBucketRetention(rs *ResourceSet) []Finding {
	var out []Finding
	for _, b := range rs.Buckets {
		hasRetention := b.RetentionPolicy != nil && b.RetentionPolicy.RetentionPeriod > 0
		if !hasRetention {
			out = append(out, Finding{
				ResourceType: "google_storage_bucket",
				ResourceName: b.Name,
				CheckName:    "storage_bucket_retention",
				Title:        "Bucket has no retention policy",
				Controls:     []string{"A1.2", "C1.2"},
				Severity:     "medium",
				EvidenceType: "config",
				Evidence:     map[string]any{"project_id": rs.ProjectID},
				Remediation: bucketRemediation(b.Name, "storage_bucket_retention",
					"Add a retention_policy with the desired retention period."),
			})
		}
	}
	return out
}

// --- Extra compute guards ---

func checkComputeOSLogin(rs *ResourceSet) []Finding {
	var out []Finding
	for _, inst := range rs.ComputeInstances {
		if inst.Metadata == nil {
			continue
		}
		enabled := false
		for _, item := range inst.Metadata.Items {
			if item.Key == "enable-oslogin" && strings.EqualFold(strings.TrimSpace(valueOf(item.Value)), "true") {
				enabled = true
				break
			}
		}
		if !enabled {
			out = append(out, computeFinding(inst, "compute_oslogin",
				"VM does not enforce OS Login",
				[]string{"CC6.1", "CC6.3"}, "medium",
				"Enable OS Login (enable-oslogin = true) for identity-based access."))
		}
	}
	return out
}

func checkComputeSSHKeysMetadata(rs *ResourceSet) []Finding {
	var out []Finding
	for _, inst := range rs.ComputeInstances {
		if inst.Metadata == nil {
			continue
		}
		for _, item := range inst.Metadata.Items {
			if item.Key == "ssh-keys" || item.Key == "sshKeys" {
				if strings.TrimSpace(valueOf(item.Value)) != "" {
					out = append(out, computeFinding(inst, "compute_ssh_keys_metadata",
						"VM exposes inline SSH keys in instance metadata",
						[]string{"CC6.4"}, "critical",
						"Remove ssh-keys metadata; use OS Login / managed keys."))
					break
				}
			}
		}
	}
	return out
}

// --- Extra firewall guard ---

func checkFirewallEgressBroad(rs *ResourceSet) []Finding {
	var out []Finding
	for _, fw := range rs.Firewalls {
		if fw.Disabled || fw.Direction != "EGRESS" {
			continue
		}
		for _, allowed := range fw.Allowed {
			proto := strings.ToLower(allowed.IPProtocol)
			if proto != "tcp" && proto != "udp" && proto != "all" {
				continue
			}
			if !contains0(fw.DestinationRanges, "0.0.0.0/0", "::/0") {
				continue
			}
			if proto == "all" {
				out = append(out, firewallFinding(fw, "firewall_egress_broad",
					"Firewall allows all egress traffic to 0.0.0.0/0",
					[]string{"CC6.6"}, "medium",
					"Restrict egress destinations to required CIDRs."))
				break
			}
		}
	}
	return out
}

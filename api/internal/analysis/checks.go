package analysis

import (
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
	storage "google.golang.org/api/storage/v1"
)

var highRiskDBPorts = map[string]bool{
	"22": true, "3389": true, "5432": true, "5433": true,
	"3306": true, "1433": true, "27017": true, "6379": true, "11211": true,
}

// Evaluate runs every check against the resource set and returns findings
// ordered by severity.
func Evaluate(rs *ResourceSet) []Finding {
	var out []Finding
	out = append(out, checkBucketUniformAccess(rs)...)
	out = append(out, checkBucketPublicBinding(rs)...)
	out = append(out, checkBucketVersioning(rs)...)
	out = append(out, checkBucketCMEK(rs)...)
	out = append(out, checkBucketRetention(rs)...)
	out = append(out, checkSQLSsl(rs)...)
	out = append(out, checkSQLPublicExposure(rs)...)
	out = append(out, checkSQLHA(rs)...)
	out = append(out, checkSQLBackups(rs)...)
	out = append(out, checkSQLPITR(rs)...)
	out = append(out, checkSQLDeletionProtection(rs)...)
	out = append(out, checkSQLCMEK(rs)...)
	out = append(out, checkSQLBroadAuthorizedNetworks(rs)...)
	out = append(out, checkComputeShielded(rs)...)
	out = append(out, checkComputePublicIP(rs)...)
	out = append(out, checkComputeSerialPort(rs)...)
	out = append(out, checkComputeOSLogin(rs)...)
	out = append(out, checkComputeSSHKeysMetadata(rs)...)
	out = append(out, checkFirewallBroadIngress(rs)...)
	out = append(out, checkFirewallLogging(rs)...)
	out = append(out, checkFirewallEgressBroad(rs)...)
	out = append(out, checkSubnetFlowLogs(rs)...)
	out = append(out, checkProjectPrimitiveRoles(rs)...)
	out = append(out, checkProjectPublicBindings(rs)...)
	out = append(out, checkSAUserManagedKeys(rs)...)
	out = append(out, checkLoggingAuditSink(rs)...)
	out = append(out, checkKMSRotation(rs)...)
	out = append(out, checkSecretPublicBinding(rs)...)
	out = append(out, checkSecretRotation(rs)...)
	for _, check := range caiChecks() {
		out = append(out, check(rs)...)
	}
	for _, check := range awsChecks() {
		out = append(out, check(rs)...)
	}
	for _, check := range azureChecks() {
		out = append(out, check(rs)...)
	}
	sortFindings(out)
	return out
}

func sortFindings(fs []Finding) {
	// insertion sort (small n) to avoid importing sort.Slice unstable ordering
	for i := 1; i < len(fs); i++ {
		for j := i; j > 0 && sevRank(fs[j].Severity) < sevRank(fs[j-1].Severity); j-- {
			fs[j], fs[j-1] = fs[j-1], fs[j]
		}
	}
}

func sevRank(sev string) int {
	switch sev {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

func hasPublicMember(members []string) (string, bool) {
	for _, m := range members {
		if m == "allUsers" || m == "allAuthenticatedUsers" {
			return m, true
		}
	}
	return "", false
}

func bindingMembers(bindings []*storage.PolicyBindings) []string {
	var members []string
	for _, b := range bindings {
		members = append(members, b.Members...)
	}
	return members
}

// --- Storage buckets ---

func checkBucketUniformAccess(rs *ResourceSet) []Finding {
	var out []Finding
	for _, b := range rs.Buckets {
		enabled := b.IamConfiguration != nil && b.IamConfiguration.UniformBucketLevelAccess != nil &&
			b.IamConfiguration.UniformBucketLevelAccess.Enabled
		if !enabled {
			out = append(out, Finding{
				ResourceType: "google_storage_bucket",
				ResourceName: b.Name,
				CheckName:    "storage_bucket_uniform_access",
				Title:        "Bucket does not use IAM-only (uniform) access",
				Controls:     []string{"CC6.1", "CC6.6"},
				Severity:     "high",
				EvidenceType: "config",
				Evidence:     map[string]any{"project_id": rs.ProjectID, "location": b.Location},
				Remediation: bucketRemediation(b.Name, "storage_bucket_uniform_access",
					"Enable uniform bucket-level access so only IAM policies grant access."),
			})
		}
	}
	return out
}

func checkBucketPublicBinding(rs *ResourceSet) []Finding {
	var out []Finding
	for _, b := range rs.Buckets {
		if member, ok := hasPublicMember(bindingMembers(rs.BucketPolicies[b.Name])); ok {
			out = append(out, Finding{
				ResourceType: "google_storage_bucket",
				ResourceName: b.Name,
				CheckName:    "storage_bucket_public_binding",
				Title:        "Bucket grants public access to " + member,
				Controls:     []string{"CC6.6"},
				Severity:     "critical",
				EvidenceType: "policy",
				Evidence:     map[string]any{"project_id": rs.ProjectID, "public_member": member},
				Remediation: bucketRemediation(b.Name, "storage_bucket_public_binding",
					"Remove allUsers/allAuthenticatedUsers bindings and restrict via IAM policies only."),
			})
		}
	}
	return out
}

func checkBucketVersioning(rs *ResourceSet) []Finding {
	var out []Finding
	for _, b := range rs.Buckets {
		enabled := b.Versioning != nil && b.Versioning.Enabled
		if !enabled {
			out = append(out, Finding{
				ResourceType: "google_storage_bucket",
				ResourceName: b.Name,
				CheckName:    "storage_bucket_versioning",
				Title:        "Bucket versioning disabled",
				Controls:     []string{"A1.2"},
				Severity:     "medium",
				EvidenceType: "config",
				Evidence:     map[string]any{"project_id": rs.ProjectID},
				Remediation: bucketRemediation(b.Name, "storage_bucket_versioning",
					"Enable versioning for object recoverability."),
			})
		}
	}
	return out
}

func checkBucketCMEK(rs *ResourceSet) []Finding {
	var out []Finding
	for _, b := range rs.Buckets {
		kmsEmpty := b.Encryption == nil || b.Encryption.DefaultKmsKeyName == ""
		if kmsEmpty {
			out = append(out, Finding{
				ResourceType: "google_storage_bucket",
				ResourceName: b.Name,
				CheckName:    "storage_bucket_cmek",
				Title:        "Bucket not using customer-managed encryption (CMEK)",
				Controls:     []string{"CC6.7", "C1.1"},
				Severity:     "low",
				EvidenceType: "config",
				Evidence:     map[string]any{"project_id": rs.ProjectID},
				Remediation: bucketRemediation(b.Name, "storage_bucket_cmek",
					"Associate a Cloud KMS key (default_kms_key_name) for stronger encryption control."),
			})
		}
	}
	return out
}

// --- Cloud SQL ---

func checkSQLSsl(rs *ResourceSet) []Finding {
	var out []Finding
	for _, i := range rs.SQLInstances {
		cfg := i.Settings
		sslOnly := cfg != nil && cfg.IpConfiguration != nil && cfg.IpConfiguration.SslMode == "ENCRYPTED_ONLY"
		if !sslOnly {
			out = append(out, sqlFinding(i, "sql_ssl_encrypted_only",
				"Cloud SQL does not require encrypted connections (SSL mode)",
				[]string{"CC6.7"}, "high",
				"Enforce ssl_mode = ENCRYPTED_ONLY (require_ssl = true)."))
		}
	}
	return out
}

func checkSQLPublicExposure(rs *ResourceSet) []Finding {
	var out []Finding
	for _, i := range rs.SQLInstances {
		cfg := i.Settings
		if cfg == nil || cfg.IpConfiguration == nil || !cfg.IpConfiguration.Ipv4Enabled {
			continue
		}
		severe := len(cfg.IpConfiguration.AuthorizedNetworks) == 0
		sev := "medium"
		if severe {
			sev = "high"
		}
		out = append(out, sqlFinding(i, "sql_public_exposure",
			"Cloud SQL instance has a public IP address",
			[]string{"CC6.6", "A1.2"}, sev,
			"Prefer private networking (private_network); avoid public IPv4 or restrict authorized networks strictly."))
	}
	return out
}

func checkSQLHA(rs *ResourceSet) []Finding {
	var out []Finding
	for _, i := range rs.SQLInstances {
		ha := i.Settings != nil && i.Settings.AvailabilityType == "REGIONAL"
		if !ha {
			out = append(out, sqlFinding(i, "sql_high_availability",
				"Cloud SQL instance is not regional (no automatic failover)",
				[]string{"A1.1", "A1.3"}, "medium",
				"Set availability_type = REGIONAL."))
		}
	}
	return out
}

func checkSQLBackups(rs *ResourceSet) []Finding {
	var out []Finding
	for _, i := range rs.SQLInstances {
		backup := i.Settings != nil && i.Settings.BackupConfiguration != nil && i.Settings.BackupConfiguration.Enabled
		if !backup {
			out = append(out, sqlFinding(i, "sql_backups_enabled",
				"Cloud SQL automated backups are disabled",
				[]string{"A1.2"}, "high",
				"Enable automated backups with PITR."))
		}
	}
	return out
}

func checkSQLDeletionProtection(rs *ResourceSet) []Finding {
	var out []Finding
	for _, i := range rs.SQLInstances {
		prot := i.Settings != nil && i.Settings.DeletionProtectionEnabled
		if !prot {
			out = append(out, sqlFinding(i, "sql_deletion_protection",
				"Cloud SQL instance can be deleted without protection",
				[]string{"A1.3", "C1.2"}, "medium",
				"Set deletion_protection = true."))
		}
	}
	return out
}

func checkSQLCMEK(rs *ResourceSet) []Finding {
	var out []Finding
	for _, i := range rs.SQLInstances {
		cmek := i.DiskEncryptionConfiguration != nil && i.DiskEncryptionConfiguration.KmsKeyName != ""
		if !cmek {
			out = append(out, sqlFinding(i, "sql_disk_cmek",
				"Cloud SQL disk not using customer-managed encryption (CMEK)",
				[]string{"CC6.7", "C1.1"}, "low",
				"Enable disk_encryption_key/encryption_key_name with a KMS key."))
		}
	}
	return out
}

func sqlFinding(i *sqladmin.DatabaseInstance, checkName, title string, controls []string, sev, note string) Finding {
	return Finding{
		ResourceType: "google_sql_database_instance",
		ResourceName: i.Name,
		CheckName:    checkName,
		Title:        title,
		Controls:     controls,
		Severity:     sev,
		EvidenceType: "config",
		Evidence:     map[string]any{"project": i.Project, "region": i.Region},
		Remediation:  sqlRemediation(i.Name, checkName, note),
	}
}

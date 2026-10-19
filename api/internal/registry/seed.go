package registry

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Seed inserts the versioned SOC2 control catalog and cloud resource mappings.
// Descriptions below are our own original summaries of the AICPA criteria,
// not verbatim TSC text (AICPA material is copyrighted).
//
// Edition note: the AICPA's 2022 "revised points of focus" and the guidance
// effective for reports dated on/after December 15, 2025 do NOT renumber the
// Trust Services Criteria — the CC/A/PI/C/P control codes are identical across
// editions. soc2_2025 therefore seeds the same codes with definitions that
// reflect the revised points of focus (patching, resilience and data
// recoverability, logical-access scope, monitoring depth, privacy alignment).
var (
	Edition2017 = "soc2_2017"
	Edition2025 = "soc2_2025"
)

type controlSeed struct {
	category string
	code     string
	title    string
	desc     string
}

// controlSeeds2017 is the original 2017-era criteria set.
var controlSeeds2017 = []controlSeed{
	// Security (Common Criteria) — representative set
	{"security", "CC6.1", "Logical access security", "Logical access security software, infrastructure and architectures restrict access to information assets to authorized personnel."},
	{"security", "CC6.2", "Access provisioning and deprovisioning", "User access is provisioned and deprovisioned according to management-authorized roles, and access is updated appropriately."},
	{"security", "CC6.3", "Access owner accountability", "Roles and responsibilities for system access and credential administration are assigned and maintained."},
	{"security", "CC6.4", "Credential protection", "Access to system user information (credentials) is restricted to authorized personnel."},
	{"security", "CC6.5", "Outside-user access threats", "Threats introduced by outside users of the system are identified and addressed."},
	{"security", "CC6.6", "Identity verification and access limits", "Access to the system is limited to authorized users and identity verification does not rely solely on IP allowlisting."},
	{"security", "CC6.7", "Encryption of data", "Data is protected against unauthorized use via encryption at rest and in transit."},
	{"security", "CC7.1", "Anomaly detection", "Anomalies in system behavior are detected through ongoing monitoring."},
	{"security", "CC7.2", "Security event monitoring", "Infrastructure and applications are monitored for security events."},
	{"security", "CC7.3", "Security event evaluation", "Security events are evaluated to determine whether they require further action or escalation."},
	{"security", "CC7.4", "Incident response", "Security incidents are responded to in a manner that addresses the incident and its cause."},
	{"security", "CC7.5", "Vulnerability management", "Vulnerabilities are identified, evaluated, and corrected through patching and configuration management."},
	{"security", "CC8.1", "Change management", "Changes to the system are authorized, designed, implemented, and assessed against intended outcomes."},
	{"security", "CC9.1", "Business disruption risk", "Risks arising from business disruption and threats to the organization are identified and mitigated."},
	{"security", "CC9.2", "Vendor risk management", "Risks from vendors and business partners are identified and addressed."},
	// Availability
	{"availability", "A1.1", "Capacity and performance monitoring", "System capacity and performance are monitored and aligned with availability objectives."},
	{"availability", "A1.2", "Backup and restoration", "Comprehensive backups are implemented and restoration procedures are tested."},
	{"availability", "A1.3", "Recovery planning", "Recovery from unexpected system interruption is enabled to meet availability objectives."},
	// Confidentiality
	{"confidentiality", "C1.1", "Confidential information safeguards", "Confidential information is protected during storage, processing, and transmission and access is limited."},
	{"confidentiality", "C1.2", "Confidential information disposal", "Confidential information is disposed of according to policy."},
	// Processing Integrity
	{"integrity", "PI1.1", "Complete and accurate input", "System inputs are complete, accurate, timely, and authorized."},
	{"integrity", "PI1.2", "Processing accuracy", "System processing is complete, accurate, and timely."},
	{"integrity", "PI1.3", "Output completeness", "System outputs are complete, accurate, and timely."},
	{"integrity", "PI1.4", "Activity records", "Records are sufficiently detailed to support performance of duties and absorption of system processing."},
	// Privacy (representative)
	{"privacy", "P1.1", "Privacy notice", "Personal information is communicated to users and a privacy notice is provided."},
	{"privacy", "P1.2", "Choice and consent", "Users are given choices and consent regarding the use of personal information."},
	{"privacy", "P6.1", "Secure storage and retention", "Personal information is securely stored and retained in accordance with policy."},
}

// controlSeeds2025 seeds the same codes (AICPA did not renumber the criteria)
// with definitions reflecting the revised 2022 points of focus.
var controlSeeds2025 = []controlSeed{
	{"security", "CC6.1", "Logical access security", "Logical access controls span the full system architecture — infrastructure, tools, and all identity types (employees, contractors, vendors, partners, system and service accounts) — and device recovery is considered."},
	{"security", "CC6.2", "Access provisioning and deprovisioning", "User access is provisioned and deprovisioned according to management-authorized roles and updated appropriately; access reviews include the first and second lines of defense."},
	{"security", "CC6.3", "Access owner accountability", "Roles, responsibilities, and reviews of access roles and rules for system access and credential administration are assigned and maintained."},
	{"security", "CC6.4", "Credential protection", "Access to system user information (credentials) is restricted to authorized personnel."},
	{"security", "CC6.5", "Outside-user access threats", "Threats introduced by outside users of the system are identified and addressed."},
	{"security", "CC6.6", "Identity verification and access limits", "Access to the system is limited to authorized users and identity verification does not rely solely on IP allowlisting."},
	{"security", "CC6.7", "Encryption of data", "Data is protected against unauthorized use via encryption at rest and in transit."},
	{"security", "CC7.1", "Anomaly detection", "Anomalies in system behavior are detected through ongoing monitoring."},
	{"security", "CC7.2", "Security event monitoring", "Infrastructure and applications are monitored for security events, with monitoring performed by operators and by managers who oversee them."},
	{"security", "CC7.3", "Security event evaluation", "Security events are evaluated to determine whether they require further action or escalation."},
	{"security", "CC7.4", "Incident response", "Security incidents are responded to in a manner that addresses the incident and its cause."},
	{"security", "CC7.5", "Vulnerability management", "Vulnerabilities are identified, evaluated, and corrected through patching and configuration management."},
	{"security", "CC8.1", "Change management", "Changes to the system are authorized, designed, implemented, and assessed against intended outcomes; software patches are identified, tested, and implemented, and resilience requirements are considered where availability is in scope."},
	{"security", "CC9.1", "Business disruption risk", "Risks arising from business disruption and threats to the organization are identified and mitigated."},
	{"security", "CC9.2", "Vendor risk management", "Risks from vendors and business partners — including vulnerabilities introduced through the supply chain — are identified and addressed."},
	// Availability
	{"availability", "A1.1", "Capacity and performance monitoring", "System capacity and performance are monitored and aligned with availability objectives."},
	{"availability", "A1.2", "Backup and restoration", "Comprehensive backups are implemented and restoration procedures are tested; threats to data recoverability (e.g. ransomware) are identified and mitigated."},
	{"availability", "A1.3", "Recovery planning", "Recovery from unexpected system interruption is enabled to meet availability objectives."},
	// Confidentiality
	{"confidentiality", "C1.1", "Confidential information safeguards", "Confidential information is protected during storage, processing, and transmission and access is limited."},
	{"confidentiality", "C1.2", "Confidential information disposal", "Confidential information is disposed of according to policy."},
	// Processing Integrity
	{"integrity", "PI1.1", "Complete and accurate input", "System inputs are complete, accurate, timely, and authorized; the types of information used by the system include data flow, asset inventory and location, and information classification."},
	{"integrity", "PI1.2", "Processing accuracy", "System processing is complete, accurate, and timely."},
	{"integrity", "PI1.3", "Output completeness", "System outputs are complete, accurate, and timely."},
	{"integrity", "PI1.4", "Activity records", "Records are sufficiently detailed to support performance of duties and absorption of system processing."},
	// Privacy (representative, controller/processor aligned)
	{"privacy", "P1.1", "Privacy notice", "Personal information is communicated to users and a privacy notice is provided; roles as data controller or processor are reflected."},
	{"privacy", "P1.2", "Choice and consent", "Users are given choices and consent regarding the use of personal information."},
	{"privacy", "P6.1", "Secure storage and retention", "Personal information is securely stored and retained in accordance with policy."},
}

type mappingSeed struct {
	control   string
	resource  string
	guardrail string
	evidence  string
}

var gcpMappings = []mappingSeed{
	{"CC6.1", "google_storage_bucket", "Uniform bucket-level access (IAM) is enabled", "config"},
	{"CC6.6", "google_storage_bucket", "No allUsers or allAuthenticatedUsers IAM bindings exist", "policy"},
	{"CC6.7", "google_storage_bucket", "Objects encrypted at rest (CMEK or service-side encryption)", "config"},
	{"C1.1", "google_storage_bucket", "IAM permissions restrict access to authorized principals only", "policy"},
	{"A1.2", "google_storage_bucket", "Versioning enabled with retention/lifecycle policy", "config"},
	{"CC6.7", "google_sql_database_instance", "SSL mode requires encrypted connections only", "config"},
	{"CC6.6", "google_sql_database_instance", "No public IP assigned; private networking preferred", "config"},
	{"A1.1", "google_sql_database_instance", "High availability (regional) availability type", "config"},
	{"A1.2", "google_sql_database_instance", "Automated backups configured", "config"},
	{"CC6.1", "google_compute_instance", "Shielded VM features (secure boot, vTPM, integrity monitoring) enabled", "config"},
	{"CC6.6", "google_compute_instance", "No external public IP address", "config"},
	{"CC6.7", "google_compute_instance", "Boot/attached disks encrypted with CMEK or at least SSE", "config"},
	{"CC6.1", "google_compute_instance", "Serial port access disabled", "config"},
	{"CC6.6", "google_compute_firewall", "Ingress deny-by-default with no broad 0.0.0.0/0 allows on management ports", "policy"},
	{"CC7.2", "google_compute_firewall", "Firewall rule logging enabled for allow rules", "log"},
	{"CC7.2", "google_compute_subnetwork", "VPC flow logs enabled on subnets", "log"},
	{"CC7.2", "google_logging_project_sink", "AUDIT (admin + data access) logs exported with retention >= 365 days", "log"},
	{"CC7.3", "google_logging_project_sink", "Security-relevant log-based alerts defined (e.g. IAM changes)", "log"},
	{"CC6.1", "google_secret_manager_secret", "IAM restricts access to named principals with least privilege", "policy"},
	{"C1.1", "google_secret_manager_secret", "Version destroy protection enabled", "config"},
	{"CC6.1", "google_kms_crypto_key", "Automatic key rotation configured", "config"},
	{"CC6.2", "google_project_iam", "No primitive roles (owner/editor/viewer) granted to user identities", "policy"},
	{"CC6.6", "google_bigquery_dataset", "No allUsers or allAuthenticatedUsers IAM bindings exist", "policy"},
	{"C1.1", "google_bigquery_dataset", "Default encryption uses a customer-managed key (CMEK)", "config"},
	{"CC6.6", "google_cloud_run_service", "No public allUsers/allAuthenticatedUsers invoker bindings", "policy"},
	{"CC6.7", "google_cloud_run_service", "Service data encrypted at rest with a customer-managed key", "config"},
	{"C1.1", "google_pubsub_topic", "Topic encrypted with a customer-managed key (CMEK)", "config"},
	{"CC6.1", "google_compute_instance_template", "Shielded VM features (secure boot, vTPM, integrity monitoring) enabled", "config"},
}

func Seed(ctx context.Context, pool *pgxpool.Pool) error {
	repo := NewRepo(pool)

	editions := []struct {
		edition string
		seeds   []controlSeed
	}{
		{Edition2017, controlSeeds2017},
		{Edition2025, controlSeeds2025},
	}

	// Index seeded controls by (edition, code -> id) for mapping lookups.
	ids := map[string]string{}
	for _, ed := range editions {
		for _, s := range ed.seeds {
			if err := repo.UpsertControl(ctx, ed.edition, s.category, s.code, s.title, s.desc); err != nil {
				return fmt.Errorf("upsert control %s %s: %w", ed.edition, s.code, err)
			}
			c, err := repo.ControlByCode(ctx, ed.edition, s.code)
			if err != nil {
				return fmt.Errorf("lookup control %s %s: %w", ed.edition, s.code, err)
			}
			ids[ed.edition+"|"+s.code] = c.ID
		}
	}

	for _, m := range gcpMappings {
		// Mappings use the 2017-era codes; both editions share the same codes.
		controlID, ok := ids[Edition2017+"|"+m.control]
		if !ok {
			continue
		}
		if err := repo.UpsertMapping(ctx, controlID, "gcp", m.resource, m.guardrail, m.evidence); err != nil {
			return fmt.Errorf("upsert mapping %s %s: %w", m.resource, m.guardrail, err)
		}
	}
	return nil
}

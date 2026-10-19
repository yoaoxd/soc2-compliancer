package analysis

import (
	"strings"

	compute "google.golang.org/api/compute/v1"
)

// --- Cloud Asset Inventory depth checks ---

func bigQueryFinding(dataset, name, title string, controls []string, sev string, evidence map[string]any, notes string) Finding {
	return Finding{
		ResourceType: "google_bigquery_dataset",
		ResourceName: name,
		CheckName:    dataset,
		Title:        title,
		Controls:     controls,
		Severity:     sev,
		EvidenceType: "config",
		Evidence:     evidence,
		Remediation:  bigqueryRemediation(name, dataset, notes),
	}
}

func checkBigQueryDatasetPublicBinding(rs *ResourceSet) []Finding {
	var out []Finding
	for _, p := range rs.PublicIAM {
		if !strings.Contains(p.AssetType, "bigquery.googleapis.com/Dataset") {
			continue
		}
		member, ok := iamResultHasPublicMember(p)
		if !ok {
			continue
		}
		name := shortName(p.Resource)
		out = append(out, Finding{
			ResourceType: "google_bigquery_dataset",
			ResourceName: name,
			CheckName:    "bigquery_dataset_public_binding",
			Title:        "BigQuery dataset grants public access to " + member,
			Controls:     []string{"CC6.6", "C1.1"},
			Severity:     "critical",
			EvidenceType: "policy",
			Evidence:     map[string]any{"project_id": rs.ProjectID, "public_member": member, "resource": p.Resource},
			Remediation: bigqueryRemediation(name, "bigquery_dataset_public_binding",
				"Remove allUsers/allAuthenticatedUsers bindings from the dataset IAM policy."),
		})
	}
	return out
}

func checkBigQueryDatasetCMEK(rs *ResourceSet) []Finding {
	var out []Finding
	for _, d := range rs.BigQueryDatasets {
		if datasetEncryptionKMS(d) != "" || len(d.KmsKeys) > 0 {
			continue
		}
		name := shortName(d.Name)
		out = append(out, bigQueryFinding("bigquery_dataset_cmek", name,
			"BigQuery dataset has no customer-managed encryption key (CMEK)",
			[]string{"CC6.7", "C1.1"}, "low",
			map[string]any{"project_id": rs.ProjectID, "location": d.Location},
			"Attach a Cloud KMS key to the dataset's default encryption configuration."))
	}
	return out
}

func checkCloudRunPublicInvoker(rs *ResourceSet) []Finding {
	var out []Finding
	for _, p := range rs.PublicIAM {
		if !strings.Contains(p.AssetType, "run.googleapis.com/Service") {
			continue
		}
		member, ok := iamResultHasPublicMember(p)
		if !ok {
			continue
		}
		name := shortName(p.Resource)
		out = append(out, Finding{
			ResourceType: "google_cloud_run_service",
			ResourceName: name,
			CheckName:    "cloud_run_public_invoker",
			Title:        "Cloud Run service allows public invocation (" + member + ")",
			Controls:     []string{"CC6.6"},
			Severity:     "critical",
			EvidenceType: "policy",
			Evidence:     map[string]any{"project_id": rs.ProjectID, "public_member": member, "resource": p.Resource},
			Remediation: cloudRunRemediation(name, "cloud_run_public_invoker",
				"Restrict the invoker IAM binding to authorized identities; remove allUsers/allAuthenticatedUsers."),
		})
	}
	return out
}

func checkCloudRunCMEK(rs *ResourceSet) []Finding {
	var out []Finding
	for _, s := range rs.CloudRunServices {
		if len(s.KmsKeys) > 0 {
			continue
		}
		name := shortName(s.Name)
		out = append(out, Finding{
			ResourceType: "google_cloud_run_service",
			ResourceName: name,
			CheckName:    "cloud_run_cmek",
			Title:        "Cloud Run service does not use a customer-managed encryption key (CMEK)",
			Controls:     []string{"CC6.7", "C1.1"},
			Severity:     "low",
			EvidenceType: "config",
			Evidence:     map[string]any{"project_id": rs.ProjectID, "location": s.Location},
			Remediation: cloudRunRemediation(name, "cloud_run_cmek",
				"Configure a customer-managed key for the Cloud Run service so data is encrypted with your KMS key."),
		})
	}
	return out
}

func checkPubSubTopicCMEK(rs *ResourceSet) []Finding {
	var out []Finding
	for _, t := range rs.PubSubTopics {
		if len(t.KmsKeys) > 0 {
			continue
		}
		name := shortName(t.Name)
		out = append(out, Finding{
			ResourceType: "google_pubsub_topic",
			ResourceName: name,
			CheckName:    "pubsub_topic_cmek",
			Title:        "Pub/Sub topic is not encrypted with a customer-managed key (CMEK)",
			Controls:     []string{"CC6.7", "C1.1"},
			Severity:     "low",
			EvidenceType: "config",
			Evidence:     map[string]any{"project_id": rs.ProjectID},
			Remediation: pubsubRemediation(name, "pubsub_topic_cmek",
				"Create the topic with a Cloud KMS key (kms_key_name) to use CMEK."),
		})
	}
	return out
}

func checkInstanceTemplateShielded(rs *ResourceSet) []Finding {
	var out []Finding
	for _, t := range rs.InstanceTemplates {
		if templateShielded(t) {
			continue
		}
		name := t.Name
		if name == "" {
			name = "unknown"
		}
		out = append(out, Finding{
			ResourceType: "google_compute_instance_template",
			ResourceName: name,
			CheckName:    "instance_template_shielded",
			Title:        "Instance template does not enforce Shielded VM",
			Controls:     []string{"CC6.1"},
			Severity:     "high",
			EvidenceType: "config",
			Evidence:     map[string]any{"project_id": rs.ProjectID},
			Remediation: instanceTemplateRemediation(name, "instance_template_shielded",
				"Enable secure boot, vTPM, and integrity monitoring in the template's shielded_instance_config."),
		})
	}
	return out
}

func templateShielded(t *compute.InstanceTemplate) bool {
	if t.Properties == nil || t.Properties.ShieldedInstanceConfig == nil {
		return false
	}
	c := t.Properties.ShieldedInstanceConfig
	return c.EnableSecureBoot && c.EnableVtpm && c.EnableIntegrityMonitoring
}

// caiChecks lists all CAI-depth check funcs, invoked by Evaluate.
func caiChecks() []func(*ResourceSet) []Finding {
	return []func(*ResourceSet) []Finding{
		checkBigQueryDatasetPublicBinding,
		checkBigQueryDatasetCMEK,
		checkCloudRunPublicInvoker,
		checkCloudRunCMEK,
		checkPubSubTopicCMEK,
		checkInstanceTemplateShielded,
	}
}

package analysis

import (
	"fmt"
	"strings"
)

// slugFor converts a GCP resource name into a terraform-valid resource label.
func slugFor(name string) string {
	var b strings.Builder
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			if b.Len() > 0 && !strings.HasSuffix(b.String(), "_") && name[i-1] != '-' {
				b.WriteByte('_')
			}
			b.WriteRune(r + 32)
		case r == '-' || r == '.' || r == '/' || r == '_':
			if b.Len() > 0 && !strings.HasSuffix(b.String(), "_") {
				b.WriteByte('_')
			}
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		out = "resource"
	}
	if out[0] >= '0' && out[0] <= '9' {
		out = "r_" + out
	}
	return out
}

func remediate(rType, rName, check string, tfConfig, notes string) Remediation {
	label := slugFor(rName)
	address := rType + "." + label
	importCmd := fmt.Sprintf("terraform import %s %s", address, rName)
	if strings.HasPrefix(rName, "projects/") || strings.HasPrefix(rName, "//") || strings.Contains(rName, " ") {
		importCmd = fmt.Sprintf("terraform import %s %q", address, rName)
	}
	return Remediation{
		ImportCommand:   importCmd,
		ResourceAddress: address,
		ResourceType:    rType,
		TerraformConfig: tfConfig,
		Notes:           notes,
	}
}

// bucketRemediation emits a compliant storage bucket snippet for the given bucket.
func bucketRemediation(rName, check, notes string) Remediation {
	cfg := `resource "google_storage_bucket" "` + slugFor(rName) + `" {
  name                        = "` + rName + `"
  project                     = var.project_id
  location                    = var.location
  uniform_bucket_level_access = true     # IAM-only access (CC6.1, CC6.6)
  versioning {
    enabled = true                        # A1.2 object recoverability
  }
  # force_destroy must remain false to protect data
  encryption {
    default_kms_key_name = "projects/PROJECT_ID/locations/global/keyRings/RING/cryptoKeys/KEY" # optional CMEK (CC6.7)
  }
}

variable "project_id"  { default = "YOUR_PROJECT" }
variable "location"    { default = "US" }`
	return remediate("google_storage_bucket", rName, check, cfg, notes)
}

func sqlRemediation(rName, check, notes string) Remediation {
	cfg := `resource "google_sql_database_instance" "` + slugFor(rName) + `" {
  project             = var.project_id
  name                = "` + rName + `"
  database_version    = "POSTGRES_15"
  region              = var.region
  deletion_protection = true                     # A1.3

  settings {
    tier              = "db-f1-micro"
    availability_type = "REGIONAL"               # A1.1 HA
    disk_encryption_key_name = "projects/PROJECT_ID/locations/REGION/keyRings/RING/cryptoKeys/KEY" # optional CMEK (CC6.7)

    ip_configuration {
      ipv4_enabled    = false                    # no public IP (CC6.6)
      ssl_mode        = "ENCRYPTED_ONLY"         # CC6.7 TLS
      require_ssl     = true
      private_network = var.private_network
    }

    backup_configuration {
      enabled            = true                  # A1.2 automated backups
      binary_log_enabled = true                  # PITR
      start_time         = "03:00"
    }
  }
}

variable "project_id"      { default = "YOUR_PROJECT" }
variable "region"          { default = "us-central1" }
variable "private_network" { default = "projects/YOUR_PROJECT/global/networks/default" }`
	return remediate("google_sql_database_instance", rName, check, cfg, notes)
}

func subnetRemediation(rName, check, notes string) Remediation {
	cfg := `resource "google_compute_subnetwork" "` + slugFor(rName) + `" {
  name          = "` + rName + `"
  ip_cidr_range = "10.0.0.0/24"
  region        = var.region
  network       = var.network
  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }                                                # CC7.2 flow logs
}

variable "network"     { default = "projects/YOUR_PROJECT/global/networks/default" }
variable "region"      { default = "us-central1" }`
	return remediate("google_compute_subnetwork", rName, check, cfg, notes)
}

func projectIAMRemediation(member, role, notes string) Remediation {
	cfg := fmt.Sprintf(`# Remove %q (role %q) from the project
resource "google_project_iam_member" "removed" {
  project = var.project_id
  role    = %q
  member  = %q
}
`, member, role, role, member)
	rem := remediate("google_project_iam_member", "removed", "project_primitive_roles", cfg, notes)
	rem.ImportCommand = fmt.Sprintf("gcloud projects remove-iam-policy-binding YOUR_PROJECT --member=%s --role=%s", member, role)
	return rem
}

func saKeyRemediation(email, notes string) Remediation {
	cfg := `# Delete the user-managed key (k1) and disable it so it can no longer be used.
resource "google_service_account_key" "this" {
  service_account_id = var.service_account_email
  key_algorithm      = "KEY_ALG_RSA_2048"
  keepers = {
    "rotation" = "rotate-me"
  }
}

# After rotating, remove old keys:
#   gcloud iam service-accounts keys delete $KEY_ID --iam-account=$EMAIL
`
	rem := remediate("google_service_account_key", "this", "sa_user_managed_keys", cfg, notes)
	rem.ImportCommand = fmt.Sprintf("gcloud iam service-accounts keys list --iam-account=%s --managed-by=user", email)
	return rem
}

func loggingSinkRemediation(check string, notes string) Remediation {
	cfg := `resource "google_logging_project_sink" "this" {
  name        = "soc2-audit-sink"
  project     = var.project_id
  destination = "storage.googleapis.com/" + var.audit_bucket   # or a bigquery dataset
  filter      = "logName:activities AND protoPayload.serviceName:\"audit\""
  unique_writer_identity = true
}

resource "google_storage_bucket" "audit" {
  name     = var.audit_bucket
  location = "US"
}
# Attach a retention policy >= 365 days and CMEK per A1.2 / CC7.3.

variable "project_id"   { default = "YOUR_PROJECT" }
variable "audit_bucket" { default = "soc2-audit-logs" }`
	return remediate("google_logging_project_sink", "soc2-audit-sink", check, cfg, notes)
}

func kmsRemediation(rName, check, notes string) Remediation {
	cfg := `resource "google_kms_crypto_key" "` + slugFor(rName) + `" {
  name            = "` + rName + `"
  key_ring        = var.key_ring_id
  rotation_period = "7776000s"   # 90 days (CC6.1)
}
variable "key_ring_id"  { default = "projects/YOUR_PROJECT/locations/global/keyRings/YOUR_RING" }`
	return remediate("google_kms_crypto_key", rName, check, cfg, notes)
}

func secretRemediation(rName, check, notes string) Remediation {
	cfg := `# Restrict secret access - never allUsers/allAuthenticatedUsers (CC6.6)
resource "google_secret_manager_secret_iam_member" "restricted" {
  project = var.project_id
  secret_id = "` + rName + `"
  role = "roles/secretmanager.secretAccessor"
  member = "serviceAccount:YOUR-SERVICE-ACCOUNT"
}
variable "project_id" { default = "YOUR_PROJECT" }`
	return remediate("google_secret_manager_secret", rName, check, cfg, notes)
}

func computeRemediation(zone, rName, check, notes string) Remediation {
	cfg := `resource "google_compute_instance" "` + slugFor(rName) + `" {
  name         = "` + rName + `"
  zone         = "` + zone + `"
  machine_type = "e2-micro"
  tags         = ["soc2-shielded"]

  boot_disk {
    initialize_params { image = "projects/debian-cloud/global/images/family/debian-12" }
  }
  shielded_instance_config {   # CC6.1
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }
  network_interface {
    network = "default"
    # no access_config block => no public external IP (CC6.6)
  }
  metadata = {
    serial-port-enable = 0      # disable serial port access
  }
}
variable "project_id"    { default = "YOUR_PROJECT" }`
	return remediate("google_compute_instance", rName, check, cfg, notes)
}

func firewallRemediation(rName, check, notes string) Remediation {
	cfg := `# Tighten this rule to specific service accounts / source CIDR ranges (CC6.6)
resource "google_compute_firewall" "` + slugFor(rName) + `" {
  name    = "` + rName + `"
  network = var.network
  direction = "INGRESS"
  source_ranges = ["10.0.0.0/8"]   # never 0.0.0.0/0 for management/database ports
  allow {
    protocol = "tcp"
    ports    = ["22", "3389"]      # keep only what you need
  }
  log_config { metadata = "EXCLUDE_ALL_METADATA" } # CC7.2
}
variable "network"   { default = "projects/YOUR_PROJECT/global/networks/default" }`
	return remediate("google_compute_firewall", rName, check, cfg, notes)
}

func containsFilter(filter, needle string) bool {
	return strings.Contains(filter, needle)
}

func bigqueryRemediation(rName, check, notes string) Remediation {
	cfg := `resource "google_bigquery_dataset" "` + slugFor(rName) + `" {
  dataset_id = "` + rName + `"
  project    = var.project_id
  location   = "US"

  # Access restricted to authorized principals only (CC6.6)
  access {
    role          = "roles/bigquery.dataOwner"
    user_by_email = "your-owner@example.com"
  }

  # CMEK at rest (CC6.7)
  default_encryption_configuration {
    kms_key_name = "projects/PROJECT_ID/locations/global/keyRings/RING/cryptoKeys/KEY"
  }
}

variable "project_id" { default = "YOUR_PROJECT" }`
	return remediate("google_bigquery_dataset", rName, check, cfg, notes)
}

func cloudRunRemediation(rName, check, notes string) Remediation {
	cfg := `# Restrict the service to authenticated, authorized identities only (CC6.6)
resource "google_cloud_run_service_iam_member" "restricted" {
  location = var.region
  project  = var.project_id
  service  = "` + rName + `"
  role     = "roles/run.invoker"
  member   = "serviceAccount:YOUR-SERVICE-ACCOUNT"
}

# CMEK for the service's data (CC6.7)
resource "google_cloud_run_service" "` + slugFor(rName) + `" {
  name     = "` + rName + `"
  location = var.region
  template {
    metadata {
      annotations = {
        "run.googleapis.com/encryption-key" = "projects/PROJECT_ID/locations/global/keyRings/RING/cryptoKeys/KEY"
      }
    }
  }
}

variable "project_id" { default = "YOUR_PROJECT" }
variable "region"     { default = "us-central1" }`
	return remediate("google_cloud_run_service", rName, check, cfg, notes)
}

func pubsubRemediation(rName, check, notes string) Remediation {
	cfg := `resource "google_pubsub_topic" "` + slugFor(rName) + `" {
  name        = "` + rName + `"
  project     = var.project_id
  kms_key_name = "projects/PROJECT_ID/locations/global/keyRings/RING/cryptoKeys/KEY"  # CMEK (CC6.7)
}

variable "project_id" { default = "YOUR_PROJECT" }`
	return remediate("google_pubsub_topic", rName, check, cfg, notes)
}

func instanceTemplateRemediation(rName, check, notes string) Remediation {
	cfg := `resource "google_compute_instance_template" "` + slugFor(rName) + `" {
  name        = "` + rName + `"
  machine_type = "e2-micro"
  disk {
    source_image = "projects/debian-cloud/global/images/family/debian-12"
    auto_delete  = true
    boot         = true
  }
  network_interface { network = "default" }
  shielded_instance_config {   # CC6.1
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }
}

variable "project_id" { default = "YOUR_PROJECT" }`
	return remediate("google_compute_instance_template", rName, check, cfg, notes)
}

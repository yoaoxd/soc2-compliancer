terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

variable "project_id" {
  type        = string
  description = "GCP project that SOC2 Compliancer will analyze (read-only)."
}

resource "google_service_account" "soc2_analyzer" {
  account_id   = "soc2-analyzer"
  display_name = "SOC2 Compliancer read-only analyzer"
  description  = "Read-only service account used by SOC2 Compliancer to scan resources."
}

# Read-only roles required by the analyzer.
resource "google_project_iam_member" "roles" {
  for_each = toset([
    "roles/viewer",
    "roles/cloudasset.viewer",
    "roles/iam.serviceAccountViewer",
    "roles/resourcemanager.projectIamViewer",
    "roles/cloudkms.viewer",
    "roles/secretmanager.viewer",
    "roles/logging.viewer",
    "roles/compute.viewer",
    "roles/sqladmin.viewer",
  ])
  project = var.project_id
  role    = each.key
  member  = "serviceAccount:${google_service_account.soc2_analyzer.email}"
}

output "analyzer_service_account_email" {
  description = "Email of the read-only analyzer SA. Create a key with: gcloud iam service-accounts keys create key.json --iam-account=<email>"
  value       = google_service_account.soc2_analyzer.email
}
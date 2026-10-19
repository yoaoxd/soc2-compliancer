# SOC2 Compliancer — GCP read-only connector
#
# Applies this module in the project you want to analyze. It creates a service
# account with strictly read-only permissions and grants the roles the analyzer
# needs. The app never receives write credentials.
#
# Usage:
#   terraform init && terraform apply -var project_id=YOUR_PROJECT
#   gcloud iam service-accounts keys create key.json --iam-account=<output_email>
#   Upload key.json in the app (Connections → GCP → Paste service account key).

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
  description = "Email of the read-only analyzer SA."
  value       = google_service_account.soc2_analyzer.email
}
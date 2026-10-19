terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

resource "google_storage_bucket" "this" {
  name                        = var.bucket_name
  project                     = var.project_id
  location                    = var.location
  force_destroy               = var.force_destroy
  uniform_bucket_level_access = true

  # SOC2 CC6.7 / C1.1: encryption at rest (CMEK when a key is supplied,
  # otherwise Google-managed service-side encryption still applies).
  dynamic "encryption" {
    for_each = var.kms_key != "" ? [1] : []
    content {
      default_kms_key_name = var.kms_key
    }
  }

  # SOC2 A1.2: versioning + retention for recoverability.
  versioning {
    enabled = true
  }

  retention_policy {
    is_locked        = var.lock_retention
    retention_period = var.retention_days * 86400
  }
}
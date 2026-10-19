terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

resource "google_kms_key_ring" "this" {
  name     = var.key_ring_name
  location = var.location
  project  = var.project_id
}

resource "google_kms_crypto_key" "this" {
  name     = var.crypto_key_name
  key_ring = google_kms_key_ring.this.id

  # SOC2 CC6.1: automatic rotation keeps keys from aging
  rotation_period = var.rotation_seconds

  # SOC2 CC6.1 / C1.1: soft-delete of destroyed keys, no hard destroy
  purpose = "ENCRYPT_DECRYPT"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "SOFTWARE"
  }
}

# SOC2 CC6.2: least-privilege example grantor (empty by default, never "allUsers")
resource "google_kms_crypto_key_iam_member" "service_account" {
  count         = var.iam_member != "" ? 1 : 0
  crypto_key_id = google_kms_crypto_key.this.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = var.iam_member
}

output "key_id" {
  value = google_kms_crypto_key.this.id
}
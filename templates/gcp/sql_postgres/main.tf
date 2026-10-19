terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

resource "google_sql_database_instance" "postgres" {
  name                = var.instance_name
  project             = var.project_id
  region              = var.region
  database_version    = "POSTGRES_16"
  deletion_protection = true

  # SOC2 CC6.7 / C1.1: CMEK disk encryption when a key is supplied.
  encryption_key_name = var.kms_key != "" ? var.kms_key : null

  settings {
    tier              = var.tier
    disk_type         = var.disk_type
    disk_size         = var.disk_size_gb
    availability_type = "REGIONAL" # SOC2 A1.1: high availability

    ip_configuration {
      ssl_mode        = "ENCRYPTED_ONLY" # SOC2 CC6.7: encrypted connections only
      ipv4_enabled    = var.enable_public_ip
      private_network = var.private_network != "" ? var.private_network : null

      # SOC2 CC6.6 / A1.2: explicit ingress allowlist only, never 0.0.0.0/0.
      dynamic "authorized_networks" {
        for_each = var.authorized_networks
        content {
          name  = authorized_networks.value.name
          value = authorized_networks.value.value
        }
      }
    }

    backup_configuration {
      enabled                        = true # SOC2 A1.2
      start_time                     = "03:00"
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = "7"
    }
  }
}

output "instance_name" {
  value = google_sql_database_instance.postgres.name
}

output "private_ip" {
  value = google_sql_database_instance.postgres.private_ip_address
}
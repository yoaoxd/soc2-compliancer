terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

resource "azurerm_postgresql_flexible_server" "this" {
  name                   = var.server_name
  resource_group_name    = var.resource_group_name
  location               = var.location
  version                = "16"
  administrator_login    = var.administrator_login
  administrator_password = var.administrator_password
  storage_mb             = 32768
  sku_name               = var.sku_name

  # SOC2 CC6.6: private networking only, no public access.
  public_network_access_enabled = false

  # SOC2 CC6.7: TLS is enforced by flexible server (min TLS 1.2).

  # SOC2 A1.1: zone-redundant high availability.
  high_availability {
    mode = var.zone_redundant_ha ? "ZoneRedundant" : "SameZone"
  }

  # SOC2 A1.2: automated backups with retention + geo-redundancy.
  backup_retention_days        = var.backup_retention_days
  geo_redundant_backup_enabled = true

  # SOC2 A1.3: protect against accidental deletion (no deletion_protection_enabled
  # on flexible server; reliance is on geo-redundant backups + RBAC).
  # SOC2 CC6.7 / C1.1: customer-managed key encryption when a key id is supplied.
  dynamic "customer_managed_key" {
    for_each = var.kms_key != "" ? [1] : []
    content {
      key_vault_key_id = var.kms_key
    }
  }
}

output "server_id" {
  value = azurerm_postgresql_flexible_server.this.id
}

output "fqdn" {
  value = azurerm_postgresql_flexible_server.this.fqdn
}
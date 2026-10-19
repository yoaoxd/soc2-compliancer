terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

resource "azurerm_storage_account" "this" {
  name                              = var.account_name
  resource_group_name               = var.resource_group_name
  location                          = var.location
  account_tier                      = "Standard"
  account_replication_type          = "GRS"
  min_tls_version                   = var.min_tls_version
  allow_nested_items_to_be_public   = false # SOC2 CC6.1/CC6.6: no public blob access
  public_network_access_enabled     = false # SOC2 CC6.6: private access only
  infrastructure_encryption_enabled = true  # SOC2 CC6.7: double encryption at rest

  identity { type = "SystemAssigned" }

  blob_properties {
    versioning_enabled = var.enable_versioning # SOC2 A1.2
    delete_retention_policy {
      days = var.retention_days # SOC2 A1.2/C1.2
    }
    container_delete_retention_policy {
      days = var.retention_days
    }
  }
}

# SOC2 CC6.7 / C1.1: customer-managed key encryption when a key vault key id is supplied.
resource "azurerm_storage_account_customer_managed_key" "this" {
  count              = var.kms_key != "" ? 1 : 0
  storage_account_id = azurerm_storage_account.this.id
  key_vault_uri      = local.kv_uri
  key_name           = local.kv_name
  key_version        = local.kv_version
}

locals {
  kv_parts = var.kms_key != "" ? split("/", var.kms_key) : []
  # e.g. ["https:", "", "myvault.vault.azure.net", "keys", "mykey", "version"]
  kv_uri     = local.kv_parts != [] ? join("/", slice(local.kv_parts, 0, 3)) : ""
  kv_name    = length(local.kv_parts) > 4 ? local.kv_parts[4] : ""
  kv_version = length(local.kv_parts) > 5 ? local.kv_parts[5] : ""
}

output "storage_account_id" {
  value = azurerm_storage_account.this.id
}

output "primary_blob_endpoint" {
  value = azurerm_storage_account.this.primary_blob_endpoint
}
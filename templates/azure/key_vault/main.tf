terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "this" {
  name                          = var.vault_name
  resource_group_name           = var.resource_group_name
  location                      = var.location
  tenant_id                     = var.tenant_id
  sku_name                      = "standard"
  soft_delete_retention_days    = var.soft_delete_retention_days
  purge_protection_enabled      = true # SOC2 C1.2: no hard purge
  enabled_for_disk_encryption   = var.enabled_for_disk_encryption
  public_network_access_enabled = false # SOC2 CC6.6: private access only

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
}

# SOC2 CC6.2: example least-privilege policy for the analyzer identity.
resource "azurerm_key_vault_access_policy" "this" {
  key_vault_id = azurerm_key_vault.this.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = data.azurerm_client_config.current.object_id

  key_permissions    = ["Get", "List", "UnwrapKey", "WrapKey", "Decrypt", "Encrypt"]
  secret_permissions = ["Get", "List"]
}

# SOC2 CC6.7 / C1.1: a rotation-enabled symmetric key for CMEK use by dependent modules.
resource "azurerm_key_vault_key" "soc2" {
  name         = "soc2-key"
  key_vault_id = azurerm_key_vault.this.id
  key_type     = "RSA"
  key_size     = 3072
  key_opts     = ["decrypt", "encrypt", "unwrapKey", "wrapKey", "sign", "verify"]
  rotation_policy {
    automatic {
      time_before_expiry = "P30D"
    }
    expire_after         = "P90D" # SOC2 CC6.1: rotation
    notify_before_expiry = "P15D"
  }
}

output "key_vault_id" {
  value = azurerm_key_vault.this.id
}

output "key_vault_uri" {
  value = azurerm_key_vault.this.vault_uri
}

output "key_vault_key_id" {
  description = "Key id for customer-managed key encryption in dependent modules (CMEK)."
  value       = azurerm_key_vault_key.soc2.id
}
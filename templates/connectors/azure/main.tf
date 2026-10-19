terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.0"
    }
  }
}

data "azurerm_client_config" "current" {}
data "azurerm_subscription" "current" {}

# Read-only service principal used by the SOC2 Compliancer analyzer.
resource "azuread_application" "soc2_analyzer" {
  display_name = "soc2-compliance-analyzer"
}

resource "azuread_service_principal" "soc2_analyzer" {
  client_id = azuread_application.soc2_analyzer.client_id
}

# ReadOnly RBAC assignment at subscription scope (analyzer never mutates).
resource "azurerm_role_assignment" "readonly" {
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Reader"
  principal_id         = azuread_service_principal.soc2_analyzer.object_id
}

# Allow the analyzer to read secrets in Key Vaults (Reader doesn't cover secrets).
resource "azurerm_role_assignment" "secrets" {
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Key Vault Reader"
  principal_id         = azuread_service_principal.soc2_analyzer.object_id
}

output "application_id" {
  description = "Client id (application id) of the read-only analyzer service principal."
  value       = azuread_application.soc2_analyzer.client_id
}

output "tenant_id" {
  description = "Tenant id of the Azure AD tenant."
  value       = data.azurerm_client_config.current.tenant_id
}

output "subscription_id" {
  description = "Subscription id the analyzer will scan."
  value       = data.azurerm_subscription.current.id
}
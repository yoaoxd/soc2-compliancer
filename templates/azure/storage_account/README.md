# storage_account

SOC2-compliant Azure Storage account: public access disabled, private network,
TLS 1.2, infrastructure double-encryption, optional CMEK via Key Vault
(CC6.6/CC6.7/C1.1), blob versioning and soft-delete retention (A1.2/C1.2).

Requires the `azurerm` provider. See `variables.tf`.
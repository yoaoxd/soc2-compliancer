package analysis

import "strings"

// --- Storage accounts ---

func checkAzureStoragePublicAccess(rs *ResourceSet) []Finding {
	var out []Finding
	for _, a := range rs.AzureStorage {
		if !a.PublicAccess {
			continue
		}
		out = append(out, azureFinding("azurerm_storage_account", a.Name, "azure_storage_public_access",
			"Storage account allows public blob access",
			[]string{"CC6.1", "CC6.6"}, "critical",
			map[string]any{"resource_group": a.ResourceGroup},
			azureStorageRemediation(a.Name, "azure_storage_public_access",
				"Disable public access (allow_nested_items_to_be_public = false) and enable private networking.")))
	}
	return out
}

func checkAzureStorageMinTLS(rs *ResourceSet) []Finding {
	var out []Finding
	for _, a := range rs.AzureStorage {
		if strings.HasPrefix(a.MinTLS, "TLS1_2") || strings.HasPrefix(a.MinTLS, "TLS1_3") {
			continue
		}
		out = append(out, azureFinding("azurerm_storage_account", a.Name, "azure_storage_min_tls",
			"Storage account does not require TLS 1.2+",
			[]string{"CC6.7"}, "high",
			map[string]any{"min_tls_version": a.MinTLS},
			azureStorageRemediation(a.Name, "azure_storage_min_tls",
				"Set min_tls_version = \"TLS1_2\" (or higher).")))
	}
	return out
}

func checkAzureStorageInfraEncryption(rs *ResourceSet) []Finding {
	var out []Finding
	for _, a := range rs.AzureStorage {
		if a.InfraEncrypted {
			continue
		}
		out = append(out, azureFinding("azurerm_storage_account", a.Name, "azure_storage_infra_encryption",
			"Storage account does not enable infrastructure double encryption",
			[]string{"CC6.7", "C1.1"}, "low",
			map[string]any{"resource_group": a.ResourceGroup},
			azureStorageRemediation(a.Name, "azure_storage_infra_encryption",
				"Enable infrastructure_encryption_enabled = true.")))
	}
	return out
}

func azureStorageRemediation(rName, check, notes string) Remediation {
	cfg := `resource "azurerm_storage_account" "` + slugFor(rName) + `" {
  name                     = "` + rName + `"
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "GRS"
  min_tls_version          = "TLS1_2"                  # CC6.7
  allow_nested_items_to_be_public = false              # CC6.1/CC6.6
  public_network_access_enabled   = false              # CC6.6
  infrastructure_encryption_enabled = true             # CC6.7

  blob_properties {
    versioning_enabled = true                          # A1.2
    delete_retention_policy { days = 365 }             # A1.2/C1.2
  }
}

variable "resource_group_name" {}
variable "location"           { default = "eastus2" }`
	return remediate("azurerm_storage_account", rName, check, cfg, notes)
}

// --- Postgres flexible ---

func checkAzurePostgresPublicNetwork(rs *ResourceSet) []Finding {
	var out []Finding
	for _, p := range rs.AzurePostgres {
		if !p.PublicNetwork {
			continue
		}
		out = append(out, azureFinding("azurerm_postgresql_flexible_server", p.Name, "azure_postgres_public_network",
			"PostgreSQL server allows public network access",
			[]string{"CC6.6"}, "high",
			map[string]any{"resource_group": p.ResourceGroup},
			azurePostgresRemediation(p.Name, "azure_postgres_public_network",
				"Disable public network access; use private endpoints / VNet integration.")))
	}
	return out
}

func checkAzurePostgresHA(rs *ResourceSet) []Finding {
	var out []Finding
	for _, p := range rs.AzurePostgres {
		if p.ZoneRedundantHA {
			continue
		}
		out = append(out, azureFinding("azurerm_postgresql_flexible_server", p.Name, "azure_postgres_ha",
			"PostgreSQL server is not zone-redundant HA",
			[]string{"A1.1", "A1.3"}, "medium",
			map[string]any{"resource_group": p.ResourceGroup},
			azurePostgresRemediation(p.Name, "azure_postgres_ha",
				"Enable zone-redundant high availability (high_availability.mode = \"ZoneRedundant\").")))
	}
	return out
}

func checkAzurePostgresBackups(rs *ResourceSet) []Finding {
	var out []Finding
	for _, p := range rs.AzurePostgres {
		if p.BackupRetention >= 7 && p.GeoBackup {
			continue
		}
		out = append(out, azureFinding("azurerm_postgresql_flexible_server", p.Name, "azure_postgres_backups",
			"PostgreSQL automated backups are insufficient (retention < 7 days or no geo-redundancy)",
			[]string{"A1.2"}, "high",
			map[string]any{"retention_days": p.BackupRetention, "geo_backup": p.GeoBackup},
			azurePostgresRemediation(p.Name, "azure_postgres_backups",
				"Set backup_retention_days >= 7 and geo_redundant_backup_enabled = true.")))
	}
	return out
}

func checkAzurePostgresDeletionProtection(rs *ResourceSet) []Finding {
	var out []Finding
	for _, p := range rs.AzurePostgres {
		if p.DeletionProtection {
			continue
		}
		out = append(out, azureFinding("azurerm_postgresql_flexible_server", p.Name, "azure_postgres_deletion_protection",
			"PostgreSQL server has no deletion protection",
			[]string{"A1.3", "C1.2"}, "medium",
			map[string]any{"resource_group": p.ResourceGroup},
			azurePostgresRemediation(p.Name, "azure_postgres_deletion_protection",
				"Enable deletion_protection_enabled = true (point-in-time restore to A1.3).")))
	}
	return out
}

func azurePostgresRemediation(rName, check, notes string) Remediation {
	cfg := `resource "azurerm_postgresql_flexible_server" "` + slugFor(rName) + `" {
  name                   = "` + rName + `"
  resource_group_name    = var.resource_group_name
  location               = var.location
  version                = "16"
  administrator_login    = var.administrator_login
  administrator_password = var.administrator_password
  sku_name               = "B_Standard_B1ms"

  public_network_access_enabled = false              # CC6.6

  high_availability {
    mode = "ZoneRedundant"                           # A1.1
  }

  backup_retention_days        = 30                  # A1.2
  geo_redundant_backup_enabled = true                # A1.2

  deletion_protection_enabled = true                 # A1.3/C1.2
}

variable "resource_group_name" {}
variable "location"           { default = "eastus2" }
variable "administrator_login" {}
variable "administrator_password" {}`
	return remediate("azurerm_postgresql_flexible_server", rName, check, cfg, notes)
}

// --- Key Vault ---

func checkAzureKeyVaultSoftDelete(rs *ResourceSet) []Finding {
	var out []Finding
	for _, kv := range rs.AzureKeyVaults {
		if kv.SoftDelete && kv.PurgeProtect {
			continue
		}
		out = append(out, azureFinding("azurerm_key_vault", kv.Name, "azure_key_vault_soft_delete",
			"Key Vault does not enforce soft delete + purge protection",
			[]string{"C1.2", "A1.3"}, "high",
			map[string]any{"resource_group": kv.ResourceGroup, "soft_delete": kv.SoftDelete, "purge_protection": kv.PurgeProtect},
			azureKeyVaultRemediation(kv.Name, "azure_key_vault_soft_delete",
				"Enable soft delete (90 days) and purge protection on the vault.")))
	}
	return out
}

func checkAzureKeyVaultPublicNetwork(rs *ResourceSet) []Finding {
	var out []Finding
	for _, kv := range rs.AzureKeyVaults {
		if !kv.PublicNetwork {
			continue
		}
		out = append(out, azureFinding("azurerm_key_vault", kv.Name, "azure_key_vault_public_network",
			"Key Vault allows public network access",
			[]string{"CC6.6", "C1.1"}, "high",
			map[string]any{"resource_group": kv.ResourceGroup},
			azureKeyVaultRemediation(kv.Name, "azure_key_vault_public_network",
				"Restrict network access (public_network_access_enabled = false + network ACLs).")))
	}
	return out
}

func azureKeyVaultRemediation(rName, check, notes string) Remediation {
	cfg := `resource "azurerm_key_vault" "` + slugFor(rName) + `" {
  name                = "` + rName + `"
  resource_group_name = var.resource_group_name
  location            = var.location
  tenant_id           = var.tenant_id
  sku_name            = "standard"

  soft_delete_retention_days = 90                    # C1.2/A1.3
  purge_protection_enabled   = true                  # C1.2
  public_network_access_enabled = false              # CC6.6/C1.1

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
}

variable "resource_group_name" {}
variable "location"           { default = "eastus2" }
variable "tenant_id"          {}`
	return remediate("azurerm_key_vault", rName, check, cfg, notes)
}

// --- VMs / NSGs ---

func checkAzureVMPublicIP(rs *ResourceSet) []Finding {
	var out []Finding
	for _, vm := range rs.AzureVMs {
		if !vm.PublicIP {
			continue
		}
		out = append(out, azureFinding("azurerm_virtual_machine", vm.Name, "azure_vm_public_ip",
			"Virtual machine is associated with a public IP",
			[]string{"CC6.6"}, "high",
			map[string]any{"resource_id": vm.ResourceID},
			azureVMRemediation(vm.Name, "azure_vm_public_ip",
				"Remove the public IP; use a private NIC + NAT gateway / Azure Bastion.")))
	}
	return out
}

func azureVMRemediation(rName, check, notes string) Remediation {
	cfg := `resource "azurerm_network_interface" "` + slugFor(rName) + `" {
  name                = "` + rName + `-nic"
  resource_group_name = var.resource_group_name
  location            = var.location

  ip_configuration {
    name                          = "internal"
    subnet_id                     = var.private_subnet_id  # CC6.6: no public IP
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_linux_virtual_machine" "` + slugFor(rName) + `" {
  name                  = "` + rName + `"
  resource_group_name   = var.resource_group_name
  location              = var.location
  network_interface_ids = [azurerm_network_interface.` + slugFor(rName) + `.id]
  size                  = "Standard_B1s"
  admin_username        = var.admin_username
  admin_ssh_key {
    username   = var.admin_username
    public_key = var.admin_ssh_public_key
  }
  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }
}

variable "resource_group_name" {}
variable "location"           { default = "eastus2" }
variable "private_subnet_id"  {}
variable "admin_username"     {}
variable "admin_ssh_public_key" {}`
	return remediate("azurerm_linux_virtual_machine", rName, check, cfg, notes)
}

func checkAzureNSGBroadIngress(rs *ResourceSet) []Finding {
	var out []Finding
	badPorts := map[int32]bool{22: true, 3389: true, 5432: true, 3306: true, 1433: true, 6379: true, 27017: true}
	for _, nsg := range rs.AzureNSGs {
		for _, rule := range nsg.Ingress {
			if !rule.PublicSource {
				continue
			}
			openAll := rule.AllProtocol && rule.FromPort == 0 && rule.ToPort == 0
			sensitive := rule.FromPort != 0 && badPorts[rule.FromPort]
			if !openAll && !sensitive {
				continue
			}
			sev := "high"
			if openAll {
				sev = "critical"
			}
			out = append(out, azureFinding("azurerm_network_security_group", nsg.Name, "azure_nsg_broad_ingress",
				"NSG allows broad ingress from the internet on sensitive port/protocol",
				[]string{"CC6.6"}, sev,
				map[string]any{"resource_group": nsg.ResourceGroup, "from_port": rule.FromPort},
				azureNSGRemediation(nsg.Name, "azure_nsg_broad_ingress",
					"Tighten source address prefixes; never allow * / 0.0.0.0/0 on management/DB ports.")))
			break
		}
	}
	return out
}

func azureNSGRemediation(rName, check, notes string) Remediation {
	cfg := `resource "azurerm_network_security_group" "` + slugFor(rName) + `" {
  name                = "` + rName + `"
  resource_group_name = var.resource_group_name
  location            = var.location

  security_rule {
    name                       = "soc2-restricted-ingress"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefixes    = ["10.0.0.0/8"]   # CC6.6: only admin CIDR
    destination_address_prefix = "*"
  }
}

variable "resource_group_name" {}
variable "location"           { default = "eastus2" }`
	return remediate("azurerm_network_security_group", rName, check, cfg, notes)
}

// azureFinding builds a finding with config evidence type.
func azureFinding(rType, rName, check, title string, controls []string, sev string, evidence map[string]any, rem Remediation) Finding {
	return Finding{
		ResourceType: rType,
		ResourceName: rName,
		CheckName:    check,
		Title:        title,
		Controls:     controls,
		Severity:     sev,
		EvidenceType: "config",
		Evidence:     evidence,
		Remediation:  rem,
	}
}

// azureChecks lists all Azure check funcs, invoked by Evaluate when Azure data present.
func azureChecks() []func(*ResourceSet) []Finding {
	return []func(*ResourceSet) []Finding{
		checkAzureStoragePublicAccess,
		checkAzureStorageMinTLS,
		checkAzureStorageInfraEncryption,
		checkAzurePostgresPublicNetwork,
		checkAzurePostgresHA,
		checkAzurePostgresBackups,
		checkAzurePostgresDeletionProtection,
		checkAzureKeyVaultSoftDelete,
		checkAzureKeyVaultPublicNetwork,
		checkAzureVMPublicIP,
		checkAzureNSGBroadIngress,
	}
}
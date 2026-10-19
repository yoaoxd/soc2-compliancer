variable "server_name" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "location" {
  type    = string
  default = "eastus2"
}

variable "administrator_login" {
  type = string
}

variable "administrator_password" {
  type      = string
  sensitive = true
}

variable "sku_name" {
  type    = string
  default = "B_Standard_B1ms"
}

variable "zone_redundant_ha" {
  type        = bool
  default     = true
  description = "Zone-redundant high availability (SOC2 A1.1)."
}

variable "backup_retention_days" {
  type        = number
  default     = 30
  description = "Automated backup retention in days (SOC2 A1.2)."
}

variable "kms_key" {
  type        = string
  default     = ""
  description = "Key Vault key id for customer-managed encryption (CMEK); empty = platform-managed"
}

variable "private_dns_zone_id" {
  type        = string
  default     = ""
  description = "Private DNS zone id for private networking"
}
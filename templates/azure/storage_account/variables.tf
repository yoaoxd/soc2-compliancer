variable "account_name" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "location" {
  type    = string
  default = "eastus2"
}

variable "kms_key" {
  type        = string
  default     = ""
  description = "Key Vault key id for customer-managed key encryption (CMEK); empty = platform-managed"
}

variable "min_tls_version" {
  type    = string
  default = "TLS1_2"
}

variable "enable_versioning" {
  type    = bool
  default = true
}

variable "retention_days" {
  type    = number
  default = 365
}
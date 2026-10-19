variable "project_id" {
  type = string
}

variable "instance_name" {
  type = string
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "tier" {
  type    = string
  default = "db-f1-micro"
}

variable "disk_type" {
  type    = string
  default = "PD_SSD"
}

variable "disk_size_gb" {
  type    = number
  default = 10
}

variable "kms_key" {
  type        = string
  default     = ""
  description = "CMEK key self-link for disk encryption"
}

variable "private_network" {
  type        = string
  default     = ""
  description = "VPC self-link for private IP; empty = default public IP mode"
}

variable "enable_public_ip" {
  type        = bool
  default     = true
  description = "Grant a public IPv4 address. Prefer false with private_network."
}

variable "authorized_networks" {
  type        = list(map(string))
  default     = []
  description = "List of {name, value} networks for ingress allowlist (never 0.0.0.0/0)."
}
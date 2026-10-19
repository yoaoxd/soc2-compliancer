variable "project_id" {
  type = string
}

variable "key_ring_name" {
  type    = string
  default = "soc2-keyring"
}

variable "crypto_key_name" {
  type    = string
  default = "soc2-key"
}

variable "location" {
  type    = string
  default = "global"
}

variable "rotation_seconds" {
  type        = number
  default     = 7776000
  description = "Key rotation period (default 90 days)"
}

variable "iam_member" {
  type        = string
  default     = ""
  description = "Service account (serviceAccount:...) to grant ENCRYPT/DECRYPT; empty = none"
}
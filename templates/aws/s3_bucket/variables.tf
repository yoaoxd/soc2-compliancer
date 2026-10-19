variable "bucket_name" {
  type = string
}

variable "force_destroy" {
  type        = bool
  default     = false
  description = "Allow Terraform to destroy a bucket with objects (keep false for SOC2)."
}

variable "kms_key" {
  type        = string
  default     = ""
  description = "KMS key ARN for SSE-KMS (CMEK); empty = AES256"
}

variable "versioning_enabled" {
  type    = bool
  default = true
}

variable "object_lock_enabled" {
  type        = bool
  default     = true
  description = "Compliance object lock for write-once retention."
}

variable "retention_days" {
  type        = number
  default     = 365
  description = "Default object lock retention in days."
}
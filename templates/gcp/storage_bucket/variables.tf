variable "project_id" {
  description = "GCP project where the bucket is created."
  type        = string
}

variable "bucket_name" {
  description = "Globally unique name for the bucket."
  type        = string
}

variable "location" {
  description = "GCS location (e.g. US, EU, us-central1)."
  type        = string
  default     = "US"
}

variable "kms_key" {
  description = "CMEK key self-link (projects/X/locations/Y/keyRings/Z/cryptoKeys/W) or empty for SSE."
  type        = string
  default     = ""
}

variable "retention_days" {
  description = "Object retention period in days (SOC2 A1.2 / confidentiality policies)."
  type        = number
  default     = 365
}

variable "lock_retention" {
  description = "Whether to permanently lock the retention policy."
  type        = bool
  default     = false
}

variable "force_destroy" {
  description = "Allow bucket deletion with contents. Keep false for protected data."
  type        = bool
  default     = false
}
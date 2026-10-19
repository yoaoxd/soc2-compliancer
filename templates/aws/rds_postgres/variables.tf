variable "instance_identifier" {
  type = string
}

variable "db_name" {
  type    = string
  default = "soc2db"
}

variable "username" {
  type = string
}

variable "password" {
  type      = string
  sensitive = true
}

variable "instance_class" {
  type    = string
  default = "db.t3.micro"
}

variable "allocated_storage_gb" {
  type    = number
  default = 20
}

variable "multi_az" {
  type        = bool
  default     = true
  description = "Multi-AZ deployment for high availability (SOC2 A1.1)."
}

variable "backup_retention_days" {
  type        = number
  default     = 30
  description = "Automated backup retention in days (SOC2 A1.2)."
}

variable "kms_key" {
  type        = string
  default     = ""
  description = "KMS key ARN for EBS encryption; empty = AWS-managed key"
}
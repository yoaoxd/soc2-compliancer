output "bucket_name" {
  description = "Name of the created bucket."
  value       = google_storage_bucket.this.name
}

output "bucket_self_link" {
  description = "Self-link of the created bucket."
  value       = google_storage_bucket.this.self_link
}

output "encryption_kms_key" {
  description = "CMEK key in use (empty for SSE)."
  value       = var.kms_key
}
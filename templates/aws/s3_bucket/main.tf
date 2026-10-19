terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

resource "aws_s3_bucket" "this" {
  bucket        = var.bucket_name
  force_destroy = var.force_destroy

  # SOC2 A1.2: object lock requires the flag at creation time.
  object_lock_enabled = var.object_lock_enabled
}

# SOC2 CC6.1 / CC6.6: block all public access — access only via IAM policies.
resource "aws_s3_bucket_public_access_block" "this" {
  bucket = aws_s3_bucket.this.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# SOC2 CC6.7 / C1.1: encryption at rest — SSE-KMS (CMEK) when a key is supplied,
# otherwise AWS-managed AES256 still protects at rest.
resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key != "" ? "aws:kms" : "AES256"
      kms_master_key_id = var.kms_key != "" ? var.kms_key : null
    }
  }
}

# SOC2 A1.2: versioning for object recoverability.
resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id

  versioning_configuration {
    status = var.versioning_enabled ? "Enabled" : "Suspended"
  }
}

# SOC2 A1.2 / C1.2: compliance object lock retention when enabled.
resource "aws_s3_bucket_object_lock_configuration" "this" {
  count  = var.object_lock_enabled ? 1 : 0
  bucket = aws_s3_bucket.this.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.retention_days
    }
  }
}

output "bucket_id" {
  value = aws_s3_bucket.this.id
}

output "bucket_arn" {
  value = aws_s3_bucket.this.arn
}
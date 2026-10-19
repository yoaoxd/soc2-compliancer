terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

resource "aws_db_instance" "postgres" {
  identifier          = var.instance_identifier
  engine              = "postgres"
  engine_version      = "16.4"
  instance_class      = var.instance_class
  db_name             = var.db_name
  username            = var.username
  password            = var.password
  allocated_storage   = var.allocated_storage_gb
  skip_final_snapshot = false

  # SOC2 CC6.6: no public access; traffic only within the VPC.
  publicly_accessible = false

  # SOC2 CC6.7 / C1.1: encryption at rest with KMS (CMEK when a key is supplied).
  storage_encrypted = true
  kms_key_id        = var.kms_key != "" ? var.kms_key : null

  # SOC2 CC6.7: require TLS connections via rds.force_ssl.
  parameter_group_name = aws_db_parameter_group.postgres.name

  # SOC2 A1.1: multi-AZ for high availability / automatic failover.
  multi_az = var.multi_az

  # SOC2 A1.2: automated backups with retention.
  backup_retention_period = var.backup_retention_days
  backup_window           = "03:00-04:00"

  # SOC2 A1.3 / C1.2: protect against accidental deletion.
  deletion_protection = true
}

resource "aws_db_parameter_group" "postgres" {
  family = "postgres16"
  name   = var.instance_identifier
  parameter {
    name         = "rds.force_ssl"
    value        = "1" # SOC2 CC6.7: encrypted connections only
    apply_method = "pending-reboot"
  }
}

output "db_identifier" {
  value = aws_db_instance.postgres.identifier
}

output "db_address" {
  value = aws_db_instance.postgres.address
}
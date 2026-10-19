# rds_postgres

SOC2-compliant RDS PostgreSQL: encrypted at rest with KMS (CC6.7/C1.1), TLS-only
(rds.force_ssl), private VPC (CC6.6), multi-AZ HA (A1.1), automated backups with
retention (A1.2) and deletion protection (A1.3/C1.2).

Requires the `aws` provider and valid AWS credentials. See `variables.tf`.
package analysis

// AWS findings builder helper.
func awsFinding(rType, rName, check, title string, controls []string, sev string, evidence map[string]any, rem Remediation) Finding {
	return Finding{
		ResourceType: rType,
		ResourceName: rName,
		CheckName:    check,
		Title:        title,
		Controls:     controls,
		Severity:     sev,
		EvidenceType: "config",
		Evidence:     evidence,
		Remediation:  rem,
	}
}

// --- S3 ---

func checkAWSBucketPublicAccess(rs *ResourceSet) []Finding {
	var out []Finding
	for _, b := range rs.AWSBuckets {
		if b.PublicBlock {
			continue
		}
		out = append(out, awsFinding("aws_s3_bucket", b.Name, "aws_s3_bucket_public_access",
			"S3 bucket does not block all public access",
			[]string{"CC6.1", "CC6.6"}, "critical",
			map[string]any{"bucket": b.Name},
			s3Remediation(b.Name, "aws_s3_bucket_public_access",
				"Enable the Public Access Block on the bucket (block_public_acls/policy, ignore_public_acls, restrict_public_buckets).")))
	}
	return out
}

func checkAWSBucketPublicPolicy(rs *ResourceSet) []Finding {
	var out []Finding
	for _, b := range rs.AWSBuckets {
		if b.PublicPolicy == "" {
			continue
		}
		out = append(out, awsFinding("aws_s3_bucket_policy", b.Name, "aws_s3_bucket_public_policy",
			"S3 bucket policy is public ("+b.PublicPolicy+")",
			[]string{"CC6.6", "C1.1"}, "critical",
			map[string]any{"bucket": b.Name},
			s3Remediation(b.Name, "aws_s3_bucket_public_policy",
				"Remove the public bucket policy and rely on explicit IAM grants.")))
	}
	return out
}

func checkAWSBucketVersioning(rs *ResourceSet) []Finding {
	var out []Finding
	for _, b := range rs.AWSBuckets {
		if b.Versioning {
			continue
		}
		out = append(out, awsFinding("aws_s3_bucket", b.Name, "aws_s3_bucket_versioning",
			"S3 bucket versioning is disabled",
			[]string{"A1.2"}, "medium",
			map[string]any{"bucket": b.Name},
			s3Remediation(b.Name, "aws_s3_bucket_versioning",
				"Enable versioning for object recoverability.")))
	}
	return out
}

func checkAWSBucketEncryption(rs *ResourceSet) []Finding {
	var out []Finding
	for _, b := range rs.AWSBuckets {
		if b.Encrypted {
			continue
		}
		out = append(out, awsFinding("aws_s3_bucket", b.Name, "aws_s3_bucket_encryption",
			"S3 bucket default encryption is not configured",
			[]string{"CC6.7", "C1.1"}, "low",
			map[string]any{"bucket": b.Name},
			s3Remediation(b.Name, "aws_s3_bucket_encryption",
				"Configure default server-side encryption (SSE-KMS with a CMK preferred).")))
	}
	return out
}

func s3Remediation(rName, check, notes string) Remediation {
	cfg := `resource "aws_s3_bucket" "` + slugFor(rName) + `" {
  bucket = "` + rName + `"
}

resource "aws_s3_bucket_public_access_block" "` + slugFor(rName) + `" {
  bucket = aws_s3_bucket.` + slugFor(rName) + `.id

  block_public_acls       = true   # CC6.1/CC6.6
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "` + slugFor(rName) + `" {
  bucket = aws_s3_bucket.` + slugFor(rName) + `.id
  versioning_configuration { status = "Enabled" }   # A1.2
}

resource "aws_s3_bucket_server_side_encryption_configuration" "` + slugFor(rName) + `" {
  bucket = aws_s3_bucket.` + slugFor(rName) + `.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"    # CC6.7/C1.1
      kms_master_key_id = var.kms_key_id
    }
  }
}

variable "kms_key_id" { default = "alias/soc2-key" }`
	return remediate("aws_s3_bucket", rName, check, cfg, notes)
}

// --- RDS ---

func checkAWSRDSEncryption(rs *ResourceSet) []Finding {
	var out []Finding
	for _, i := range rs.AWSRDS {
		if i.StorageEncrypted {
			continue
		}
		out = append(out, awsFinding("aws_db_instance", i.Identifier, "aws_rds_storage_encrypted",
			"RDS instance storage is not encrypted",
			[]string{"CC6.7", "C1.1"}, "high",
			map[string]any{"identifier": i.Identifier},
			rdsRemediation(i.Identifier, "aws_rds_storage_encrypted",
				"Enable storage_encrypted = true with a KMS key.")))
	}
	return out
}

func checkAWSRDSDeletionProtection(rs *ResourceSet) []Finding {
	var out []Finding
	for _, i := range rs.AWSRDS {
		if i.DeletionProtection {
			continue
		}
		out = append(out, awsFinding("aws_db_instance", i.Identifier, "aws_rds_deletion_protection",
			"RDS instance has no deletion protection",
			[]string{"A1.3", "C1.2"}, "medium",
			map[string]any{"identifier": i.Identifier},
			rdsRemediation(i.Identifier, "aws_rds_deletion_protection",
				"Set deletion_protection = true.")))
	}
	return out
}

func checkAWSRDSMultiAZ(rs *ResourceSet) []Finding {
	var out []Finding
	for _, i := range rs.AWSRDS {
		if i.MultiAZ {
			continue
		}
		out = append(out, awsFinding("aws_db_instance", i.Identifier, "aws_rds_multi_az",
			"RDS instance is not multi-AZ (no automatic failover)",
			[]string{"A1.1", "A1.3"}, "medium",
			map[string]any{"identifier": i.Identifier},
			rdsRemediation(i.Identifier, "aws_rds_multi_az",
				"Set multi_az = true.")))
	}
	return out
}

func checkAWSRDSBackups(rs *ResourceSet) []Finding {
	var out []Finding
	for _, i := range rs.AWSRDS {
		if i.BackupRetention > 0 {
			continue
		}
		out = append(out, awsFinding("aws_db_instance", i.Identifier, "aws_rds_backup_retention",
			"RDS automated backups are disabled",
			[]string{"A1.2"}, "high",
			map[string]any{"identifier": i.Identifier},
			rdsRemediation(i.Identifier, "aws_rds_backup_retention",
				"Enable automated backups (backup_retention_period >= 7 days).")))
	}
	return out
}

func checkAWSRDSPublicAccess(rs *ResourceSet) []Finding {
	var out []Finding
	for _, i := range rs.AWSRDS {
		if !i.PubliclyAccessible {
			continue
		}
		out = append(out, awsFinding("aws_db_instance", i.Identifier, "aws_rds_public_access",
			"RDS instance is publicly accessible",
			[]string{"CC6.6", "A1.2"}, "high",
			map[string]any{"identifier": i.Identifier},
			rdsRemediation(i.Identifier, "aws_rds_public_access",
				"Set publicly_accessible = false; keep the instance in a private subnet.")))
	}
	return out
}

func rdsRemediation(rName, check, notes string) Remediation {
	cfg := `resource "aws_db_instance" "` + slugFor(rName) + `" {
  identifier            = "` + rName + `"
  engine                = "postgres"
  engine_version        = "16.4"
  instance_class        = "db.t3.micro"
  allocated_storage     = 20
  username              = var.db_username
  password              = var.db_password

  storage_encrypted     = true          # CC6.7/C1.1
  kms_key_id            = var.kms_key_id
  storage_type          = "gp3"

  multi_az              = true          # A1.1
  backup_retention_period = 30          # A1.2
  backup_window         = "03:00-04:00"

  deletion_protection   = true          # A1.3/C1.2
  publicly_accessible   = false         # CC6.6

  parameter_group_name = aws_db_parameter_group.` + slugFor(rName) + `.name
}

resource "aws_db_parameter_group" "` + slugFor(rName) + `" {
  family = "postgres16"
  name   = "` + rName + `-soc2"
  parameter {
    name  = "rds.force_ssl"
    value = "1"                         # CC6.7
  }
}

variable "db_username"  {}
variable "db_password"  {}
variable "kms_key_id"   { default = "alias/soc2-key" }`
	return remediate("aws_db_instance", rName, check, cfg, notes)
}

// --- EC2 ---

func checkAWSEC2PublicIP(rs *ResourceSet) []Finding {
	var out []Finding
	for _, i := range rs.AWSEC2 {
		if !i.PublicIP {
			continue
		}
		out = append(out, awsFinding("aws_instance", i.InstanceID, "aws_ec2_public_ip",
			"EC2 instance has a public IP address",
			[]string{"CC6.6"}, "high",
			map[string]any{"instance_id": i.InstanceID, "name": i.Name},
			ec2Remediation(i.InstanceID, "aws_ec2_public_ip",
				"Remove the public IP (EIP / public subnet); use a private subnet + NAT gateway.")))
	}
	return out
}

func ec2Remediation(rName, check, notes string) Remediation {
	cfg := `resource "aws_instance" "` + slugFor(rName) + `" {
  ami           = var.ami
  instance_type = "t3.micro"
  subnet_id     = var.private_subnet_id   # CC6.6: no public IP

  # No associate_public_ip_address -> instance stays private
  vpc_security_group_ids = [aws_security_group.` + slugFor(rName) + `.id]
}

resource "aws_security_group" "` + slugFor(rName) + `" {
  name = "` + rName + `-soc2"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]        # CC6.6: never 0.0.0.0/0
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

variable "ami"              {}
variable "private_subnet_id" {}`
	return remediate("aws_instance", rName, check, cfg, notes)
}

// --- Security groups ---

func checkAWSSecurityGroupBroadIngress(rs *ResourceSet) []Finding {
	var out []Finding
	badPorts := map[int32]bool{22: true, 3389: true, 5432: true, 3306: true, 1433: true, 6379: true, 27017: true}
	for _, sg := range rs.AWSSecurityGroups {
		for _, rule := range sg.Ingress {
			if !rule.Cidr0 {
				continue
			}
			openAll := rule.AllProtocol && rule.FromPort == 0 && rule.ToPort == 0
			sensitive := rule.FromPort != 0 && badPorts[rule.FromPort] && rule.ToPort == rule.FromPort
			if !openAll && !sensitive {
				continue
			}
			sev := "high"
			if openAll {
				sev = "critical"
			}
			out = append(out, awsFinding("aws_security_group", sg.GroupID, "aws_security_group_broad_ingress",
				"Security group allows broad ingress from 0.0.0.0/0 on sensitive port/protocol",
				[]string{"CC6.6"}, sev,
				map[string]any{"group_id": sg.GroupID, "from_port": rule.FromPort},
				sgRemediation(sg.GroupID, "aws_security_group_broad_ingress",
					"Tighten ingress CIDR blocks to specific ranges; never 0.0.0.0/0 on management/DB ports.")))
			break
		}
	}
	return out
}

func sgRemediation(rName, check, notes string) Remediation {
	cfg := `resource "aws_security_group" "` + slugFor(rName) + `" {
  name = "` + slugFor(rName) + `"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]   # CC6.6: only your admin CIDR
  }
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]   # only app subnets
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}`
	return remediate("aws_security_group", rName, check, cfg, notes)
}

// --- KMS ---

func checkAWSKMSRotation(rs *ResourceSet) []Finding {
	var out []Finding
	for _, k := range rs.AWSKMS {
		if k.Manager == "AWS" || k.RotationEnabled {
			continue
		}
		out = append(out, awsFinding("aws_kms_key", k.KeyID, "aws_kms_key_rotation",
			"KMS customer-managed key has automatic rotation disabled",
			[]string{"CC6.1"}, "medium",
			map[string]any{"key_id": k.KeyID},
			kmsRemediationAWS(k.KeyID, "aws_kms_key_rotation",
				"Enable automatic rotation (enable_key_rotation = true).")))
	}
	return out
}

func kmsRemediationAWS(rName, check, notes string) Remediation {
	cfg := `resource "aws_kms_key" "` + slugFor(rName) + `" {
  description         = "` + rName + `"
  enable_key_rotation = true   # CC6.1
}

resource "aws_kms_alias" "` + slugFor(rName) + `" {
  name          = "alias/soc2-key"
  target_key_id = aws_kms_key.` + slugFor(rName) + `.key_id
}`
	return remediate("aws_kms_key", rName, check, cfg, notes)
}

// --- IAM ---

func checkAWSIAMAccessKeys(rs *ResourceSet) []Finding {
	var out []Finding
	for _, u := range rs.AWSIAMUsers {
		if u.AccessKeys == 0 {
			continue
		}
		out = append(out, awsFinding("aws_iam_user", u.UserName, "aws_iam_user_access_keys",
			"IAM user has long-lived access keys",
			[]string{"CC6.2", "CC6.4"}, "medium",
			map[string]any{"user_name": u.UserName, "key_count": u.AccessKeys},
			iamRemediation(u.UserName, "aws_iam_user_access_keys",
				"Rotate and remove long-lived access keys; prefer IAM roles (IRSA/Workload Identity).")))
	}
	return out
}

func iamRemediation(rName, check, notes string) Remediation {
	cfg := `# Delete the access key after rotating to a role/SSO-based identity (CC6.2, CC6.4)
resource "aws_iam_access_key" "rotated" {
  user    = "` + rName + `"
  status  = "Inactive"
}

# Prefer attaching a role to the workload instead:
resource "aws_iam_role" "workload" {
  name = "workload-soc2"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}`
	return remediate("aws_iam_access_key", rName, check, cfg, notes)
}

// --- CloudTrail ---

func checkAWSCloudTrail(rs *ResourceSet) []Finding {
	if len(rs.AWSCloudTrails) == 0 {
		return []Finding{awsFinding("aws_cloudtrail", "aws", "aws_cloudtrail_enabled",
			"No CloudTrail trail is configured",
			[]string{"CC7.2", "CC7.3"}, "high",
			map[string]any{"trail_count": 0},
			cloudTrailRemediation("aws_cloudtrail_enabled",
				"Create a multi-region trail writing to a private S3 bucket with 365-day retention."))}
	}
	var out []Finding
	for _, t := range rs.AWSCloudTrails {
		if !t.MultiRegion || !t.HasBucket {
			out = append(out, awsFinding("aws_cloudtrail", t.Name, "aws_cloudtrail_config",
				"CloudTrail trail is not multi-region or has no log bucket",
				[]string{"CC7.2", "CC7.3"}, "medium",
				map[string]any{"trail": t.Name, "multi_region": t.MultiRegion, "has_bucket": t.HasBucket},
				cloudTrailRemediation("aws_cloudtrail_config",
					"Make the trail multi-region with is_multi_region_trail = true and a log bucket.")))
		}
	}
	return out
}

func cloudTrailRemediation(check, notes string) Remediation {
	cfg := `resource "aws_cloudtrail" "soc2" {
  name                          = "soc2-audit-trail"
  s3_bucket_name                = aws_s3_bucket.audit.id
  is_multi_region_trail         = true    # CC7.2
  enable_log_file_validation    = true
  include_global_service_events = true
  kms_key_id                    = aws_kms_key.audit.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }
}

resource "aws_s3_bucket" "audit" {
  bucket = "soc2-audit-logs"
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "audit" {
  bucket = aws_s3_bucket.audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_kms_key" "audit" {
  enable_key_rotation = true
}

variable "log_bucket" { default = "soc2-audit-logs" }`
	return remediate("aws_cloudtrail", "soc2-audit-trail", check, cfg, notes)
}

// awsChecks lists all AWS check funcs, invoked by Evaluate when AWS data present.
func awsChecks() []func(*ResourceSet) []Finding {
	return []func(*ResourceSet) []Finding{
		checkAWSBucketPublicAccess,
		checkAWSBucketPublicPolicy,
		checkAWSBucketVersioning,
		checkAWSBucketEncryption,
		checkAWSRDSEncryption,
		checkAWSRDSDeletionProtection,
		checkAWSRDSMultiAZ,
		checkAWSRDSBackups,
		checkAWSRDSPublicAccess,
		checkAWSEC2PublicIP,
		checkAWSSecurityGroupBroadIngress,
		checkAWSKMSRotation,
		checkAWSIAMAccessKeys,
		checkAWSCloudTrail,
	}
}

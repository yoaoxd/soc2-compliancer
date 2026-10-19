terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "account_id" {
  type        = string
  description = "AWS account ID (12 digits) that SOC2 Compliancer will analyze (read-only)."
}

# Read-only IAM policies required by the SOC2 Compliancer analyzer.
resource "aws_iam_policy" "soc2_analyzer" {
  name        = "soc2-compliance-analyzer"
  description = "Read-only policy for SOC2 Compliancer analysis."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "s3:GetBucketPublicAccessBlock", Resource = "*" },
      { Effect = "Allow", Action = "s3:GetBucketPolicyStatus", Resource = "*" },
      { Effect = "Allow", Action = "s3:ListAllMyBuckets", Resource = "*" },
      { Effect = "Allow", Action = ["rds:DescribeDBInstances", "rds:ListTagsForResource"], Resource = "*" },
      { Effect = "Allow", Action = ["ec2:DescribeInstances", "ec2:DescribeSecurityGroups", "ec2:DescribeSubnets", "ec2:DescribeFlowLogs", "ec2:DescribeVpcs"], Resource = "*" },
      { Effect = "Allow", Action = ["kms:ListKeys", "kms:DescribeKey", "kms:GetKeyRotationStatus", "kms:GetKeyPolicy", "kms:ListResourceTags"], Resource = "*" },
      { Effect = "Allow", Action = ["iam:ListUsers", "iam:ListAccessKeys", "iam:GenerateCredentialReport"], Resource = "*" },
      { Effect = "Allow", Action = ["cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus", "cloudtrail:ListTrails"], Resource = "*" },
    ]
  })
}

# Same benefit via the managed ReadOnlyAccess policy as a baseline, plus the
# granular policy above so it works even in restricted environments.
resource "aws_iam_role" "soc2_analyzer" {
  name        = "soc2-compliance-analyzer"
  description = "Read-only role assumed by SOC2 Compliancer."
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "readonly" {
  role       = aws_iam_role.soc2_analyzer.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "soc2" {
  role       = aws_iam_role.soc2_analyzer.name
  policy_arn = aws_iam_policy.soc2_analyzer.arn
}

output "analyzer_role_arn" {
  description = "ARN of the read-only analyzer role. Create temporary credentials with: aws sts assume-role --role-arn=<arn> --role-session-name=soc2-scan"
  value       = aws_iam_role.soc2_analyzer.arn
}
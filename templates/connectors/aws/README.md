# SOC2 Compliancer — AWS analyzer role

1. Set your AWS account id: `variable account_id` (12 digits).
2. Run: `terraform init && terraform apply`.
3. The output `analyzer_role_arn` is a read-only role you can assume.

Create temporary credentials for the analyzer:

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::<ACCOUNT_ID>:role/soc2-compliance-analyzer \
  --role-session-name soc2-scan \
  --region us-east-1
```

Copy `AccessKeyId`, `SecretAccessKey`, and `SessionToken` into the SOC2
Compliancer "AWS" connection form (region: where your resources live).

The role grants `ReadOnlyAccess` plus a focused policy for the services the
analyzer inspects (S3, RDS, EC2/security groups, KMS, IAM, CloudTrail). It can
only read — it never mutates anything.
# s3_bucket

SOC2-compliant S3 bucket: all public access blocked (CC6.1/CC6.6), server-side
encryption SSE-KMS when a key is supplied (CC6.7/C1.1), versioning (A1.2) and
compliance object lock retention (A1.2/C1.2).

Requires the `aws` provider and valid AWS credentials. See `variables.tf`.
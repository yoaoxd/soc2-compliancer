# GCP — `kms_key`

Customer-managed encryption key (CMEK) with automatic rotation.

## Controls covered
- **CC6.1** — automatic rotation (90 days), least-privilege IAM grantor.
- **C1.1** — provides CMEK material for protecting confidential data.

## Usage
```hcl
module "soc2_kms" {
  source        = "./modules/gcp/kms_key"
  project_id    = "my-project"
  rotation_seconds = 7776000
}

module "soc2_storage" {
  source      = "./modules/gcp/storage_bucket"
  project_id  = "my-project"
  bucket_name = "soc2-data"
  kms_key     = module.soc2_kms.key_id
}
```

## Guardrails (see `metadata.yaml`)
- Rotation configured (never static keys).
- No public IAM; grantor empty by default.
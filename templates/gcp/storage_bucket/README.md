# GCP — `storage_bucket`

SOC2-compliant Cloud Storage (GCS) bucket.

## Controls covered
- **CC6.1 / CC6.6** — IAM-only access via uniform bucket-level access; no public bindings.
- **CC6.7 / C1.1** — encryption at rest (CMEK when `kms_key` is set, else service-side encryption).
- **A1.2** — versioning and retention for recoverability.
- **C1.2** — retention lifecycle enables policy-based disposal.

## Usage
```hcl
module "soc2_storage" {
  source      = "./modules/gcp/storage_bucket"
  project_id  = "my-project"
  bucket_name = "soc2-data"
  kms_key     = "projects/my-project/locations/us-central1/keyRings/soc2/cryptoKeys/soc2"
}
```

## Inputs
| Name | Type | Default | Description |
|---|---|---|---|
| `project_id` | string | – | Project to create the bucket in |
| `bucket_name` | string | – | Globally unique bucket name |
| `location` | string | `"US"` | GCS location |
| `kms_key` | string | `""` | CMEK key self-link; empty = SSE |
| `retention_days` | number | `365` | Object retention in days |

## Requirements / guardrails enforced (see `metadata.yaml`)
- `uniform_bucket_level_access = true`
- No `allUsers`/`allAuthenticatedUsers` IAM bindings (add none)
- Encryption configured (CMEK preferred)
- Versioning enabled with retention

## Tests
Running `checkov` and `tfsec` on this module must pass (see CI).
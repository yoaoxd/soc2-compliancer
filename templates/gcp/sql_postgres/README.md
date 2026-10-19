# GCP — `sql_postgres`

SOC2-compliant Cloud SQL for PostgreSQL instance.

## Controls covered
- **CC6.7** — `ENCRYPTED_ONLY` SSL mode; optional CMEK disk encryption.
- **CC6.6** — private networking preferred; no implicit public exposure.
- **A1.1** — regional high availability.
- **A1.2** — automated backups + PITR with transaction log retention.

## Guardrails (see `metadata.yaml`)
- `require_ssl = true`, `ssl_mode = ENCRYPTED_ONLY`
- `availability_type = REGIONAL`
- Backups enabled with PITR
- `deletion_protection = true`
- No `0.0.0.0/0` authorized network (caller must own the allowlist)
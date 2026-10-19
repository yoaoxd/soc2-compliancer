# Project — SOC2 Compliancer

A multi-cloud compliance platform that makes cloud infrastructure **SOC2-ready**:

1. **Bundle generator** — select SOC2-relevant cloud components and get a self-contained
   Terraform bundle (dependencies auto-included, CMEK wired, module sources vendored)
   that provisions compliant infrastructure.
2. **Read-only analyzer** — connect a GCP project with a service-account key and get a
   scan of what it's *missing* against SOC2 controls, plus per-finding
   `terraform import` + compliant `.tf` to close each gap.

Docs in this repo are original work — control summaries are authored by us, not verbatim
AICPA Trust Services Criteria text (AICPA material is copyrighted).

---

## Goals

| # | Goal | Status |
|---|------|--------|
| 1 | Versioned SOC2 control registry (editions, categories, codes) with original summaries | ✅ `soc2_2017` seeded (27 controls); `soc2_2025` pending verification |
| 2 | Map cloud resource guardrails → SOC2 controls (evidence type: config/policy/log) | ✅ GCP mappings seeded |
| 3 | Multi-tenant auth with orgs + RBAC (admin/editor/viewer) | ✅ |
| 4 | Terraform component catalog driven by module metadata (`templates/`) | ✅ GCP: `storage_bucket`, `kms_key`, `sql_postgres` |
| 5 | Bundle generator (topological deps, CMEK, vendored modules, ZIP download) | ✅ |
| 6 | Generation history per org | ✅ |
| 7 | GCP read-only analysis: collect resources with a SA key | ✅ 8 collectors |
| 8 | Rule engine: evaluate resources against SOC2 guardrails | ✅ 35 checks |
| 9 | Per-finding remediation (`terraform import` + compliant HCL + notes) | ✅ |
| 10 | Persist connections, scans, and findings per org (credentials encrypted at rest) | ✅ AES-256-GCM |
| 11 | Findings UI (browse scans, filter by severity, copy remediation `.tf`) | ✅ |
| 12 | Scheduled re-scans (Type 2 operational evidence), scan interval per connection | ✅ scheduler + `PATCH` interval |
| 13 | Evidence matrix: SOC2 controls × guardrails × current finding coverage | ✅ `/orgs/{id}/evidence/matrix` + UI |
| 14 | CI hook reporting bundle policy results | ✅ `/orgs/{id}/ci-runs` |
| 15 | Cloud Asset Inventory depth (asset search + public IAM) + ~30 checks | ✅ 35 checks |
| 16 | AWS / Azure module libraries + rule engine parity | ✅ aws/azure modules + collectors + checks |
| 17 | SaaS hardening: KMS-envelope encryption, quotas, audit trail, Google SSO | ✅ |

---

## Architecture

```
api/                  Go backend — the one real API (chi + Postgres, migrations embedded)
webapp/               React 18 + Vite dashboard (proxy /api -> :8080)
templates/            Versioned Terraform module library per provider (metadata.yaml)
scripts/              Repo scripts (validate-templates.sh)
docker-compose.yml    Local Postgres only (production does not use it)
```

### Backend packages (`api/internal/`)

| Package | Responsibility |
|---|---|
| `server/` | Router assembly + wiring (health, mounts) |
| `auth/` | Register/login, JWT sessions, orgs, RBAC middleware |
| `registry/` | SOC2 control catalog + control↔resource mappings (seeded) |
| `catalog/` | Provider/component catalog from `templates/**/metadata.yaml` |
| `generation/` | Terraform bundle generator + per-org history |
| `analysis/` | **Read-only multi-cloud analysis**: collect → evaluate → remediate (GCP/AWS/Azure) |
| `analyze/` | Stateless `/analyze` HTTP route (credentials JSON in → findings out) |
| `connections/` | Org-scoped connections, scans, findings persistence, quotas |
| `evidence/` | Evidence matrix: control coverage across the org's scans |
| `cirun/` | CI hook: report/list bundle policy results |
| `encrypt/` | Envelope encryption (AES-256-GCM DEK wrapped by local or AWS-KMS KEK) |
| `audit/` | Audit trail: `audit_logs` persistence + list API |
| `db/` | Connection pool + embedded SQL migrations |
| `config/` | Env-driven configuration |
| `web/` | JSON helpers |

### The analysis pipeline (`internal/analysis/`)

```
SA key (JWT, read-only scopes)
   │  Collect(ctx, sa)                    collect.go / inventory.go / cai.go
   ├── Cloud Storage buckets + IAM policies
   ├── Cloud SQL instances
   ├── Compute instances / firewalls / subnets / instance templates
   ├── Project IAM (primitive roles, public bindings)
   ├── Service accounts + user-managed keys
   ├── Logging sinks
   ├── Cloud KMS keys
   ├── Secret Manager secrets + IAM
   └── Cloud Asset Inventory depth (SearchAllResources + SearchAllIamPolicies)
        └── BigQuery datasets, Cloud Run services, Pub/Sub topics + public IAM
   │
   │  Evaluate(rs)                        checks.go / checks2.go / checks3.go
   └── 35 SOC2-mapped findings, each with:
         severity, evidence, controls, Remediation{import_command, .tf snippet, notes}
```

Failures per service degrade to `Warnings` instead of aborting the scan, so a missing
API permission never hides the rest of the project's results.

### Schema (migrations `api/internal/db/migrations/`)

- `0001` — orgs, users, memberships (RBAC), controls, mappings
- `0002` — `created_at` on controls/mappings
- `0003` — generations
- `0004` — connections (encrypted creds), scans, findings
- `0005` — findings `title`
- `0006` — connections `scan_interval_hours` (scheduled re-scans)
- `0007` — CI runs (`ci_runs` bundle policy results)
- `0008` — audit trail (`audit_logs`)
- `0009` — SSO (`users.password` nullable, `sso_provider`, `oauth_states` CSRF)

Schema changes go through the embedded migration runner (`db.RunMigrations`) — there is no
`create_all()`. New migration → add `000N_*.sql` and the runner picks it up automatically.

---

## Install & run locally

Prerequisites: **Go 1.26+**, **Node 20+**, **Docker** (Postgres only).

```bash
# 1. Postgres (port 5433 deliberately, to avoid clashing with a local :5432)
docker compose up -d postgres

# 2. Backend on :8080 (migrations + control registry seed run automatically at boot)
cd api && go mod download && go run ./cmd/api

# 3. Dashboard on :5173 (Vite proxies /api -> :8080)
cd webapp && npm install && npm run dev
```

Health: `GET /api/v1/health`.

### Environment variables (`api/internal/config/config.go`)

| Var | Default | Purpose |
|---|---|---|
| `HTTP_ADDR` | `:8080` | API bind address |
| `DATABASE_URL` | `postgres://soc2:soc2@localhost:5433/soc2?sslmode=disable` | Postgres DSN |
| `JWT_SECRET` | dev value | HMAC secret for session JWTs (set a strong one) |
| `JWT_TTL_HOURS` | `24` | Session lifetime |
| `ENCRYPTION_KEY` | dev fallback | Master key for AES-256-GCM credential encryption |
| `ENCRYPTION_KEK_ID` | empty | AWS KMS key ID/alias → envelope encryption via KMS (overrides local key) |
| `MAX_CONNECTIONS_PER_ORG` | `10` | Per-org connection quota (429 when exceeded) |
| `MAX_SCANS_PER_ORG_PER_DAY` | `100` | Per-org daily scan quota (429 when exceeded) |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | empty | Google OAuth sign-in |
| `OAUTH_REDIRECT_URL` | `http://localhost:8080/api/v1/auth/google/callback` | Google callback target |
| `WEBAPP_URL` | `http://localhost:5173` | Redirect target after OAuth (token/error query param) |
| `OAUTH_ALLOWED_DOMAINS` | `gmail.com` | Allowed email domains for SSO (comma-separated) |
| `TEMPLATES_DIR` | `../templates` | Terraform module library root |
| `LOG_LEVEL` | `info` | Logging level |

---

## Using the analyzer

### 1. Create a GCP service-account key

In GCP console: create a service account with **read-only** access, e.g. role
`roles/viewer` (or scoped roles for storage/sql/compute/logging/kms/secretmanager),
then download the JSON key. The API reads it with read-only OAuth scopes — it can only
read, never mutate.

### 2. Stateless one-off scan

```bash
curl -s -X POST http://localhost:8080/api/v1/analyze \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"service_account_json\": \"$(cat key.json)\"}"
```

Returns `{ project_id, warnings, counts, findings[] }` where each finding carries
severity, evidence, control codes, and a `remediation` with `terraform import` command
+ compliant `.tf`.

### 3. Persistent org-scoped flow (stores history)

```bash
# register/login → token + org id (see /api/v1/auth endpoints)

# create connection (SA JSON encrypted at rest)
POST /api/v1/orgs/{orgID}/connections
{ "provider": "gcp", "name": "prod", "service_account_json": "..." }

# run a scan
POST /api/v1/orgs/{orgID}/connections/{connectionID}/scan

# read results
GET /api/v1/orgs/{orgID}/connections/{connectionID}/scans
GET /api/v1/orgs/{orgID}/connections/{connectionID}/scans/{scanID}/findings?severity=critical
```

---

## SOC2 tests / checks

### Control catalog (seeded, edition `soc2_2017`)

- **Security (CC):** CC6.1–CC6.7, CC7.1–CC7.5, CC8.1, CC9.1, CC9.2
- **Availability (A):** A1.1–A1.3
- **Confidentiality (C):** C1.1–C1.2
- **Integrity (PI):** PI1.1–PI1.4
- **Privacy (P):** P1.1, P1.2, P6.1

### Guardrail checks implemented in the analyzer (35)

| Check | Resource | Severity | Controls | Fix |
|---|---|---|---|---|
| `storage_bucket_uniform_access` | GCS bucket | high | CC6.1, CC6.6 | IAM-only access |
| `storage_bucket_public_binding` | GCS bucket | critical | CC6.6 | drop allUsers/allAuthenticatedUsers |
| `storage_bucket_versioning` | GCS bucket | medium | A1.2 | enable versioning |
| `storage_bucket_cmek` | GCS bucket | low | CC6.7, C1.1 | customer-managed key |
| `sql_ssl_encrypted_only` | Cloud SQL | high | CC6.7 | enforce TLS-only |
| `sql_public_exposure` | Cloud SQL | high | CC6.6, A1.2 | private IP only |
| `sql_high_availability` | Cloud SQL | medium | A1.1, A1.3 | regional HA |
| `sql_backups_enabled` | Cloud SQL | high | A1.2 | automated backups + PITR |
| `sql_deletion_protection` | Cloud SQL | medium | A1.3, C1.2 | deletion protection |
| `sql_disk_cmek` | Cloud SQL | low | CC6.7, C1.1 | disk CMEK |
| `compute_shielded_vm` | Compute | high | CC6.1 | Shielded VM secure boot |
| `compute_public_ip` | Compute | high | CC6.6 | remove external IPs |
| `compute_serial_port` | Compute | medium | CC6.1 | disable serial port |
| `firewall_http_ingress_broad` | VPC firewall | critical/high | CC6.6 | tighten 0.0.0.0/0 |
| `firewall_logging` | VPC firewall | low | CC7.2 | log allow rules |
| `subnet_flow_logs` | Subnet | medium | CC7.2 | VPC flow logs |
| `project_primitive_roles` | Project IAM | high/med/low | CC6.2 | least-privilege roles |
| `project_public_bindings` | Project IAM | critical | CC6.6 | remove public principals |
| `sa_user_managed_keys` | SA keys | medium | CC6.2, CC6.4 | rotate / Workload Identity |
| `logging_audit_sink` | Logging | high | CC7.2, CC7.3 | export audit logs |
| `kms_key_rotation` | Cloud KMS | medium | CC6.1 | rotation period |
| `secret_public_binding` | Secret Manager | critical | CC6.6, C1.1 | restrict secret IAM |

**Cloud Asset Inventory depth (CAI `SearchAllResources` + `SearchAllIamPolicies`):**

| Check | Resource | Severity | Controls | Fix |
|---|---|---|---|---|
| `bigquery_dataset_public_binding` | BigQuery dataset | critical | CC6.6, C1.1 | remove allUsers/allAuthenticatedUsers |
| `bigquery_dataset_cmek` | BigQuery dataset | low | CC6.7, C1.1 | dataset-level default CMEK |
| `cloud_run_public_invoker` | Cloud Run service | critical | CC6.6 | restrict invoker IAM |
| `cloud_run_cmek` | Cloud Run service | low | CC6.7, C1.1 | CMEK via run.googleapis.com encryption key |
| `pubsub_topic_cmek` | Pub/Sub topic | low | CC6.7, C1.1 | CMEK via kms_key_name |
| `instance_template_shielded` | Instance template | high | CC6.1 | shielded VM in template |

Every finding's `remediation` field includes:
- **import command** — e.g. `terraform import google_storage_bucket.my_bucket my-bucket`
- **compliant `.tf` snippet** — drop-in config with the guardrail fixed (and control codes
  as inline comments)
- **notes** — why the control applies

Severity ordering: `critical` → `high` → `medium` → `low`.

---

## Tests

```bash
docker compose up -d postgres

cd api && go test ./...          # DB-backed tests skip if Postgres is unreachable
cd webapp && npm run build
bash scripts/validate-templates.sh   # terraform fmt/validate on the module library (CI uses official binary)
```

Coverage today:
- **Unit:** analysis checks + remediation/HCL generation + severity ordering
  (`api/internal/analysis/checks_test.go`, `cai_test.go`)
- **Integration:** auth flow, control registry, bundle generation, connection lifecycle
  (create/list/scan/delete, 404s), findings persistence + severity filter + title round-trip
  — `api/tests/`
- **Webapp build:** `tsc -b && vite build` type-checks the React app incl. the Compliance page

CI: Go build/vet/test (with Postgres service), webapp build, Terraform fmt/validate.

---

## Roadmap / what's missing

- **Phase 3 (done)**
  - Findings **UI** is implemented (Compliance page: connect GCP, run scans, filter by
    severity, copy the remediation `.tf`)
  - Scheduled re-scans (Type 2 operational evidence) — per-connection interval,
    background scheduler, evidence matrix of control coverage, and the CI hook for
    reporting bundle policy results
  - Cloud Asset Inventory depth: 6 new checks across BigQuery, Cloud Run, Pub/Sub, and
    instance templates (35 total), plus CAI-powered public-IAM detection
- **Phase 3/4 next**
  - Pin `soc2_2025` control codes/definitions in a compliance-content spike
- **Phase 4 (done)**
  - AWS / Azure module libraries (`templates/aws`, `templates/azure`) with provider
    parity in the bundle generator
  - AWS / Azure analysis parity: collectors + checks, provider dispatch in `/analyze`
    and persistent connections, multi-cloud UI in the Compliance page
- **Phase 5 (done)**
  - Envelope credential encryption (DEK wrapped by local or AWS-KMS KEK); legacy
    ciphertext still decrypts after upgrade
  - Per-org quotas: max connections and max scans/day (`429`), config-driven
  - Audit trail: `audit_logs` written on connection create/scan/delete, readable via
    `GET /orgs/{id}/audit`
  - Google OAuth sign-in (`/auth/google/start` → callback → webapp redirect) with
    CSRF state, verified-email linking, and SSO-only accounts
- **Phase 6 / backlog**
  - Per-org plan tiers instead of global quotas, quota UI
  - GCP KMS / HashiCorp Vault as additional KEKs
  - Audit trail admin/export views, retention policy
  - GitHub/Azure AD SSO providers

---

## Contributing notes

- New backend route → add file in `api/routes/` style package, mount in
  `internal/server/server.go` (**easy to forget**).
- New model/schema → add `000N_*.sql` migration; the embedded runner applies it at boot.
- New check → implement in `internal/analysis/`, wire into `Evaluate()`, add a unit test,
  and document it in the SOC2 checks table above.
- Business logic lives in `internal/*/service.go`; HTTP handlers stay thin.
- Never commit real credentials; dev secrets in `config` are placeholders.

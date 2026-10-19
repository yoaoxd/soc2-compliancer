# SOC2 Compliancer

Multi-cloud infrastructure control analysis and Terraform bundle generation for AWS, Azure, and Google Cloud.

SOC2 Compliancer connects cloud configuration findings with control mappings and reviewable Terraform proposals. It combines a Go API, a React dashboard, a versioned control catalog, and reusable Terraform modules.

## What is in the repository

- **Terraform catalog:** nine modules covering storage, encryption keys, and PostgreSQL services across AWS, Azure, and GCP, plus connector templates.
- **Bundle generation:** component selection, dependency resolution, key wiring, vendored modules, and downloadable ZIP bundles.
- **Infrastructure analysis:** provider collectors, rule evaluation, findings with supporting observations, and remediation proposals.
- **Organization workflows:** authentication, roles, connection management, scan history, scheduled scans, audit records, and CI-result reporting.
- **Control coverage:** a registry of control summaries and a matrix connecting findings to infrastructure guardrails.
- **Credential handling:** envelope encryption with local or AWS KMS key wrapping.

## Explore the design

See [architecture and decisions](PROJECT.md#architecture), [cloud coverage](PROJECT.md#cloud-coverage), and a [worked bucket-access example](PROJECT.md#example-review-a-bucket-access-finding).

## Repository layout

| Path | Purpose |
| --- | --- |
| `api/` | Go backend, provider collectors, rule engine, migrations, and tests |
| `webapp/` | React and TypeScript dashboard |
| `templates/` | Terraform modules, connector templates, and control metadata |
| `scripts/` | Template validation tooling |
| `PROJECT.md` | Architecture, coverage, worked example, and limitations |

## Local development

Requires Go 1.26+, Node.js 20+, and Docker for PostgreSQL. Use an isolated development environment with disposable resources.

Start the database from the repository root:

```bash
docker compose up -d postgres
```

Generate two different random secrets, save them securely, and export them in the API terminal. The following commands are an example for a fresh local setup; retain the encryption key for subsequent starts:

```bash
export JWT_SECRET="$(openssl rand -hex 32)"
export ENCRYPTION_KEY="$(openssl rand -hex 32)"
cd api
go mod download
go run ./cmd/api
```

In another terminal, starting from the repository root:

```bash
cd webapp
npm install
npm run dev
```

The API listens on port 8080; the dashboard uses port 5173 and proxies `/api` to the backend. PostgreSQL uses local port 5433. Configuration examples are in `.env.example`; set environment variables in the processes that run the application.

Use the dashboard to register, select a provider, inspect the module catalog, and generate a bundle. Review its variables and generated files before any Terraform operation. A cloud connection requires separately provisioned credentials with the permissions documented in `templates/connectors/`.

## Design decisions

- **Metadata-driven modules:** each module declares its variables, control mappings, and dependencies. The generator composes those declarations rather than maintaining a separate hard-coded catalog.
- **Collection and remediation are separate:** configuration observations produce findings; generated changes remain reviewable by an operator.
- **Organization-scoped records:** connections, scans, and findings carry organizational context for multi-tenant workflows.
- **Control mappings are explicit:** the project exposes which guardrails relate to which controls, allowing reviewers to challenge coverage rather than treating a scan result as a compliance certificate.

## Status and known limitations

This is a development implementation published for review. No tests, cloud scans, or deployment validation were run as part of this publication. Test sources and validation scripts are included; their presence is not a claim that they pass.

- The API requires explicit signing and encryption secrets at startup. `.env.example` is a reference; the API does not load it automatically. AWS KMS wrapping is available through `ENCRYPTION_KEK_ID`.
- IAM-binding removal and service-account/access-key retirement provide manual guidance, without generating grants or new keys as a removal operation.
- Other remediation snippets remain illustrative drafts, with placeholders and settings that require resource-specific and provider-schema review. Review the full plan before any apply.
- A completed scan or absence of findings does not prove full coverage. Missing permissions, unavailable APIs and unsupported resources can limit observations.
- The evidence matrix and project-authored control mappings support technical review; they do not certify compliance or establish effectiveness over an audit period.

See [detailed limitations](PROJECT.md#limits-that-matter), including the migration implications of changing an existing encryption key.
SOC 2 readiness depends on organizational processes, people, scope, and evidence as well as infrastructure configuration. This project supports selected technical controls; it does not certify compliance.

## Validation tooling

The repository includes Go tests, frontend build configuration, and `scripts/validate-templates.sh`. The GitHub Actions workflow is manual-only in this publication so uploading the project does not launch tests automatically.

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

## Architecture

```text
React dashboard
       |
       v
Go HTTP API ---- PostgreSQL
       |
       +---- Terraform catalog ---> bundle generator ---> reviewed Terraform
       |
       +---- cloud collectors ---> rules ---> findings + remediation proposals
                                         |
                                         +---- control coverage and scan history
```

The collection workflow reads cloud configuration. Applying generated Terraform is a separate operator action. Cloud permissions must be scoped separately for each connector.

## Repository layout

| Path | Purpose |
| --- | --- |
| `api/` | Go backend, provider collectors, rule engine, migrations, and tests |
| `webapp/` | React and TypeScript dashboard |
| `templates/` | Terraform modules, connector templates, and control metadata |
| `scripts/` | Template validation tooling |
| `PROJECT.md` | Detailed implementation notes and development history |

## Local development

Requires Go 1.26+, Node.js 20+, and Docker for PostgreSQL. Use an isolated development environment with disposable resources.

Start the database from the repository root:

```bash
docker compose up -d postgres
```

In one terminal:

```bash
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

- Some remediation snippets need correction. In particular, an IAM-removal proposal currently declares the same binding as a Terraform resource. Treat every remediation as a draft; do not apply it without reviewing the full plan and existing resource configuration.
- Development defaults exist for session signing and local encryption. Production use requires explicit secret configuration and further security review.
- A completed scan or absence of findings does not prove full coverage. Missing permissions, unavailable APIs, and unsupported resources can limit observations.
- The evidence matrix summarizes technical observations. It does not establish operating effectiveness over an audit period or replace an independent SOC 2 examination.
- Control mappings are project-authored interpretations. The `soc2_2025` label mentioned in older planning notes is unverified and is not a supported edition claim.
- `PROJECT.md` contains historical completion and validation statements; they are not fresh verification results. This section describes the publication status.

SOC 2 readiness depends on organizational processes, people, scope, and evidence as well as infrastructure configuration. This project supports selected technical controls; it does not certify compliance.

## Validation tooling

The repository includes Go tests, frontend build configuration, and `scripts/validate-templates.sh`. The GitHub Actions workflow is manual-only in this publication so uploading the project does not launch tests automatically.

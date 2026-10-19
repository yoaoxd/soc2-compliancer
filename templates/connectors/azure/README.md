# SOC2 Compliancer — Azure analyzer service principal

1. Set your subscription id (the subscriber of this Terraform run).
2. Run: `terraform init && terraform apply`.
3. The outputs (`application_id`, `tenant_id`, `subscription_id`) identify a
   read-only service principal on the current subscription.

Create a client secret for the analyzer service principal:

```bash
az ad app credential reset --id <APPLICATION_ID> --append
```

Copy the `client_id` (= application_id), `client_secret`, `tenant_id`, and
`subscription_id` into the SOC2 Compliancer "Azure" connection form.

The service principal is assigned `Reader` at subscription scope plus `Key Vault
Reader`, so it can only read — never mutate.
# NHIID Terraform (AWS / EKS)

Provisions the production substrate for IdentityAttackGraph:

- **VPC** — 3 AZs, public + private subnets, NAT, EKS discovery tags.
- **EKS** — managed cluster + node group, OIDC provider (IRSA), core addons + EBS CSI.
- **RDS Postgres 16** — encrypted, private, SG-restricted to EKS nodes; DSN stored in Secrets Manager.
- **ElastiCache Redis** — single node for the rate limiter (optional).
- **IRSA** — a hub role bound to the NHIID ServiceAccount that can `sts:AssumeRole` into
  read-only collector roles in member accounts and read the DB secret. **No static cloud creds.**
- **`modules/collector-member-role`** — reusable, least-privilege read-only role to deploy in
  *each* AWS account NHIID inventories, with an ExternalId-guarded trust to the hub role.

These map to Roadmap **Phase 5** (`helm install` on EKS; collectors use IRSA + assume-role).

## Layout

```
deploy/terraform/
  versions.tf  variables.tf  main.tf
  vpc.tf  eks.tf  rds.tf  elasticache.tf  irsa.tf  outputs.tf
  terraform.tfvars.example
  modules/collector-member-role/   # apply per member account
```

## Usage

```bash
cd deploy/terraform
cp terraform.tfvars.example terraform.tfvars   # edit region, sizes, member accounts
terraform init
terraform apply
```

Then point kubectl and install the chart:

```bash
$(terraform output -raw configure_kubectl)
helm upgrade --install nhiid ../helm/nhiid -n nhiid --create-namespace \
  -f ../helm/values-prod.example.yaml \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=$(terraform output -raw irsa_role_arn)
```

### Wiring the database secret

`terraform output db_dsn_secret_arn` is a Secrets Manager secret with a `database-dsn` key.
Sync it into the cluster as the Secret named `nhiid-secret` (matching `secrets.existingSecret`)
using the [External Secrets Operator](https://external-secrets.io/) or the AWS Secrets &
Configuration Provider (CSI). The chart consumes the `database-dsn` key directly.

### Member-account collector roles (cross-account discovery)

In each account you want to inventory, apply the module with the hub role ARN + a shared ExternalId:

```hcl
module "nhiid_collector" {
  source           = "github.com/utpalbalse/IdentityAttackGraph//deploy/terraform/modules/collector-member-role"
  trusted_role_arn = "arn:aws:iam::<central-acct>:role/nhiid-collector-irsa" # irsa_role_arn output
  external_id      = "<shared-secret-external-id>"
}
```

Then trigger collection against that account:

```bash
collector --provider aws \
  --role-arn $(terraform output -raw role_arn) \
  --external-id "<shared-secret-external-id>"
```

The role grants only IAM `Get*/List*`, `cloudtrail:LookupEvents`, and `sts:GetCallerIdentity` —
enough to discover identities, keys, trust, and last-used, and nothing that exposes secret values.

## Production hardening checklist

- Configure the S3 remote backend in `versions.tf`.
- Set `db_multi_az = true`, `db_deletion_protection = true`, and restrict
  `cluster_public_access_cidrs` (or set `cluster_public_access = false`).
- Scope `collector_member_account_ids` to explicit accounts (drops the `:role/*` wildcard).
- Enable `transit_encryption_enabled` on Redis and switch the app to `rediss://`.

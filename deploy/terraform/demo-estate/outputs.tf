# Everything you need to point the collector at the estate and to stage the
# "leaked key" story. The access-key secret is sensitive; read it explicitly with
# `terraform output -raw leaked_access_key_secret` when you want to plant it.

output "account_id" {
  description = "Account the estate was created in (from sts:GetCallerIdentity)."
  value       = local.account_id
}

output "region" {
  value = var.region
}

output "collector_role_arn" {
  description = "Read-only role for cross-account collection. Pass to `collector --provider aws --role-arn <this> --external-id <collector_external_id>`. Null if create_collector_role=false."
  value       = var.create_collector_role ? module.collector_role[0].role_arn : null
}

output "collector_external_id" {
  description = "ExternalId to pass to the collector via --external-id."
  value       = var.collector_external_id
}

output "crown_jewel_bucket" {
  description = "The crown-jewel S3 bucket (tagged). This is the asset at the end of the attack path."
  value       = aws_s3_bucket.prod_billing.bucket
}

output "dev_scratch_bucket" {
  description = "The untagged contrast bucket."
  value       = aws_s3_bucket.dev_scratch.bucket
}

output "billing_admin_role_arn" {
  description = "The weakly-guarded role the leaked key can assume."
  value       = aws_iam_role.billing_admin.arn
}

output "svc_billing_export_user" {
  description = "The foothold IAM user whose key is 'leaked'."
  value       = aws_iam_user.svc_billing_export.name
}

output "leaked_access_key_id" {
  description = "Access key id for the foothold user. Commit this together with the secret to a THROWAWAY repo to trigger the repo collector's secret_exposed_in_repo finding."
  value       = aws_iam_access_key.svc_billing_export.id
}

output "leaked_access_key_secret" {
  description = "Secret for the foothold user's access key. Sensitive: read with `terraform output -raw leaked_access_key_secret`. This key grants only sts:AssumeRole on the demo role — it is safe to plant in a throwaway repo, and `terraform destroy` revokes it."
  value       = aws_iam_access_key.svc_billing_export.secret
  sensitive   = true
}

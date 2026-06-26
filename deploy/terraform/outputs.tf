output "region" {
  value = var.region
}

output "cluster_name" {
  value = module.eks.cluster_name
}

output "cluster_endpoint" {
  value = module.eks.cluster_endpoint
}

output "configure_kubectl" {
  description = "Run this to point kubectl at the new cluster."
  value       = "aws eks update-kubeconfig --region ${var.region} --name ${module.eks.cluster_name}"
}

output "irsa_role_arn" {
  description = "Set as serviceAccount.annotations.\"eks.amazonaws.com/role-arn\" in the Helm values."
  value       = module.irsa_role.iam_role_arn
}

output "db_endpoint" {
  description = "RDS Postgres endpoint (host)."
  value       = module.rds.db_instance_address
}

output "db_dsn_secret_arn" {
  description = "Secrets Manager ARN holding the database-dsn key. Wire into the Helm release (External Secrets / CSI) as secrets.existingSecret."
  value       = aws_secretsmanager_secret.db_dsn.arn
}

output "redis_endpoint" {
  description = "ElastiCache primary endpoint; use as externalRedis.url (redis://<endpoint>:6379/0)."
  value       = var.redis_enabled ? aws_elasticache_replication_group.this[0].primary_endpoint_address : null
}

output "helm_values_hint" {
  description = "Key Helm values derived from this stack."
  value = {
    "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn" = module.irsa_role.iam_role_arn
    "externalRedis.url"                                         = var.redis_enabled ? "redis://${aws_elasticache_replication_group.this[0].primary_endpoint_address}:6379/0" : ""
    "secrets.existingSecret"                                    = "nhiid-secret (sync from ${aws_secretsmanager_secret.db_dsn.name})"
  }
}

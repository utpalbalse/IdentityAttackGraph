# Collector member-role ARNs the hub IRSA role may assume. Empty account list => any account's
# role of the configured name (convenient for demos; scope to explicit accounts for prod).
locals {
  collector_role_arns = length(var.collector_member_account_ids) > 0 ? [
    for acct in var.collector_member_account_ids :
    "arn:aws:iam::${acct}:role/${var.collector_member_role_name}"
  ] : ["arn:aws:iam::*:role/${var.collector_member_role_name}"]
}

# Least-priv permissions for the NHIID app pods: assume read-only collector roles in member
# accounts, and read the database DSN secret. No direct cloud-read perms live here — discovery
# happens through the assumed member-account role with an ExternalId-guarded trust.
data "aws_iam_policy_document" "collector" {
  statement {
    sid       = "AssumeCollectorRoles"
    effect    = "Allow"
    actions   = ["sts:AssumeRole"]
    resources = local.collector_role_arns
  }

  statement {
    sid       = "ReadDatabaseSecret"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.db_dsn.arn]
  }
}

resource "aws_iam_policy" "collector" {
  name_prefix = "${local.name}-collector-"
  description = "NHIID app: assume member-account collector roles + read DB secret"
  policy      = data.aws_iam_policy_document.collector.json
  tags        = local.tags
}

# IRSA hub role bound to the Kubernetes ServiceAccount used by the Helm release.
module "irsa_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.39"

  role_name = "${local.name}-collector-irsa"

  role_policy_arns = {
    collector = aws_iam_policy.collector.arn
  }

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["${var.app_namespace}:${var.app_service_account}"]
    }
  }

  tags = local.tags
}

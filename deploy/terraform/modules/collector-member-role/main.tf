# Read-only collector role for a single member account. Apply this in EACH AWS account NHIID
# should inventory. It trusts the central hub IRSA role, gated by a shared ExternalId, and grants
# only the read permissions the AWS collector needs (IAM/STS introspection + CloudTrail lookup).

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

data "aws_iam_policy_document" "trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [var.trusted_role_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.external_id]
    }
  }
}

# Least-privilege read-only discovery. IAM Get*/List* enumerate identities, keys, policies, and
# trust; cloudtrail:LookupEvents backs usage/last-used signals; sts:GetCallerIdentity resolves the
# account. None of these expose secret material.
data "aws_iam_policy_document" "permissions" {
  statement {
    sid    = "IamReadOnly"
    effect = "Allow"
    actions = [
      "iam:GetAccountAuthorizationDetails",
      "iam:GetAccountSummary",
      "iam:ListUsers",
      "iam:ListRoles",
      "iam:GetRole",
      "iam:GetUser",
      "iam:ListAccessKeys",
      "iam:GetAccessKeyLastUsed",
      "iam:ListUserPolicies",
      "iam:ListAttachedUserPolicies",
      "iam:ListRolePolicies",
      "iam:ListAttachedRolePolicies",
      "iam:GetUserPolicy",
      "iam:GetRolePolicy",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:ListPolicyVersions",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "CloudTrailLookup"
    effect    = "Allow"
    actions   = ["cloudtrail:LookupEvents"]
    resources = ["*"]
  }

  statement {
    sid       = "StsIdentity"
    effect    = "Allow"
    actions   = ["sts:GetCallerIdentity"]
    resources = ["*"]
  }
}

resource "aws_iam_role" "collector" {
  name                 = var.role_name
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
  description          = "NHIID read-only non-human-identity collector role"
  tags                 = var.tags
}

resource "aws_iam_role_policy" "collector" {
  name   = "${var.role_name}-readonly"
  role   = aws_iam_role.collector.id
  policy = data.aws_iam_policy_document.permissions.json
}

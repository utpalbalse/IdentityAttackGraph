# =============================================================================
# NHIID demo estate — deliberately vulnerable, deliberately disposable.
#
# This builds the smallest real AWS environment that reproduces NHIID's hero
# finding on live data: a leaked access key that can assume a weakly-guarded
# role that can read a crown-jewel S3 bucket.
#
#     svc-billing-export (IAM user, access key)
#            │  can assume  (trust policy has NO ExternalId / MFA)   -> conditionless_assume_role
#            ▼
#     billing-admin (IAM role, s3:* on the billing bucket)
#            │  acts on
#            ▼
#     <prefix>-prod-billing (S3)  tagged nhiid:criticality=crown_jewel
#
# It is safe by construction: every resource is prefixed, buckets are EMPTY,
# private, and public-access-blocked, and the only credential created is for a
# user with no real access to anything of value. Nothing here holds real data.
#
# Cost: ~$0 (IAM, empty S3, and tags are free). Enabling CloudTrail adds pennies.
# Teardown: `terraform destroy` removes everything the prefix owns.
# =============================================================================

provider "aws" {
  region = var.region

  # Stamp every resource so it is obvious in the console (and to any teammate)
  # that this is a disposable NHIID demo estate, not production.
  default_tags {
    tags = merge({
      "nhiid:estate"  = "demo"
      "nhiid:purpose" = "security-demo-delete-me"
    }, var.tags)
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  # Principal allowed to assume the read-only collector role. Empty var -> account root.
  collector_trusted_arn = var.collector_trusted_principal_arn != "" ? var.collector_trusted_principal_arn : "arn:${local.partition}:iam::${local.account_id}:root"
}

# Random suffix keeps S3 bucket names globally unique across re-applies/accounts.
resource "random_id" "suffix" {
  byte_length = 4
}

# -----------------------------------------------------------------------------
# The crown jewel: an S3 bucket tagged so the collector elevates it to crown_jewel.
# Empty + private + public-access-blocked -> a screenshot of it can never leak data.
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "prod_billing" {
  bucket        = "${var.name_prefix}-prod-billing-${random_id.suffix.hex}"
  force_destroy = true # allow `terraform destroy` even if something wrote objects

  tags = {
    (var.criticality_tag_key) = "crown_jewel"
    "nhiid:role"              = "crown-jewel"
  }
}

resource "aws_s3_bucket_public_access_block" "prod_billing" {
  bucket                  = aws_s3_bucket.prod_billing.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# A second, untagged bucket for contrast: proves the crown-jewel signal comes
# from the tag, not from "it's an S3 bucket". This one stays plain 'high' at most.
resource "aws_s3_bucket" "dev_scratch" {
  bucket        = "${var.name_prefix}-dev-scratch-${random_id.suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "dev_scratch" {
  bucket                  = aws_s3_bucket.dev_scratch.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# -----------------------------------------------------------------------------
# The foothold: a CI/exporter service user with a long-lived access key.
# Output the key so you can commit it to a THROWAWAY repo and let the repo
# collector raise `secret_exposed_in_repo` (the "leaked into a .env" story).
# -----------------------------------------------------------------------------
resource "aws_iam_user" "svc_billing_export" {
  name          = "${var.name_prefix}-svc-billing-export"
  force_destroy = true
}

resource "aws_iam_access_key" "svc_billing_export" {
  user = aws_iam_user.svc_billing_export.name
}

# The user itself only needs to be able to assume the powerful role — the whole
# point is that a low-value credential unlocks a high-value path.
resource "aws_iam_user_policy" "svc_billing_export_assume" {
  name = "assume-billing-admin"
  user = aws_iam_user.svc_billing_export.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "AssumeBillingAdmin"
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = aws_iam_role.billing_admin.arn
    }]
  })
}

# -----------------------------------------------------------------------------
# The capability hop: a role the user can assume with NO ExternalId and NO MFA
# condition. That missing guard is exactly what `conditionless_assume_role` flags.
# Its permissions give s3:* on the crown-jewel bucket -> high blast radius.
# -----------------------------------------------------------------------------
resource "aws_iam_role" "billing_admin" {
  name = "${var.name_prefix}-billing-admin"

  # Conditionless trust: the user can assume this role with nothing but its key.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = aws_iam_user.svc_billing_export.arn }
      Action    = "sts:AssumeRole"
      # NOTE: intentionally no Condition (no sts:ExternalId, no aws:MultiFactorAuthPresent).
    }]
  })
}

resource "aws_iam_role_policy" "billing_admin" {
  name = "billing-bucket-full"
  role = aws_iam_role.billing_admin.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "FullBillingBucket"
      Effect = "Allow"
      Action = "s3:*"
      Resource = [
        aws_s3_bucket.prod_billing.arn,
        "${aws_s3_bucket.prod_billing.arn}/*",
      ]
    }]
  })
}

# -----------------------------------------------------------------------------
# A second over-privileged role for a richer graph: broad write across data
# services + iam:PassRole (a classic privilege-escalation primitive). Fires
# `over_privileged_sa` and the priv-esc flag.
# -----------------------------------------------------------------------------
resource "aws_iam_role" "over_privileged_ci" {
  name = "${var.name_prefix}-over-privileged-ci"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:${local.partition}:iam::${local.account_id}:root" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "over_privileged_ci" {
  name = "broad-ci"
  role = aws_iam_role.over_privileged_ci.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "BroadData"
        Effect   = "Allow"
        Action   = ["s3:*", "dynamodb:*", "secretsmanager:GetSecretValue"]
        Resource = "*"
      },
      {
        Sid      = "PassAnyRole"
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = "*"
      },
    ]
  })
}

# -----------------------------------------------------------------------------
# The read-only role NHIID assumes to collect. Reuses the shared module so this
# estate exercises the exact same collection path a real member account would.
# -----------------------------------------------------------------------------
module "collector_role" {
  count  = var.create_collector_role ? 1 : 0
  source = "../modules/collector-member-role"

  role_name        = "${var.name_prefix}-collector"
  trusted_role_arn = local.collector_trusted_arn
  external_id      = var.collector_external_id
  tags = {
    "nhiid:role" = "collector"
  }
}

# -----------------------------------------------------------------------------
# Optional: a management-events trail so the collector has usage history to
# attribute. Off by default (keeps the estate free). The trail writes to its own
# dedicated bucket with the required service bucket policy.
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "trail" {
  count         = var.enable_cloudtrail ? 1 : 0
  bucket        = "${var.name_prefix}-trail-${random_id.suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "trail" {
  count                   = var.enable_cloudtrail ? 1 : 0
  bucket                  = aws_s3_bucket.trail[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "trail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.trail[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail[0].arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail[0].arn}/AWSLogs/${local.account_id}/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      },
    ]
  })
}

resource "aws_cloudtrail" "demo" {
  count                         = var.enable_cloudtrail ? 1 : 0
  name                          = "${var.name_prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.trail[0].id
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_logging                = true
  depends_on                    = [aws_s3_bucket_policy.trail]
}

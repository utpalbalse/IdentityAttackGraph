# Inputs for the throwaway demo estate. Every default is chosen so `terraform apply` with no
# tfvars produces the "leaked key -> crown jewel" storyline NHIID is built to find. Override the
# prefix if you run more than one estate in the same account.

variable "region" {
  description = "AWS region to create the estate in. IAM is global; only S3/CloudTrail are regional."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix on every resource so teardown is unambiguous and nothing collides with real resources. Keep the 'nhiid-demo' lineage so `terraform destroy` (and a human) can tell these apart at a glance."
  type        = string
  default     = "nhiid-demo"
}

variable "criticality_tag_key" {
  description = "Tag key the collector reads to classify crown-jewel resources. Must match the collector's --criticality-tag (default nhiid:criticality)."
  type        = string
  default     = "nhiid:criticality"
}

variable "create_collector_role" {
  description = "Create the read-only role NHIID assumes to collect. Leave true for the realistic cross-account setup; you can also just run the collector with your own credentials same-account (see README)."
  type        = bool
  default     = true
}

variable "collector_trusted_principal_arn" {
  description = "ARN allowed to assume the read-only collector role. Empty = this account's root (any principal in the account that also has sts:AssumeRole). For a real hub, pass the NHIID IRSA role ARN."
  type        = string
  default     = ""
}

variable "collector_external_id" {
  description = "Shared ExternalId required on the collector assume-role (confused-deputy guard). Pass the same value to the collector via --external-id."
  type        = string
  default     = "nhiid-demo-external-id"
}

variable "enable_cloudtrail" {
  description = "Create a management-events CloudTrail so the collector has usage history to attribute (drives the 'usage' risk factor). Off by default to keep the estate free; a short session with it on costs pennies. Note: CloudTrail records source IP but not country/ASN, so geo/impossible-travel anomalies still need the geo-enrichment step (roadmap) to fire on live data."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Extra tags merged onto every resource. The estate marker tag is always added."
  type        = map(string)
  default     = {}
}

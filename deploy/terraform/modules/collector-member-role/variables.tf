variable "role_name" {
  description = "Name of the collector role to create in this member account. Must match the name the hub IRSA role is allowed to assume."
  type        = string
  default     = "nhiid-collector"
}

variable "trusted_role_arn" {
  description = "ARN of the NHIID hub IRSA role (terraform output irsa_role_arn from the main stack) that may assume this role."
  type        = string
}

variable "external_id" {
  description = "Shared ExternalId required on the assume-role call (defense against the confused-deputy problem). Pass the same value to the collector via --external-id."
  type        = string
}

variable "tags" {
  type    = map(string)
  default = {}
}

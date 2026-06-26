variable "region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "name" {
  description = "Name prefix for all resources (cluster, RDS, etc.)."
  type        = string
  default     = "nhiid"
}

variable "environment" {
  description = "Environment label applied as a tag (e.g. dev, staging, prod)."
  type        = string
  default     = "dev"
}

variable "tags" {
  description = "Additional tags applied to every resource."
  type        = map(string)
  default     = {}
}

# ---- Networking ----
variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.40.0.0/16"
}

variable "az_count" {
  description = "Number of Availability Zones to spread subnets across."
  type        = number
  default     = 3
}

# ---- EKS ----
variable "kubernetes_version" {
  description = "EKS control-plane version."
  type        = string
  default     = "1.30"
}

variable "node_instance_types" {
  description = "Instance types for the managed node group."
  type        = list(string)
  default     = ["t3.large"]
}

variable "node_min_size" {
  type    = number
  default = 2
}

variable "node_max_size" {
  type    = number
  default = 5
}

variable "node_desired_size" {
  type    = number
  default = 2
}

variable "cluster_public_access" {
  description = "Expose the EKS public API endpoint. Set false for fully private clusters."
  type        = bool
  default     = true
}

variable "cluster_public_access_cidrs" {
  description = "CIDRs allowed to reach the public EKS API endpoint."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

# ---- RDS (Postgres) ----
variable "db_instance_class" {
  type    = string
  default = "db.t4g.medium"
}

variable "db_allocated_storage" {
  type    = number
  default = 20
}

variable "db_max_allocated_storage" {
  description = "Upper bound for storage autoscaling."
  type        = number
  default     = 100
}

variable "db_engine_version" {
  type    = string
  default = "16.4"
}

variable "db_name" {
  type    = string
  default = "nhiid"
}

variable "db_username" {
  type    = string
  default = "nhiid"
}

variable "db_multi_az" {
  description = "Run RDS in Multi-AZ (recommended for prod)."
  type        = bool
  default     = false
}

variable "db_deletion_protection" {
  type    = bool
  default = false
}

# ---- ElastiCache (Redis) ----
variable "redis_enabled" {
  type    = bool
  default = true
}

variable "redis_node_type" {
  type    = string
  default = "cache.t4g.micro"
}

variable "redis_engine_version" {
  type    = string
  default = "7.1"
}

# ---- IRSA / collector ----
variable "app_namespace" {
  description = "Kubernetes namespace the NHIID release runs in."
  type        = string
  default     = "nhiid"
}

variable "app_service_account" {
  description = "Kubernetes ServiceAccount name (must match the Helm release's serviceAccountName)."
  type        = string
  default     = "nhiid"
}

variable "collector_member_role_name" {
  description = "Name of the read-only collector role deployed in each member account (the IRSA hub role is granted sts:AssumeRole to roles with this name)."
  type        = string
  default     = "nhiid-collector"
}

variable "collector_member_account_ids" {
  description = "Member AWS account IDs the collector may assume into. Empty list allows any account's collector role (scope down for prod)."
  type        = list(string)
  default     = []
}

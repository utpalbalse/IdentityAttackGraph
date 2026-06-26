provider "aws" {
  region = var.region

  default_tags {
    tags = local.tags
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

locals {
  name = var.name

  azs = slice(data.aws_availability_zones.available.names, 0, var.az_count)

  # /20 private + /24 public subnets carved from the VPC CIDR.
  private_subnets = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, 4, i)]
  public_subnets  = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, 8, i + 48)]

  tags = merge({
    "app.kubernetes.io/part-of" = "nhiid"
    "environment"               = var.environment
    "terraform"                 = "true"
  }, var.tags)
}

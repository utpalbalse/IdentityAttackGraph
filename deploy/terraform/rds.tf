# Security group: allow Postgres only from the EKS node group.
resource "aws_security_group" "rds" {
  name_prefix = "${local.name}-rds-"
  description = "NHIID RDS Postgres access from EKS nodes"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description     = "Postgres from EKS nodes"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [module.eks.node_security_group_id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "random_password" "db" {
  length  = 24
  special = false # avoid DSN/URL-encoding pitfalls
}

module "rds" {
  source  = "terraform-aws-modules/rds/aws"
  version = "~> 6.5"

  identifier = "${local.name}-pg"

  engine               = "postgres"
  engine_version       = var.db_engine_version
  family               = "postgres16"
  major_engine_version = "16"
  instance_class       = var.db_instance_class

  allocated_storage     = var.db_allocated_storage
  max_allocated_storage = var.db_max_allocated_storage
  storage_encrypted     = true

  db_name  = var.db_name
  username = var.db_username
  port     = 5432

  # We manage the password ourselves (stored as a full DSN in Secrets Manager below), so disable
  # both RDS-managed credentials and the module's own random-password generation.
  manage_master_user_password = false
  create_random_password      = false
  password                    = random_password.db.result

  multi_az               = var.db_multi_az
  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  backup_retention_period = 7
  deletion_protection     = var.db_deletion_protection
  skip_final_snapshot     = !var.db_deletion_protection

  performance_insights_enabled = true

  tags = local.tags
}

resource "aws_db_subnet_group" "this" {
  name       = "${local.name}-db"
  subnet_ids = module.vpc.private_subnets
  tags       = local.tags
}

# Full DSN stored in Secrets Manager. Wire this into the Helm release via the External Secrets
# Operator (or the Secrets Store CSI driver) so it becomes the chart's existingSecret with a
# `database-dsn` key. See deploy/terraform/README.md.
resource "aws_secretsmanager_secret" "db_dsn" {
  name        = "${local.name}/database-dsn"
  description = "NHIID Postgres DSN (host/credentials)"
  tags        = local.tags
}

resource "aws_secretsmanager_secret_version" "db_dsn" {
  secret_id = aws_secretsmanager_secret.db_dsn.id
  secret_string = jsonencode({
    database-dsn = "postgres://${var.db_username}:${random_password.db.result}@${module.rds.db_instance_address}:5432/${var.db_name}?sslmode=require"
  })
}

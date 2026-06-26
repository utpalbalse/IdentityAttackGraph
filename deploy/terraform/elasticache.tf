resource "aws_security_group" "redis" {
  count       = var.redis_enabled ? 1 : 0
  name_prefix = "${local.name}-redis-"
  description = "NHIID ElastiCache Redis access from EKS nodes"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description     = "Redis from EKS nodes"
    from_port       = 6379
    to_port         = 6379
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

resource "aws_elasticache_subnet_group" "this" {
  count      = var.redis_enabled ? 1 : 0
  name       = "${local.name}-redis"
  subnet_ids = module.vpc.private_subnets
  tags       = local.tags
}

# Single-node Redis for the per-principal rate limiter. The limiter fails open, so this is
# non-critical; scale to a replication group with automatic failover for prod if desired.
resource "aws_elasticache_replication_group" "this" {
  count                      = var.redis_enabled ? 1 : 0
  replication_group_id       = "${local.name}-redis"
  description                = "NHIID rate-limiter cache"
  engine                     = "redis"
  engine_version             = var.redis_engine_version
  node_type                  = var.redis_node_type
  num_cache_clusters         = 1
  port                       = 6379
  parameter_group_name       = "default.redis7"
  subnet_group_name          = aws_elasticache_subnet_group.this[0].name
  security_group_ids         = [aws_security_group.redis[0].id]
  at_rest_encryption_enabled = true
  transit_encryption_enabled = false # app connects with redis:// (no TLS); enable + use rediss:// to harden

  tags = local.tags
}

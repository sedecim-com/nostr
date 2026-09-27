# ---------------------------------------------------------------------------------------------------
# Highly available Postgres (NFR001-03): RDS PostgreSQL 17 Multi-AZ (synchronous standby in another AZ,
# automatic failover), automated backups with point-in-time recovery, KMS encryption, TLS required and
# access only from the cluster nodes. The master password is generated and kept by RDS in Secrets Manager
# (manage_master_user_password); applications use their own role (docs/runbooks/rds-postgres.md).

locals {
  rds_enabled = var.enable_rds
}

resource "aws_kms_key" "rds" {
  count                   = local.rds_enabled ? 1 : 0
  description             = "Acceso Nostr ${var.environment}: cifrado de RDS, snapshots y secreto maestro"
  enable_key_rotation     = true
  deletion_window_in_days = var.kms_deletion_window_in_days
  tags                    = local.tags
}

resource "aws_kms_alias" "rds" {
  count         = local.rds_enabled ? 1 : 0
  name          = "alias/${local.prefix}-rds"
  target_key_id = aws_kms_key.rds[0].key_id
}

resource "aws_db_subnet_group" "postgres" {
  count       = local.rds_enabled ? 1 : 0
  name        = "${local.prefix}-postgres"
  description = "Acceso Nostr ${var.environment}: subredes privadas de RDS (al menos dos AZ)"
  subnet_ids  = var.rds_subnet_ids
  tags        = local.tags

  lifecycle {
    precondition {
      condition     = length(var.rds_subnet_ids) >= 2 && var.vpc_id != ""
      error_message = "enable_rds requiere vpc_id y al menos dos rds_subnet_ids en AZ distintas (Multi-AZ)."
    }
  }
}

resource "aws_security_group" "postgres" {
  count       = local.rds_enabled ? 1 : 0
  name        = "${local.prefix}-postgres"
  description = "Acceso Nostr ${var.environment}: Postgres solo desde los nodos del cluster"
  vpc_id      = var.vpc_id
  tags        = merge(local.tags, { Name = "${local.prefix}-postgres" })
}

resource "aws_vpc_security_group_ingress_rule" "postgres" {
  for_each                     = local.rds_enabled ? toset(var.rds_allowed_security_group_ids) : toset([])
  security_group_id            = aws_security_group.postgres[0].id
  description                  = "Postgres from the cluster nodes"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = each.value
  tags                         = local.tags
}

resource "aws_db_parameter_group" "postgres" {
  count       = local.rds_enabled ? 1 : 0
  name        = "${local.prefix}-postgres17"
  family      = "postgres17"
  description = "Acceso Nostr ${var.environment}: TLS obligatorio"
  tags        = local.tags

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  parameter {
    name  = "ssl_min_protocol_version"
    value = "TLSv1.2"
  }

  # Slow queries in the postgresql log (CloudWatch), never statement parameters.
  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_db_instance" "postgres" {
  count          = local.rds_enabled ? 1 : 0
  identifier     = "${local.prefix}-postgres"
  engine         = "postgres"
  engine_version = var.rds_engine_version
  instance_class = var.rds_instance_class

  allocated_storage     = var.rds_allocated_storage
  max_allocated_storage = var.rds_max_allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.rds[0].arn

  # High availability: synchronous standby in another AZ; failover flips the endpoint's DNS.
  multi_az               = true
  db_subnet_group_name   = aws_db_subnet_group.postgres[0].name
  vpc_security_group_ids = [aws_security_group.postgres[0].id]
  publicly_accessible    = false
  port                   = 5432
  parameter_group_name   = aws_db_parameter_group.postgres[0].name
  ca_cert_identifier     = "rds-ca-rsa2048-g1"

  username                      = var.rds_master_username
  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.rds[0].arn

  # Automated backups + transaction logs = point-in-time restore within the retention window.
  backup_retention_period   = var.rds_backup_retention_days
  backup_window             = var.rds_backup_window
  maintenance_window        = var.rds_maintenance_window
  copy_tags_to_snapshot     = true
  delete_automated_backups  = false
  deletion_protection       = var.rds_deletion_protection
  skip_final_snapshot       = false
  final_snapshot_identifier = "${local.prefix}-postgres-final"

  auto_minor_version_upgrade   = true
  allow_major_version_upgrade  = false
  apply_immediately            = false
  performance_insights_enabled = var.rds_performance_insights
  # The KMS key is only valid while Performance Insights is on.
  performance_insights_kms_key_id = var.rds_performance_insights ? aws_kms_key.rds[0].arn : null
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  tags = local.tags
}

# AWS resources of Acceso Nostr for one environment (NFR001-01). Consumed from the `infrastructure`
# repository (terraform/main.tf, provider us-east-1); see deploy/README.md.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  prefix     = "${var.name}-${var.environment}"
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  partition  = data.aws_partition.current.partition

  # Keys of the managed signer live under this Secrets Manager prefix (MANAGED_SIGNER_SECRET_PREFIX).
  managed_keys_prefix = "${var.name}/${var.environment}/managed-keys/"

  tags = merge({
    Terraform   = "true"
    Project     = var.name
    Environment = var.environment
  }, var.tags)

  alb_enabled = var.vpc_id != ""
}

# ---------------------------------------------------------------------------------------------------
# Stack configuration secret, read by deploy/k8s/scripts/generate-secret.sh. Terraform creates the
# container only: values are written by `generate-secret.sh --bootstrap` (never in Terraform state).
resource "aws_secretsmanager_secret" "stack" {
  name                    = "k8s/${var.environment}/${var.name}"
  description             = "Acceso Nostr ${var.environment}: secretos del stack (JSON clave/valor)"
  recovery_window_in_days = var.secret_recovery_window_in_days
  tags                    = local.tags
}

# ---------------------------------------------------------------------------------------------------
# Managed signer (ADR 0009): dedicated KMS key (annual rotation) for the envelope + Secrets Manager prefix.
resource "aws_kms_key" "managed_signer" {
  count                   = var.enable_managed_signer ? 1 : 0
  description             = "Acceso Nostr ${var.environment}: envelope de las llaves managed (ADR 0009)"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = var.kms_deletion_window_in_days
  tags                    = local.tags
}

resource "aws_kms_alias" "managed_signer" {
  count         = var.enable_managed_signer ? 1 : 0
  name          = "alias/${local.prefix}-managed-signer"
  target_key_id = aws_kms_key.managed_signer[0].key_id
}

data "aws_iam_policy_document" "managed_signer" {
  count = var.enable_managed_signer ? 1 : 0

  # GenerateDataKey/Decrypt on this key only (services/managed-signer/src/aws.ts).
  statement {
    sid       = "EnvelopeKey"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [aws_kms_key.managed_signer[0].arn]
  }

  # CreateSecret (with the app tag), GetSecretValue and DeleteSecret (recovery window) under the prefix.
  statement {
    sid = "ManagedKeys"
    actions = [
      "secretsmanager:CreateSecret",
      "secretsmanager:GetSecretValue",
      "secretsmanager:DeleteSecret",
      "secretsmanager:DescribeSecret",
      "secretsmanager:TagResource",
    ]
    resources = ["arn:${local.partition}:secretsmanager:${local.region}:${local.account_id}:secret:${local.managed_keys_prefix}*"]
  }
}

resource "aws_iam_policy" "managed_signer" {
  count       = var.enable_managed_signer ? 1 : 0
  name        = "${local.prefix}-managed-signer"
  description = "Acceso Nostr ${var.environment}: permisos mínimos del managed-signer (ADR 0009)"
  policy      = data.aws_iam_policy_document.managed_signer[0].json
  tags        = local.tags
}

# kops without IRSA: dedicated IAM user, keys stored in Secrets Manager as the Sedecim common/iam_user
# module does (<user>_credentials = {"id","secret"}).
resource "aws_iam_user" "managed_signer" {
  count = var.enable_managed_signer && var.create_iam_users ? 1 : 0
  name  = "${replace(local.prefix, "-", "_")}_managed_signer"
  tags  = local.tags
}

resource "aws_iam_user_policy_attachment" "managed_signer" {
  count      = var.enable_managed_signer && var.create_iam_users ? 1 : 0
  user       = aws_iam_user.managed_signer[0].name
  policy_arn = aws_iam_policy.managed_signer[0].arn
}

resource "aws_iam_access_key" "managed_signer" {
  count = var.enable_managed_signer && var.create_iam_users ? 1 : 0
  user  = aws_iam_user.managed_signer[0].name
}

resource "aws_secretsmanager_secret" "managed_signer_credentials" {
  count                   = var.enable_managed_signer && var.create_iam_users ? 1 : 0
  name                    = "${aws_iam_user.managed_signer[0].name}_credentials"
  recovery_window_in_days = var.secret_recovery_window_in_days
  tags                    = local.tags
}

resource "aws_secretsmanager_secret_version" "managed_signer_credentials" {
  count     = var.enable_managed_signer && var.create_iam_users ? 1 : 0
  secret_id = aws_secretsmanager_secret.managed_signer_credentials[0].id
  secret_string = jsonencode({
    id     = aws_iam_access_key.managed_signer[0].id
    secret = aws_iam_access_key.managed_signer[0].secret
  })
}

resource "aws_iam_role_policy_attachment" "managed_signer" {
  count      = var.enable_managed_signer && !var.create_iam_users && var.managed_signer_role_name != "" ? 1 : 0
  role       = var.managed_signer_role_name
  policy_arn = aws_iam_policy.managed_signer[0].arn
}

# ---------------------------------------------------------------------------------------------------
# Backups (docs/rpo-rto.md, docs/runbooks/restore.md): versioned, encrypted, private, expiring.
resource "aws_s3_bucket" "backups" {
  count  = var.create_backup_bucket ? 1 : 0
  bucket = "${local.prefix}-backups-${local.account_id}"
  tags   = local.tags
}

resource "aws_s3_bucket_public_access_block" "backups" {
  count                   = var.create_backup_bucket ? 1 : 0
  bucket                  = aws_s3_bucket.backups[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "backups" {
  count  = var.create_backup_bucket ? 1 : 0
  bucket = aws_s3_bucket.backups[0].id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "backups" {
  count  = var.create_backup_bucket ? 1 : 0
  bucket = aws_s3_bucket.backups[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "backups" {
  count  = var.create_backup_bucket ? 1 : 0
  bucket = aws_s3_bucket.backups[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "backups" {
  count  = var.create_backup_bucket ? 1 : 0
  bucket = aws_s3_bucket.backups[0].id
  rule {
    id     = "expire-backups"
    status = "Enabled"
    filter {}
    expiration {
      days = var.backup_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = var.backup_retention_days
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "backups" {
  count = var.create_backup_bucket ? 1 : 0
  statement {
    sid       = "ListBackups"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.backups[0].arn]
  }
  # Put and Get, never Delete: expiration is the lifecycle rule's job (a leaked key cannot wipe backups).
  statement {
    sid       = "ReadWriteBackups"
    actions   = ["s3:PutObject", "s3:GetObject"]
    resources = ["${aws_s3_bucket.backups[0].arn}/*"]
  }
}

resource "aws_iam_policy" "backups" {
  count       = var.create_backup_bucket ? 1 : 0
  name        = "${local.prefix}-backups"
  description = "Acceso Nostr ${var.environment}: escribir y leer backups (sin borrar)"
  policy      = data.aws_iam_policy_document.backups[0].json
  tags        = local.tags
}

resource "aws_iam_user" "backups" {
  count = var.create_backup_bucket && var.create_iam_users ? 1 : 0
  name  = "${replace(local.prefix, "-", "_")}_backups"
  tags  = local.tags
}

resource "aws_iam_user_policy_attachment" "backups" {
  count      = var.create_backup_bucket && var.create_iam_users ? 1 : 0
  user       = aws_iam_user.backups[0].name
  policy_arn = aws_iam_policy.backups[0].arn
}

resource "aws_iam_access_key" "backups" {
  count = var.create_backup_bucket && var.create_iam_users ? 1 : 0
  user  = aws_iam_user.backups[0].name
}

resource "aws_secretsmanager_secret" "backups_credentials" {
  count                   = var.create_backup_bucket && var.create_iam_users ? 1 : 0
  name                    = "${aws_iam_user.backups[0].name}_credentials"
  recovery_window_in_days = var.secret_recovery_window_in_days
  tags                    = local.tags
}

resource "aws_secretsmanager_secret_version" "backups_credentials" {
  count     = var.create_backup_bucket && var.create_iam_users ? 1 : 0
  secret_id = aws_secretsmanager_secret.backups_credentials[0].id
  secret_string = jsonencode({
    id     = aws_iam_access_key.backups[0].id
    secret = aws_iam_access_key.backups[0].secret
  })
}

# ---------------------------------------------------------------------------------------------------
# ECR: our images and the mirrors of third-party images (scan on push, bounded history).
resource "aws_ecr_repository" "this" {
  for_each             = var.create_ecr_repositories ? toset(var.ecr_repositories) : toset([])
  name                 = each.value
  image_tag_mutability = "MUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
  tags = local.tags
}

resource "aws_ecr_lifecycle_policy" "this" {
  for_each   = aws_ecr_repository.this
  repository = each.value.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep the last ${var.ecr_keep_images} images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = var.ecr_keep_images
      }
      action = { type = "expire" }
    }]
  })
}

# ---------------------------------------------------------------------------------------------------
# ALB → NodePort of the edge proxy (Sedecim pattern). The kops InstanceGroup must list the target group
# ARN in externalLoadBalancers (output alb_target_group_arn) so the nodes register themselves.
resource "aws_lb_target_group" "edge" {
  count    = local.alb_enabled ? 1 : 0
  name     = substr("${local.prefix}-edge", 0, 32)
  port     = var.node_port
  protocol = "HTTP"
  vpc_id   = var.vpc_id

  health_check {
    path    = "/_edge_health"
    matcher = "200"
  }

  tags = merge(local.tags, { Description = "Acceso Nostr ${var.environment}: edge NodePort ${var.node_port}" })
}

resource "aws_lb_listener_rule" "edge" {
  count        = local.alb_enabled && var.alb_listener_arn != "" && length(var.public_hosts) > 0 ? 1 : 0
  listener_arn = var.alb_listener_arn
  priority     = var.alb_listener_priority

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.edge[0].arn
  }

  condition {
    host_header {
      values = var.public_hosts
    }
  }

  tags = local.tags
}

resource "aws_security_group_rule" "node_port" {
  count                    = var.node_security_group_id != "" && var.alb_security_group_id != "" ? 1 : 0
  type                     = "ingress"
  description              = "Acceso Nostr ${var.environment} edge NodePort from the ALB/proxy"
  from_port                = var.node_port
  to_port                  = var.node_port
  protocol                 = "tcp"
  security_group_id        = var.node_security_group_id
  source_security_group_id = var.alb_security_group_id
}

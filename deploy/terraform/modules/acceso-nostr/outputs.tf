output "stack_secret_name" {
  description = "Secreto JSON del stack (SECRET_ID de deploy/k8s/values.env)."
  value       = aws_secretsmanager_secret.stack.name
}

output "managed_signer_kms_key_arn" {
  description = "Llave KMS del envelope del managed-signer."
  value       = try(aws_kms_key.managed_signer[0].arn, null)
}

output "managed_signer_kms_alias" {
  description = "Valor de MANAGED_SIGNER_KMS_KEY_ID en el overlay."
  value       = try(aws_kms_alias.managed_signer[0].name, null)
}

output "managed_signer_secret_prefix" {
  description = "Valor de MANAGED_SIGNER_SECRET_PREFIX en el overlay."
  value       = var.enable_managed_signer ? local.managed_keys_prefix : null
}

output "managed_signer_policy_arn" {
  description = "Política IAM mínima del managed-signer (para adjuntarla a un rol si no se usan usuarios IAM)."
  value       = try(aws_iam_policy.managed_signer[0].arn, null)
}

output "managed_signer_credentials_secret" {
  description = "Secreto con las llaves del usuario IAM del managed-signer (SIGNER_CREDENTIALS_SECRET_ID)."
  value       = try(aws_secretsmanager_secret.managed_signer_credentials[0].name, null)
}

output "backup_bucket" {
  description = "Bucket S3 de backups."
  value       = try(aws_s3_bucket.backups[0].bucket, null)
}

output "backups_credentials_secret" {
  description = "Secreto con las llaves del usuario IAM de backups."
  value       = try(aws_secretsmanager_secret.backups_credentials[0].name, null)
}

output "ecr_repository_urls" {
  description = "URL de cada repositorio ECR."
  value       = { for k, r in aws_ecr_repository.this : k => r.repository_url }
}

output "alb_target_group_arn" {
  description = "Target group del NodePort (añadir a externalLoadBalancers del InstanceGroup de kops)."
  value       = try(aws_lb_target_group.edge[0].arn, null)
}

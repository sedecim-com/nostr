# ---------------------------------------------------------------------------------------------------
# Managed signer, enclave tier (FR005-05, docs/managed-enclave.md). A dedicated KMS key whose data keys are
# released only to a Nitro Enclave with the expected measurements: KMS answers with CiphertextForRecipient
# (encrypted to the enclave's ephemeral key) and the policy requires kms:RecipientAttestation:* values.
# Nobody, including account administrators using this policy, can Decrypt/GenerateDataKey without that
# attestation. Changing PCRs (new EIF) means updating enclave_pcr* and applying before the rollout.

locals {
  enclave_enabled = var.enable_managed_signer && var.enable_enclave_signer

  # Attestation conditions: ImageSha384 is PCR0; PCR1/PCR2 always, PCR8 (EIF signing cert) when set.
  enclave_attestation_conditions = merge(
    {
      "kms:RecipientAttestation:ImageSha384" = var.enclave_pcr0
      "kms:RecipientAttestation:PCR1"        = var.enclave_pcr1
      "kms:RecipientAttestation:PCR2"        = var.enclave_pcr2
    },
    var.enclave_pcr8 == "" ? {} : { "kms:RecipientAttestation:PCR8" = var.enclave_pcr8 },
  )

  enclave_key_admins = length(var.enclave_key_admin_arns) > 0 ? var.enclave_key_admin_arns : ["arn:${local.partition}:iam::${local.account_id}:root"]

  # Parent principals that relay the enclave's KMS calls: the signer IAM user (kops) or explicit roles.
  enclave_principals = concat(
    var.enclave_principal_arns,
    var.create_iam_users && var.enable_managed_signer ? [aws_iam_user.managed_signer[0].arn] : [],
  )
}

data "aws_iam_policy_document" "enclave_key" {
  count = local.enclave_enabled ? 1 : 0

  # Key administration without any cryptographic use (no IAM delegation of Decrypt through "kms:*").
  statement {
    sid = "KeyAdministration"
    principals {
      type        = "AWS"
      identifiers = local.enclave_key_admins
    }
    actions = [
      "kms:Create*",
      "kms:Describe*",
      "kms:Enable*",
      "kms:List*",
      "kms:Put*",
      "kms:Update*",
      "kms:Revoke*",
      "kms:Disable*",
      "kms:Get*",
      "kms:Delete*",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:ScheduleKeyDeletion",
      "kms:CancelKeyDeletion",
      "kms:RotateKeyOnDemand",
    ]
    resources = ["*"]
  }

  statement {
    sid = "EnclaveUseWithAttestation"
    principals {
      type        = "AWS"
      identifiers = local.enclave_principals
    }
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = ["*"]

    dynamic "condition" {
      for_each = local.enclave_attestation_conditions
      content {
        test     = "StringEqualsIgnoreCase"
        variable = condition.key
        values   = [condition.value]
      }
    }
  }

  # Explicit deny for everyone else: without a matching attestation document (absent keys evaluate as not
  # equal) no principal gets plaintext or data keys, whatever IAM policies say.
  statement {
    sid    = "DenyWithoutEnclaveAttestation"
    effect = "Deny"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions   = ["kms:Decrypt", "kms:GenerateDataKey", "kms:GenerateDataKeyPair", "kms:GenerateDataKeyPairWithoutPlaintext", "kms:GenerateDataKeyWithoutPlaintext"]
    resources = ["*"]
    condition {
      test     = "StringNotEqualsIgnoreCase"
      variable = "kms:RecipientAttestation:ImageSha384"
      values   = [var.enclave_pcr0]
    }
  }

  # Re-encrypting to another key would move the material out of the attestation boundary.
  statement {
    sid    = "DenyReEncrypt"
    effect = "Deny"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions   = ["kms:ReEncrypt*"]
    resources = ["*"]
  }
}

resource "aws_kms_key" "enclave_signer" {
  count                   = local.enclave_enabled ? 1 : 0
  description             = "Acceso Nostr ${var.environment}: llaves managed selladas al enclave Nitro (FR005-05)"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = var.kms_deletion_window_in_days
  policy                  = data.aws_iam_policy_document.enclave_key[0].json
  tags                    = local.tags

  lifecycle {
    precondition {
      condition     = var.enclave_pcr0 != "" && var.enclave_pcr1 != "" && var.enclave_pcr2 != ""
      error_message = "enable_enclave_signer requiere enclave_pcr0, enclave_pcr1 y enclave_pcr2 (salida de nitro-cli build-enclave)."
    }
    precondition {
      condition     = length(local.enclave_principals) > 0
      error_message = "enable_enclave_signer requiere un principal padre: create_iam_users = true o enclave_principal_arns."
    }
  }
}

resource "aws_kms_alias" "enclave_signer" {
  count         = local.enclave_enabled ? 1 : 0
  name          = "alias/${local.prefix}-enclave-signer"
  target_key_id = aws_kms_key.enclave_signer[0].key_id
}

# Optional Nitro-enabled parent host: EC2 launch template with enclave_options and IMDSv2 only. The host
# runs the managed-signer container plus `nitro-cli run-enclave` (docs/managed-enclave.md); kops node groups
# can instead set the same option on their launch template.
resource "aws_launch_template" "enclave_host" {
  count         = local.enclave_enabled && var.enclave_host_ami_id != "" ? 1 : 0
  name_prefix   = "${local.prefix}-enclave-host-"
  image_id      = var.enclave_host_ami_id
  instance_type = var.enclave_host_instance_type

  enclave_options {
    enabled = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  dynamic "iam_instance_profile" {
    for_each = var.enclave_host_instance_profile == "" ? [] : [var.enclave_host_instance_profile]
    content {
      name = iam_instance_profile.value
    }
  }

  vpc_security_group_ids = var.enclave_host_security_group_ids

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      encrypted   = true
      volume_size = 30
      volume_type = "gp3"
    }
  }

  tag_specifications {
    resource_type = "instance"
    tags          = merge(local.tags, { Name = "${local.prefix}-enclave-host" })
  }

  tags = local.tags
}

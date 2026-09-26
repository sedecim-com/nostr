# How the `infrastructure` repository consumes the module (terraform/main.tf, same provider and state).
# Here the source is the local path so `terraform validate` runs in this repository; in infrastructure
# use the git source pinned to a reviewed commit:
#
#   source = "git::https://github.com/sedecim-com/nostr.git//deploy/terraform/modules/acceso-nostr?ref=<commit>"
#
# Values come from infrastructure/terraform: VPC vpc-7907b103 (modules/sedecim), the ALB listener with the
# *.ai.acce.so certificate, the kops nodes SG and the proxy SG sg-0e939eb598c1416fb (modules/kubernetes).
terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

variable "alb_listener_arn" {
  description = "Listener HTTPS del ALB con el certificado *.ai.acce.so."
  type        = string
  default     = ""
}

variable "node_security_group_id" {
  description = "SG de los nodos de sedecim-stage.k8s.local."
  type        = string
  default     = ""
}

module "acceso_nostr_stage" {
  source = "../../modules/acceso-nostr"

  environment = "stage"

  # ALB → NodePort 31810 → edge (deploy/k8s/overlays/stage).
  vpc_id                 = "vpc-7907b103"
  node_port              = 31810
  alb_listener_arn       = var.alb_listener_arn
  alb_listener_priority  = 90
  node_security_group_id = var.node_security_group_id
  alb_security_group_id  = "sg-0e939eb598c1416fb"
  public_hosts = [
    "nostr-stage.ai.acce.so",
    "nostr-stage-relay.ai.acce.so",
    "nostr-stage-secure.ai.acce.so",
    "nostr-stage-blobs.ai.acce.so",
    "nostr-stage-mirror.ai.acce.so",
    "nostr-stage-id.ai.acce.so",
    "nostr-stage-policy.ai.acce.so",
    "nostr-stage-signer.ai.acce.so",
  ]
}

output "acceso_nostr_stage" {
  value = {
    stack_secret                 = module.acceso_nostr_stage.stack_secret_name
    managed_signer_kms_alias     = module.acceso_nostr_stage.managed_signer_kms_alias
    managed_signer_secret_prefix = module.acceso_nostr_stage.managed_signer_secret_prefix
    signer_credentials_secret    = module.acceso_nostr_stage.managed_signer_credentials_secret
    backup_bucket                = module.acceso_nostr_stage.backup_bucket
    target_group_arn             = module.acceso_nostr_stage.alb_target_group_arn
  }
}

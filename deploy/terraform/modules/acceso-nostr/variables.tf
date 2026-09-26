variable "environment" {
  description = "Entorno (stage, production). Forma parte de los nombres: k8s/<env>/acceso-nostr, alias/acceso-nostr-<env>-managed-signer, ..."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,15}$", var.environment))
    error_message = "environment: minúsculas, dígitos y guiones (2-16 caracteres)."
  }
}

variable "name" {
  description = "Prefijo de los recursos del proyecto."
  type        = string
  default     = "acceso-nostr"
}

variable "tags" {
  description = "Etiquetas adicionales para todos los recursos."
  type        = map(string)
  default     = {}
}

# --- managed signer (ADR 0009)
variable "enable_managed_signer" {
  description = "Crea la llave KMS y los permisos del managed-signer (solo SaaS)."
  type        = bool
  default     = true
}

variable "kms_deletion_window_in_days" {
  description = "Ventana de borrado de la llave KMS (7-30)."
  type        = number
  default     = 30
}

variable "managed_signer_retention_days" {
  description = "Días de recuperación de un secreto de llave borrado (DEC-09: 30; Secrets Manager admite 7-30)."
  type        = number
  default     = 30

  validation {
    condition     = var.managed_signer_retention_days >= 7 && var.managed_signer_retention_days <= 30
    error_message = "Secrets Manager solo admite ventanas de recuperación de 7 a 30 días."
  }
}

variable "create_iam_users" {
  description = "kops sin IRSA: crea usuarios IAM dedicados (patrón Sedecim, llaves guardadas en Secrets Manager <usuario>_credentials). false si los pods asumen un rol."
  type        = bool
  default     = true
}

variable "managed_signer_role_name" {
  description = "Si create_iam_users = false: rol IAM al que adjuntar la política del managed-signer (vacío = no adjuntar)."
  type        = string
  default     = ""
}

# --- config secret
variable "secret_recovery_window_in_days" {
  description = "Ventana de recuperación del secreto k8s/<env>/acceso-nostr."
  type        = number
  default     = 7
}

# --- backups (docs/rpo-rto.md)
variable "create_backup_bucket" {
  description = "Crea el bucket S3 de backups (pg_dump, volúmenes de blobs y media) con versionado y cifrado."
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Días que se conservan los backups (y sus versiones no actuales)."
  type        = number
  default     = 35
}

# --- ECR
variable "ecr_repositories" {
  description = "Repositorios ECR: imágenes propias y espejos (deploy/k8s/scripts/mirror-ecr-deps.sh)."
  type        = list(string)
  default = [
    "acceso-nostr-service",
    "acceso-nostr-web",
    "acceso-nostr-buzz",
    "acceso-nostr-seaweedfs",
    "acceso-nostr-secure-relay",
    "acceso-nostr-postgres",
    "acceso-nostr-redis",
    "acceso-nostr-nginx",
    "acceso-nostr-prometheus",
    "acceso-nostr-blackbox-exporter",
    "acceso-nostr-alertmanager",
    "acceso-nostr-grafana",
  ]
}

variable "create_ecr_repositories" {
  description = "false si los repositorios ECR se crean en otro entorno (son de la cuenta, no del entorno)."
  type        = bool
  default     = true
}

variable "ecr_keep_images" {
  description = "Imágenes que conserva la política de ciclo de vida de cada repositorio."
  type        = number
  default     = 30
}

# --- ALB → NodePort (patrón Sedecim: target group en el NodePort del edge)
variable "vpc_id" {
  description = "VPC del cluster kops (target group). Vacío = no se crea el cableado del ALB."
  type        = string
  default     = ""
}

variable "node_port" {
  description = "NodePort del Service edge (deploy/k8s/overlays/<env>). 31800 es de buzz-hermes."
  type        = number
  default     = 31810
}

variable "alb_listener_arn" {
  description = "Listener HTTPS del ALB (certificado *.ai.acce.so). Vacío = sin regla de listener."
  type        = string
  default     = ""
}

variable "alb_listener_priority" {
  description = "Prioridad de la regla: debe ganar a la regla comodín *.ai.acce.so de buzz-hermes."
  type        = number
  default     = 90
}

variable "public_hosts" {
  description = "Hosts públicos del entorno (primera etiqueta: nostr-<env>[-relay|-secure|-blobs|-mirror|-id|-policy|-signer])."
  type        = list(string)
  default     = []
}

variable "node_security_group_id" {
  description = "SG de los nodos kops donde abrir el NodePort. Vacío = no se crea la regla."
  type        = string
  default     = ""
}

variable "alb_security_group_id" {
  description = "SG origen (ALB/proxy) autorizado a llegar al NodePort."
  type        = string
  default     = ""
}

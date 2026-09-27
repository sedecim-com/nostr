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

# --- managed signer, enclave tier (FR005-05, docs/managed-enclave.md)
variable "enable_enclave_signer" {
  description = "Crea la llave KMS condicionada a la attestation del enclave Nitro (requiere enable_managed_signer y los PCR esperados)."
  type        = bool
  default     = false
}

variable "enclave_pcr0" {
  description = "PCR0 (hash de la imagen EIF, = kms:RecipientAttestation:ImageSha384), 96 hex. Salida de nitro-cli build-enclave."
  type        = string
  default     = ""

  validation {
    condition     = var.enclave_pcr0 == "" || can(regex("^[0-9a-fA-F]{96}$", var.enclave_pcr0))
    error_message = "enclave_pcr0: 96 caracteres hex (SHA-384)."
  }
}

variable "enclave_pcr1" {
  description = "PCR1 (kernel y bootstrap del enclave), 96 hex."
  type        = string
  default     = ""

  validation {
    condition     = var.enclave_pcr1 == "" || can(regex("^[0-9a-fA-F]{96}$", var.enclave_pcr1))
    error_message = "enclave_pcr1: 96 caracteres hex (SHA-384)."
  }
}

variable "enclave_pcr2" {
  description = "PCR2 (aplicación del enclave), 96 hex."
  type        = string
  default     = ""

  validation {
    condition     = var.enclave_pcr2 == "" || can(regex("^[0-9a-fA-F]{96}$", var.enclave_pcr2))
    error_message = "enclave_pcr2: 96 caracteres hex (SHA-384)."
  }
}

variable "enclave_pcr8" {
  description = "PCR8 (certificado con el que se firmó la EIF), 96 hex. Vacío = no se exige."
  type        = string
  default     = ""

  validation {
    condition     = var.enclave_pcr8 == "" || can(regex("^[0-9a-fA-F]{96}$", var.enclave_pcr8))
    error_message = "enclave_pcr8: 96 caracteres hex (SHA-384)."
  }
}

variable "enclave_principal_arns" {
  description = "Principales IAM del host padre que reenvían las llamadas KMS del enclave (rol de la instancia Nitro). El usuario IAM del signer se añade si create_iam_users = true."
  type        = list(string)
  default     = []
}

variable "enclave_key_admin_arns" {
  description = "Administradores de la llave del enclave (sin permisos de uso). Vacío = raíz de la cuenta."
  type        = list(string)
  default     = []
}

variable "enclave_host_ami_id" {
  description = "AMI (Amazon Linux 2023 con aws-nitro-enclaves-cli) del host padre. Vacío = no se crea el launch template."
  type        = string
  default     = ""
}

variable "enclave_host_instance_type" {
  description = "Tipo de instancia con soporte de Nitro Enclaves (>= 4 vCPU: el enclave reserva CPUs completas)."
  type        = string
  default     = "m6i.xlarge"
}

variable "enclave_host_instance_profile" {
  description = "Instance profile del host padre (su rol va en enclave_principal_arns)."
  type        = string
  default     = ""
}

variable "enclave_host_security_group_ids" {
  description = "SGs del host padre."
  type        = list(string)
  default     = []
}

# --- Postgres gestionado (NFR001-03, docs/runbooks/rds-postgres.md)
variable "enable_rds" {
  description = "Crea RDS PostgreSQL Multi-AZ con backups automáticos y PITR (requiere vpc_id, rds_subnet_ids y rds_allowed_security_group_ids)."
  type        = bool
  default     = false
}

variable "rds_subnet_ids" {
  description = "Subredes privadas de la VPC del cluster, al menos dos AZ."
  type        = list(string)
  default     = []
}

variable "rds_allowed_security_group_ids" {
  description = "SGs autorizados a llegar al puerto 5432 (nodos del cluster kops)."
  type        = list(string)
  default     = []
}

variable "rds_engine_version" {
  description = "Versión de PostgreSQL (mayor; las menores se aplican en la ventana de mantenimiento)."
  type        = string
  default     = "17"
}

variable "rds_instance_class" {
  description = "Clase de instancia (Multi-AZ duplica el coste: primaria + standby)."
  type        = string
  default     = "db.t4g.medium"
}

variable "rds_allocated_storage" {
  description = "GiB iniciales (gp3)."
  type        = number
  default     = 50
}

variable "rds_max_allocated_storage" {
  description = "Tope de autoescalado del almacenamiento (GiB)."
  type        = number
  default     = 200
}

variable "rds_master_username" {
  description = "Usuario maestro (solo administración; la contraseña la genera y guarda RDS en Secrets Manager)."
  type        = string
  default     = "acceso_admin"
}

variable "rds_backup_retention_days" {
  description = "Días de backups automáticos y ventana de PITR (docs/rpo-rto.md)."
  type        = number
  default     = 14

  validation {
    condition     = var.rds_backup_retention_days >= 7 && var.rds_backup_retention_days <= 35
    error_message = "rds_backup_retention_days: entre 7 y 35 (máximo de RDS)."
  }
}

variable "rds_backup_window" {
  description = "Ventana diaria del snapshot automático (UTC)."
  type        = string
  default     = "07:00-08:00"
}

variable "rds_maintenance_window" {
  description = "Ventana semanal de mantenimiento (UTC), sin solaparse con la de backup."
  type        = string
  default     = "sun:08:30-sun:09:30"
}

variable "rds_deletion_protection" {
  description = "Protección contra borrado (desactivarla es un cambio explícito antes de destruir)."
  type        = bool
  default     = true
}

variable "rds_performance_insights" {
  description = "Activa Performance Insights (7 días gratis), cifrado con la llave de RDS."
  type        = bool
  default     = false
}

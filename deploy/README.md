# Despliegue del SaaS: Kubernetes, Terraform y monitorización

Infraestructura como código de Acceso Nostr (NFR001-01) y monitorización del SLO (NFR001-02).
Sigue las convenciones de Sedecim y de `buzz-hermes-stack/k8s`: cluster kops `sedecim-stage.k8s.local`
(AWS `us-east-1`), imágenes solo desde ECR `212568716371.dkr.ecr.us-east-1.amazonaws.com`, secretos en
Secrets Manager `k8s/<env>/...`, y entrada por un NodePort registrado en un target group del ALB.

> **Estado:** manifiestos, módulo Terraform y reglas de SLO validados en CI (job `deploy-config`:
> `kubectl kustomize`, `shellcheck`, `promtool`, `terraform fmt`/`validate` y los feature gates de producción). **El despliegue en staging
> está pendiente:** requiere credenciales de AWS, el `terraform apply` en el repositorio `infrastructure`
> y la luz verde para empujar a ECR y aplicar en el cluster.

## Contenido

| Ruta | Qué es |
|---|---|
| `k8s/base/` | Todos los servicios de `docker-compose.yml`: relay Buzz, Postgres, Redis, SeaweedFS (+ Job de bucket), secure-relay, indexer, identity-service, policy-engine, blob-store, web y el proxy `edge` (NodePort). |
| `k8s/components/managed-signer/` | Firma custodial (solo SaaS, opt-in): vault `aws` = KMS + Secrets Manager (ADR 0009). |
| `k8s/components/continuity-vault/` | Continuity Vault (opt-in, [ADR 0011](../docs/adr/0011-continuity-vault.md)): sobres en su bucket del SeaweedFS del clúster con llaves propias (`VAULT_S3_*` en el secret), filas en la base de la plataforma, host `nostr-<env>-vault` en el edge. No arranca hasta que el overlay elige quién abre cuentas (`VAULT_NIP98`). |
| `k8s/components/institutional/` | Modo institucional (opt-in): `relay-allowlist`, allowlist de Buzz activado, secure-relay con admisión gRPC e indexer con políticas ([`docs/institutional.md`](../docs/institutional.md)). |
| `k8s/components/notification-gateway/` | Push opaco (opt-in, ADR 0010). Con los relays de referencia no hay disparador seguro, así que no va en producción (OPS-20). |
| `k8s/components/rds-postgres/` | Postgres gestionado (NFR001-03): quita el StatefulSet y apunta `DATABASE_URL` a RDS con TLS verificado ([runbook](../docs/runbooks/rds-postgres.md)). |
| `k8s/overlays/stage/` | Stage: imágenes de ECR, hosts `*.ai.acce.so`, NodePort `31810`, monitorización y managed-signer. |
| `k8s/scripts/` | `deploy.sh`, `update-stage.sh`, `teardown-stage.sh` y auxiliares (`generate-secret.sh`, `mirror-ecr-deps.sh`, `build-push.sh`). |
| `k8s/values.env` | Valores de stage (ECR, contexto esperado, NodePort, host, IDs de Secrets Manager). |
| `terraform/modules/acceso-nostr/` | Recursos AWS del proyecto para un entorno. |
| `terraform/examples/stage/` | Cómo lo consume el repositorio `infrastructure`. |
| `production-gates.json` | OPS-20: qué funciones (custodia gestionada, enclave, push) pueden aparecer en la configuración de producción y con qué evidencia. Lo comprueba `node scripts/release-gate.mjs config` en `deploy-config` y en el release. Todo overlay o ejemplo que no sea stage cuenta como producción ([checklist de release](../docs/release-checklist.md#funciones-con-gate-en-producción-ops-20)). |
| `monitoring/` | Prometheus + blackbox exporter + Alertmanager + Grafana, reglas y alertas del SLO ([`docs/slo.md`](../docs/slo.md)). |

## Decisiones

- **Mismos servicios, puertos y healthchecks que compose.** Las probes de Kubernetes usan los mismos
  endpoints que los `healthcheck` de compose y que `scripts/wait-stack.sh` (`/_readiness` de Buzz, `/health`
  de los servicios, NIP-11 del secure relay, `/flags.json` del web).
- **Buzz fijado por digest** desde `infra/buzz/PIN` (`images` de `k8s/base/kustomization.yaml`).
  `scripts/buzz-upstream.sh apply` reescribe también ese digest y `tests/scripts/deploy-manifests.test.ts`
  comprueba que PIN, compose y kustomize coinciden. El espejo a ECR copia el manifiesto tal cual
  (`docker buildx imagetools create`), así que el digest sigue siendo válido en ECR.
- **Postgres gestionado en stage (NFR001-03):** RDS PostgreSQL 17 Multi-AZ con backups automáticos
  (14 días), PITR, protección contra borrado, cifrado KMS, TLS obligatorio y acceso solo desde los nodos
  (`enable_rds`). El overlay incluye `components/rds-postgres`. `POSTGRES_HOST` se rellena con la salida
  `rds_endpoint` tras el apply; `deploy.sh` se niega si está vacío. La base sigue trayendo el StatefulSet
  para quien despliegue sin RDS. Alta, migración, failover y PITR: [`docs/runbooks/rds-postgres.md`](../docs/runbooks/rds-postgres.md).
- **Redis y SeaweedFS dentro del cluster en stage** (StatefulSets con volúmenes EBS), igual que prueba CI con
  compose. Redis no es sistema de registro (cachés y pub/sub), ver [`docs/rpo-rto.md`](../docs/rpo-rto.md).
- **Una sola imagen de servicios** (`acceso-nostr-service`, target `service` del `Dockerfile`): cada
  Deployment fija `SERVICE`, que el `CMD` lee en tiempo de ejecución. El web es `acceso-nostr-web`
  (`flags.json` ya va dentro de la imagen; `config.json` sale de un ConfigMap).
- **Seguridad de los pods:** no root (`runAsNonRoot`, UID explícito), sin escalada de privilegios, sin
  capacidades, `seccompProfile: RuntimeDefault`, sin token de ServiceAccount y raíz de solo lectura con
  `emptyDir` en `/tmp` donde la imagen lo permite. Excepción: el relay Buzz escribe repos git y deja la raíz
  escribible, como el chart upstream. El namespace aplica Pod Security `baseline` y avisa contra `restricted`.
- **Secretos:** nunca en los manifiestos. `generate-secret.sh` construye el Secret `acceso-nostr-secrets`
  desde Secrets Manager (`k8s/stage/acceso-nostr`, JSON clave/valor) y lo aplica aparte. La primera vez,
  `--bootstrap` genera los valores con `scripts/init-env.sh` (el mismo generador que el `.env` self-hosted)
  y los guarda con `put-secret-value`. Terraform solo crea el contenedor del secreto: los valores no pasan
  por el estado de Terraform.
- **Managed signer sin IRSA:** kops no tiene roles por pod, así que (como `pod_service_user` en
  `infrastructure`) el módulo crea un usuario IAM dedicado con la política mínima de ADR 0009
  (`kms:GenerateDataKey`/`kms:Decrypt` sobre su llave, `secretsmanager:*Secret*` sobre el prefijo
  `acceso-nostr/<env>/managed-keys/`) y guarda sus llaves en `<usuario>_credentials`, de donde
  `generate-secret.sh` las copia al Secret. Con roles por pod: `create_iam_users = false` y
  `managed_signer_role_name`.
- **Entrada:** un Deployment `edge` (nginx) en un NodePort (`31810`; el `31800` es de buzz-hermes).
  Cada servicio conserva su host (como el `Caddyfile` de compose), todos bajo `*.ai.acce.so` para que los
  cubra el certificado comodín: `nostr-stage` (web), `nostr-stage-relay`, `-secure`, `-blobs`, `-mirror`,
  `-id`, `-policy` y `-signer`. El TLS termina en el ALB. El ALB hace health check a `/_edge_health`.
  El edge toma la IP del cliente de `X-Forwarded-For` (solo confía en saltos privados, `real_ip_recursive`),
  aplica `limit_req`/`limit_conn` por IP (web 20 r/s, ráfaga 100; APIs 10 r/s, ráfaga 40; blobs 5 r/s;
  handshakes de relay 5 r/s; conexiones 16–64 según host) con 429 y `Retry-After`, añade HSTS (solo si
  `X-Forwarded-Proto: https`), `X-Content-Type-Options` y `X-Frame-Options`, y reenvía a los servicios la IP
  ya resuelta (por eso `RATE_LIMIT_TRUST_PROXY_HOPS=1` en `acceso-nostr-config`). Los límites son **por pod
  del edge** (2 réplicas: el límite efectivo es el doble). Detalle en
  [docs/architecture.md](../docs/architecture.md#apis-anti-replay-nip-98-y-límites-de-tasa).
- **No incluido en stage:** Tor (perfil soberano/self-hosted, no aplica al SaaS).

## Terraform: consumo desde `infrastructure`

El módulo no configura provider ni backend: se instancia desde `infrastructure/terraform/main.tf` (provider
`us-east-1`, estado en `promessa-infrastructure-state`), fijado a un commit revisado:

```hcl
module "acceso_nostr_stage" {
  source = "git::https://github.com/sedecim-com/nostr.git//deploy/terraform/modules/acceso-nostr?ref=<commit>"

  environment            = "stage"
  vpc_id                 = "vpc-7907b103"
  node_port              = 31810
  alb_listener_arn       = aws_lb_listener.<listener *.ai.acce.so>.arn
  alb_listener_priority  = 90 # antes que la regla comodín *.ai.acce.so de buzz-hermes
  node_security_group_id = "<SG de los nodos de sedecim-stage>"
  alb_security_group_id  = "sg-0e939eb598c1416fb" # proxy
  public_hosts           = ["nostr-stage.ai.acce.so", "nostr-stage-relay.ai.acce.so", /* ... */]
}
```

Ejemplo completo y validable: [`terraform/examples/stage/main.tf`](terraform/examples/stage/main.tf).

Crea:

| Recurso | Nombre (stage) | Uso |
|---|---|---|
| Secreto | `k8s/stage/acceso-nostr` | Secretos del stack (vacío; lo llena `generate-secret.sh --bootstrap`) |
| Llave KMS + alias | `alias/acceso-nostr-stage-managed-signer` | Envelope del managed-signer, rotación anual (ADR 0009) |
| Política + usuario IAM | `acceso-nostr-stage-managed-signer`, `acceso_nostr_stage_managed_signer` | Permisos mínimos del signer; llaves en `acceso_nostr_stage_managed_signer_credentials` |
| RDS PostgreSQL 17 Multi-AZ + KMS + SG + parameter group | `acceso-nostr-stage-postgres`, `alias/acceso-nostr-stage-rds` | NFR001-03: backups automáticos 14 días + PITR, TLS obligatorio, solo desde los nodos; contraseña maestra en Secrets Manager gestionada por RDS (`enable_rds`) |
| Llave KMS del enclave (opcional) | `alias/acceso-nostr-stage-enclave-signer` | FR005-05: data keys solo para un enclave Nitro con los PCR esperados ([`docs/managed-enclave.md`](../docs/managed-enclave.md)); `enable_enclave_signer = false` por defecto |
| Bucket S3 | `acceso-nostr-stage-backups-<cuenta>` | Backups: versionado, SSE-KMS, privado, expiración 35 días; usuario `acceso_nostr_stage_backups` sin permiso de borrado |
| ECR | `acceso-nostr-*` | Imágenes propias y espejos (scan on push, últimas 30) |
| Target group + regla + SG | `acceso-nostr-stage-edge` | ALB → NodePort 31810 (solo si se pasan `vpc_id`, `alb_listener_arn`, SGs) |

Después del apply: añadir el ARN del target group (`alb_target_group_arn`) a `externalLoadBalancers` del
InstanceGroup de kops, como en buzz-hermes.

Validación local (sin credenciales): `terraform fmt -check -recursive deploy/terraform` y
`terraform -chdir=deploy/terraform/examples/stage init -backend=false && terraform -chdir=deploy/terraform/examples/stage validate`.

## Operar stage

Orden previo: `terraform apply` (infrastructure) → certificado `*.ai.acce.so` en el listener (compartido con
buzz-hermes) → target group en el InstanceGroup de kops → rellenar `COGNITO_USER_POOL_ID` /
`COGNITO_CLIENT_ID` en `k8s/overlays/stage/kustomization.yaml` y `files/web-config.json` → deploy.

```bash
kops export kubecfg --name sedecim-stage.k8s.local --state <s3-state>

./deploy/k8s/scripts/deploy.sh --dry-run                    # plan (default: no sube ni aplica nada)
./deploy/k8s/scripts/deploy.sh --yes --bootstrap-secret     # primera vez: secreto + ECR + apply
./deploy/k8s/scripts/update-stage.sh --yes                  # actualizar (imágenes del commit actual)
./deploy/k8s/scripts/teardown-stage.sh --yes                # bajar el namespace (no toca ECR/TF/kops)
```

- Todos los scripts son **dry-run por defecto** y se niegan si el contexto de `kubectl` no contiene
  `sedecim-stage`.
- `deploy.sh` etiqueta las imágenes propias con el commit (`--tag` para otro) y se niega a construir con el
  árbol sucio.
- `update-stage.sh` no borra el namespace ni los PVCs; espeja imágenes de terceros solo con `--mirror`;
  reaplica el Job `seaweedfs-init` solo si falta o falló; reinicia los workloads para recoger el Secret.
- `teardown-stage.sh` borra el namespace **con sus PVCs** (datos): hacer backup antes.

Verificación manual tras el deploy: `https://nostr-stage.ai.acce.so/_edge_health`, NIP-11 en
`https://nostr-stage-relay.ai.acce.so`, y `npm run test:interop` con `BUZZ_RELAY_URL=wss://nostr-stage-relay.ai.acce.so`.
Grafana no se publica: `kubectl -n acceso-nostr port-forward svc/grafana 3000` (usuario `admin`, contraseña
`GRAFANA_ADMIN_PASSWORD` del secreto).

## Pendiente

- Primer despliegue real en stage y registro del resultado (credenciales AWS + aprobación).
- IDs del pool de Cognito de stage y política de enrutado de alertas (`monitoring/alertmanager/alertmanager.yml`).
- Sonda externa (fuera del cluster) contra los hosts públicos, además de las sondas internas.
- NFR001-03: `terraform apply` de RDS, migración de datos y primera prueba de failover en stage
  (`scripts/rds-failover-test.sh`, registro en el runbook).

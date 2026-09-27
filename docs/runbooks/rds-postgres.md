# Runbook: Postgres gestionado (RDS Multi-AZ) en SaaS

- **Tarea:** NFR001-03, **Parcial**. **Criterio:** "Failover probado; backups automáticos".
- **Estado:** RDS existe como código (`deploy/terraform/modules/acceso-nostr/rds.tf`) y el overlay de stage
  apunta a RDS (`deploy/k8s/components/rds-postgres`). **Aún no hay `terraform apply` ni failover
  ejecutado en staging:** hacen falta credenciales de AWS y aprobación. El criterio se cumple cuando se
  ejecute la [prueba de failover](#prueba-de-failover) y se registre el resultado al final de este runbook.

## Qué se aprovisiona

| Pieza | Valor | Por qué |
|---|---|---|
| Motor | RDS PostgreSQL 17 (`rds_engine_version`), Multi-AZ en modo instancia | Standby síncrono en otra AZ y failover automático (60-120 s típicos). Se prefiere a Aurora por simplicidad y coste para dos bases pequeñas (`buzz`, `sedecim`). Así se mantiene la misma versión mayor que compose (`postgres:17-alpine`) |
| Backups | Automáticos, `rds_backup_retention_days` = 14 (7-35), ventana `07:00-08:00` UTC, `delete_automated_backups = false`, snapshot final al destruir | PITR a cualquier segundo de la ventana (RPO de minutos) |
| Protección | `deletion_protection = true`, `skip_final_snapshot = false` | Destruir exige un cambio explícito |
| Cifrado | Almacenamiento, snapshots, secreto maestro y Performance Insights (si se activa) con la llave KMS `alias/acceso-nostr-<env>-rds` | |
| TLS | Parameter group `postgres17` con `rds.force_ssl = 1` y `ssl_min_protocol_version = TLSv1.2`, CA `rds-ca-rsa2048-g1` | Los clientes verifican el certificado (`sslmode=verify-full` con el bundle de `us-east-1`) |
| Red | Subnet group privado (≥ 2 AZ), SG con 5432 solo desde `rds_allowed_security_group_ids` (nodos kops), `publicly_accessible = false` | |
| Credenciales | Usuario maestro `acceso_admin` con contraseña generada y guardada por RDS en Secrets Manager (`manage_master_user_password`, rotación gestionada) | El maestro solo administra. Los servicios usan el rol `buzz` con `POSTGRES_PASSWORD` del secreto del stack, así la rotación del maestro no reinicia pods |
| Logs | `postgresql` y `upgrade` a CloudWatch. Consultas de más de 1 s (`log_min_duration_statement`) | Sin parámetros de las sentencias |

Salidas de Terraform: `rds_instance_id`, `rds_endpoint`, `rds_port`, `rds_master_user_secret_arn`,
`rds_security_group_id`.

## Cómo llega a los servicios

- La base (`deploy/k8s/base`) arma `DATABASE_URL` así:
  `postgres://$(POSTGRES_USER):$(POSTGRES_PASSWORD)@$(POSTGRES_HOST):5432/<db>$(POSTGRES_URL_QUERY)`.
  Por defecto usa `POSTGRES_HOST=postgres` (el StatefulSet del cluster) y query vacía.
- `components/rds-postgres` (incluido en stage) hace tres cosas:
  - Elimina el StatefulSet `postgres`, su Service y el ConfigMap de init.
  - Fija `POSTGRES_URL_QUERY=?sslmode=verify-full&sslrootcert=/etc/rds-ca/rds-ca-us-east-1.pem`.
  - Monta el bundle de CA de RDS de `us-east-1` en relay, indexer, identity-service y managed-signer. El
    bundle está versionado en `files/`, con origen
    `https://truststore.pki.rds.amazonaws.com/us-east-1/us-east-1-bundle.pem`.
- El overlay fija `POSTGRES_HOST` con el valor de `rds_endpoint`. `deploy.sh` y `update-stage.sh` se niegan
  a aplicar si está vacío. El DNS del endpoint sigue a la primaria tras un failover, así que no hace falta
  tocar nada.
- La contraseña sigue en `acceso-nostr-secrets` (`POSTGRES_PASSWORD`), generada desde Secrets Manager
  `k8s/<env>/acceso-nostr` por `generate-secret.sh`. Es el mismo mecanismo de siempre: kops no tiene
  External Secrets.

## Alta inicial (una vez por entorno)

1. `terraform apply` en `infrastructure` con `enable_rds = true`, `rds_subnet_ids` (subredes privadas de
   `vpc-7907b103` en dos AZ) y el SG de los nodos. Ver `deploy/terraform/examples/stage/main.tf`.
2. Crear el rol de aplicación y las bases con el usuario maestro. El SG solo admite los nodos, así que se
   hace desde un pod:

   ```bash
   SECRET_ARN=$(terraform output -json acceso_nostr_stage | jq -r .rds_master_user_secret_arn)
   HOST=$(terraform output -json acceso_nostr_stage | jq -r .rds_endpoint)
   MASTER_PW=$(aws secretsmanager get-secret-value --secret-id "$SECRET_ARN" --query SecretString --output text | jq -r .password)
   APP_PW=$(kubectl -n acceso-nostr get secret acceso-nostr-secrets -o jsonpath='{.data.POSTGRES_PASSWORD}' | base64 -d)
   kubectl -n acceso-nostr run rds-bootstrap --rm -i --restart=Never \
     --image=212568716371.dkr.ecr.us-east-1.amazonaws.com/acceso-nostr-postgres:17-alpine \
     --env=PGPASSWORD="$MASTER_PW" --env=APP_PW="$APP_PW" -- \
     sh -c 'psql "host='"$HOST"' user=acceso_admin dbname=postgres sslmode=require" -v ON_ERROR_STOP=1 -v app_pw="$APP_PW" <<SQL
   CREATE ROLE buzz LOGIN PASSWORD :'"'"'app_pw'"'"';
   GRANT buzz TO acceso_admin;
   CREATE DATABASE buzz OWNER buzz;
   CREATE DATABASE sedecim OWNER buzz;
   SQL'
   ```

   `GRANT buzz TO acceso_admin` hace falta en RDS para crear bases cuyo dueño sea otro rol. Hay que borrar
   las variables del shell al terminar.
3. Poner `POSTGRES_HOST=<rds_endpoint>` en `deploy/k8s/overlays/stage/kustomization.yaml`.

## Migrar desde el Postgres del cluster

Ventana corta de escritura cerrada: el relay, el mirror, identity y el signer se detienen durante el volcado.

```bash
NS=acceso-nostr
kubectl -n $NS scale deploy relay indexer identity-service managed-signer --replicas=0
for db in buzz sedecim; do
  kubectl -n $NS exec postgres-0 -- pg_dump -U buzz -Fc "$db" > "/secure/tmp/$db.dump"
done
# Restaurar desde un pod (mismo patrón que el alta), como el rol buzz:
#   pg_restore --no-owner --role=buzz -d "host=$HOST user=buzz dbname=<db> sslmode=require" /dump/<db>.dump
deploy/k8s/scripts/update-stage.sh --yes      # aplica el overlay con RDS; los pods arrancan contra RDS
```

- Verificar `/health` de cada servicio, NIP-11 del relay y `npm run test:interop` contra stage.
- `kubectl apply` no borra objetos: después de verificar, eliminar a mano `statefulset/postgres`,
  `service/postgres` y, pasados unos días, el PVC `data-postgres-0`. Antes, hacer un último `pg_dump` al
  bucket de backups.

## Prueba de failover

```bash
scripts/rds-failover-test.sh --db-instance-id acceso-nostr-stage-postgres \
  --health-url https://nostr-stage-id.ai.acce.so/health            # plan (dry-run, sin AWS)
scripts/rds-failover-test.sh --db-instance-id acceso-nostr-stage-postgres \
  --health-url https://nostr-stage-id.ai.acce.so/health --report failover.json --yes
```

El script hace lo siguiente:

1. Exige estado `available` y `MultiAZ = true`, y anota la AZ primaria.
2. Comprueba que la sonda está arriba.
3. Sondea cada segundo en segundo plano.
4. Ejecuta `aws rds reboot-db-instance --force-failover`.
5. Espera `db-instance-available` y tres sondeos seguidos arriba.
6. Comprueba que la primaria cambió de AZ.
7. Anexa los eventos de RDS y escribe un informe JSON.

Falla si la AZ no cambia o si la caída supera `--max-downtime` (120 s por defecto).

La sonda también puede ser `--psql`, que usa `DATABASE_URL` desde un pod, o `--probe-cmd`. El health de
identity-service toca la base en cada petición autenticada. Para medir solo la base, `--psql` es más fiel.

Durante el failover las conexiones abiertas se cortan. Los pools (`pg.Pool`, sqlx en Buzz) reconectan en
la siguiente consulta al resolver de nuevo el DNS del endpoint. Si algún servicio no se recupera solo, es
un bug a registrar.

`tests/scripts/rds-failover-test.test.ts` prueba el script en CI con un `aws` falso: plan, medición de la
caída y detección de una AZ que no cambia. No sustituye la prueba real.

## Backups y restauración a un punto en el tiempo (PITR)

- Estado: `aws rds describe-db-instances --db-instance-identifier acceso-nostr-stage-postgres --query 'DBInstances[0].[BackupRetentionPeriod,LatestRestorableTime]'`.
  `LatestRestorableTime` suele ir menos de 5 minutos por detrás.
- Restaurar a otro nombre y cambiar el host:

  ```bash
  aws rds restore-db-instance-to-point-in-time \
    --source-db-instance-identifier acceso-nostr-stage-postgres \
    --target-db-instance-identifier acceso-nostr-stage-postgres-pitr \
    --restore-time 2026-10-01T12:00:00Z \
    --db-subnet-group-name acceso-nostr-stage-postgres \
    --vpc-security-group-ids <rds_security_group_id> \
    --db-parameter-group-name acceso-nostr-stage-postgres17 \
    --multi-az --deletion-protection
  aws rds wait db-instance-available --db-instance-identifier acceso-nostr-stage-postgres-pitr
  ```

  Después: `POSTGRES_HOST=<endpoint nuevo>` en el overlay y `update-stage.sh --yes`. La instancia
  restaurada queda fuera del estado de Terraform. Para adoptarla, hay que importarla (`terraform import`) o
  renombrar las instancias (`modify-db-instance --new-db-instance-identifier`). La decisión se registra en
  el incidente.
- El `pg_dump` al bucket `acceso-nostr-<env>-backups-*` (`docs/runbooks/restore.md`) se mantiene como copia
  lógica independiente de RDS. Por ejemplo, para llevar datos a self-hosted.

## Registro de pruebas

| Fecha | Entorno | Quién | AZ antes → después | Caída medida | Resultado |
|---|---|---|---|---|---|
| — | stage | — | — | — | Pendiente: requiere `terraform apply` y credenciales de AWS |

#!/usr/bin/env bash
# RDS Multi-AZ failover drill (NFR001-03, docs/runbooks/rds-postgres.md). Forces a failover with
# `aws rds reboot-db-instance --force-failover` while probing the service, and reports the measured
# downtime and the AZ change.
#
#   scripts/rds-failover-test.sh --db-instance-id acceso-nostr-stage-postgres \
#     --health-url https://nostr-stage-id.ai.acce.so/health --yes
#
# Probe (one of): --health-url URL (curl, 2xx = up), --psql (psql "$DATABASE_URL" -c 'select 1') or
# --probe-cmd CMD (any command, exit 0 = up). Dry-run by default: prints the plan and makes no AWS call.
set -euo pipefail

DRY_RUN=1
DB_ID="${RDS_INSTANCE_ID:-}"
REGION="${AWS_REGION:-us-east-1}"
HEALTH_URL=""
USE_PSQL=0
PROBE_CMD=""
INTERVAL=1
TIMEOUT=900
MAX_DOWNTIME=120
RECOVERED_AFTER=3
REPORT=""

log() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 2; }

usage() {
  cat <<EOF
Uso: $0 --db-instance-id ID (--health-url URL | --psql | --probe-cmd CMD) [opciones]

  --db-instance-id ID   Instancia RDS Multi-AZ (terraform output rds_instance_id; env RDS_INSTANCE_ID)
  --health-url URL      Sondea URL con curl (2xx = arriba)
  --psql                Sondea con psql "\$DATABASE_URL" -c 'select 1'
  --probe-cmd CMD       Sondea con un comando arbitrario (exit 0 = arriba)
  --region R            Región (default ${REGION})
  --interval S          Segundos entre sondeos (default ${INTERVAL})
  --timeout S           Máximo total del drill (default ${TIMEOUT})
  --max-downtime S      Falla si la caída medida supera S segundos (default ${MAX_DOWNTIME})
  --report FILE         Escribe el resultado en JSON
  --yes, -y             Ejecuta el failover (sin esto: solo el plan)
  --dry-run             Solo el plan (default)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --db-instance-id) [[ $# -ge 2 ]] || die "$1 requiere valor"; DB_ID="$2"; shift 2 ;;
    --health-url) [[ $# -ge 2 ]] || die "$1 requiere valor"; HEALTH_URL="$2"; shift 2 ;;
    --psql) USE_PSQL=1; shift ;;
    --probe-cmd) [[ $# -ge 2 ]] || die "$1 requiere valor"; PROBE_CMD="$2"; shift 2 ;;
    --region) [[ $# -ge 2 ]] || die "$1 requiere valor"; REGION="$2"; shift 2 ;;
    --interval) [[ $# -ge 2 ]] || die "$1 requiere valor"; INTERVAL="$2"; shift 2 ;;
    --timeout) [[ $# -ge 2 ]] || die "$1 requiere valor"; TIMEOUT="$2"; shift 2 ;;
    --max-downtime) [[ $# -ge 2 ]] || die "$1 requiere valor"; MAX_DOWNTIME="$2"; shift 2 ;;
    --report) [[ $# -ge 2 ]] || die "$1 requiere valor"; REPORT="$2"; shift 2 ;;
    --yes|-y) DRY_RUN=0; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "arg desconocido: $1 (usa --help)" ;;
  esac
done

[[ -n "${DB_ID}" ]] || die "falta --db-instance-id"
probes=0
[[ -n "${HEALTH_URL}" ]] && probes=$((probes + 1))
[[ "${USE_PSQL}" -eq 1 ]] && probes=$((probes + 1))
[[ -n "${PROBE_CMD}" ]] && probes=$((probes + 1))
[[ "${probes}" -eq 1 ]] || die "elige exactamente una sonda: --health-url, --psql o --probe-cmd"
for n in INTERVAL TIMEOUT MAX_DOWNTIME; do
  [[ "${!n}" =~ ^[0-9]+$ && "${!n}" -gt 0 ]] || die "${n} debe ser un entero positivo"
done

if [[ -n "${HEALTH_URL}" ]]; then
  PROBE_DESC="curl ${HEALTH_URL}"
elif [[ "${USE_PSQL}" -eq 1 ]]; then
  PROBE_DESC="psql \$DATABASE_URL -c 'select 1'"
else
  PROBE_DESC="${PROBE_CMD}"
fi

probe() {
  if [[ -n "${HEALTH_URL}" ]]; then
    curl -fsS -o /dev/null --max-time 3 "${HEALTH_URL}" 2>/dev/null
  elif [[ "${USE_PSQL}" -eq 1 ]]; then
    PGCONNECT_TIMEOUT=3 psql "${DATABASE_URL}" -Atqc 'select 1' >/dev/null 2>&1
  else
    bash -c "${PROBE_CMD}" >/dev/null 2>&1
  fi
}

now_ms() {
  local t
  t="$(date +%s%3N)"
  [[ "${t}" =~ ^[0-9]+$ ]] || t=$(( $(date +%s) * 1000 ))
  printf '%s' "${t}"
}

if [[ "${DRY_RUN}" -eq 1 ]]; then
  cat <<EOF
=== plan: failover forzado de RDS (dry-run, sin llamadas a AWS) ===
  instancia:     ${DB_ID} (${REGION})
  sonda:         ${PROBE_DESC} cada ${INTERVAL}s
  1. aws rds describe-db-instances: exige estado available y MultiAZ = true; anota la AZ primaria
  2. sonda inicial: debe estar arriba
  3. sondeo continuo en segundo plano (marca de tiempo + arriba/abajo)
  4. aws rds reboot-db-instance --db-instance-identifier ${DB_ID} --force-failover
  5. aws rds wait db-instance-available; espera ${RECOVERED_AFTER} sondeos seguidos arriba (máx. ${TIMEOUT}s)
  6. aws rds describe-db-instances: la primaria debe haber cambiado de AZ
  7. aws rds describe-events del periodo; informe (caída medida, AZ antes/después)
  falla si: la AZ no cambia o la caída supera ${MAX_DOWNTIME}s
  real: $0 --db-instance-id ${DB_ID} ... --yes
EOF
  exit 0
fi

command -v aws >/dev/null || die "falta aws CLI"
[[ -z "${HEALTH_URL}" ]] || command -v curl >/dev/null || die "falta curl"
if [[ "${USE_PSQL}" -eq 1 ]]; then
  command -v psql >/dev/null || die "falta psql"
  [[ -n "${DATABASE_URL:-}" ]] || die "--psql requiere DATABASE_URL"
fi

describe() {
  aws rds describe-db-instances --region "${REGION}" --db-instance-identifier "${DB_ID}" \
    --query 'DBInstances[0].[DBInstanceStatus,MultiAZ,AvailabilityZone,SecondaryAvailabilityZone]' --output text
}

read -r STATUS MULTI_AZ AZ_BEFORE SECONDARY_BEFORE < <(describe)
log "${DB_ID}: estado ${STATUS}, MultiAZ ${MULTI_AZ}, primaria ${AZ_BEFORE}, standby ${SECONDARY_BEFORE}"
[[ "${STATUS}" == available ]] || die "la instancia no está available (${STATUS})"
[[ "${MULTI_AZ}" == True || "${MULTI_AZ}" == true ]] || die "la instancia no es Multi-AZ: no hay failover que probar"
probe || die "la sonda falla antes del failover: ${PROBE_DESC}"

TMP="$(mktemp -d)"
POLLER=""
cleanup() {
  touch "${TMP}/stop"
  [[ -z "${POLLER}" ]] || wait "${POLLER}" 2>/dev/null || true
  rm -rf "${TMP}"
}
trap cleanup EXIT

(
  while [[ ! -e "${TMP}/stop" ]]; do
    if probe; then echo "$(now_ms) up"; else echo "$(now_ms) down"; fi
    sleep "${INTERVAL}"
  done
) > "${TMP}/probe.log" &
POLLER=$!

START_MS="$(now_ms)"
START_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "failover forzado (${START_ISO})"
aws rds reboot-db-instance --region "${REGION}" --db-instance-identifier "${DB_ID}" --force-failover >/dev/null

DEADLINE=$(( START_MS + TIMEOUT * 1000 ))
if command -v timeout >/dev/null; then
  timeout "${TIMEOUT}" aws rds wait db-instance-available --region "${REGION}" --db-instance-identifier "${DB_ID}" || die "la instancia no volvió a available en ${TIMEOUT}s"
else
  aws rds wait db-instance-available --region "${REGION}" --db-instance-identifier "${DB_ID}"
fi
log "instancia available; esperando ${RECOVERED_AFTER} sondeos seguidos arriba"

recovered=0
while [[ "$(now_ms)" -lt "${DEADLINE}" ]]; do
  if [[ "$(tail -n "${RECOVERED_AFTER}" "${TMP}/probe.log" | grep -c ' up$' || true)" -eq "${RECOVERED_AFTER}" ]]; then
    recovered=1
    break
  fi
  sleep "${INTERVAL}"
done
END_MS="$(now_ms)"
touch "${TMP}/stop"
wait "${POLLER}" 2>/dev/null || true
POLLER=""

# Downtime: from the first failed probe to the first successful one after the last failure.
read -r FIRST_DOWN _ BACK_UP DOWN_PROBES < <(awk '
  $2 == "down" { if (!first) first = $1; last = $1; n++; back = 0; next }
  $2 == "up" && last && !back { back = $1 }
  END { printf "%s %s %s %d\n", first ? first : 0, last ? last : 0, back ? back : 0, n }' "${TMP}/probe.log")
if [[ "${FIRST_DOWN}" -eq 0 ]]; then
  DOWNTIME_MS=0
elif [[ "${BACK_UP}" -ne 0 ]]; then
  DOWNTIME_MS=$(( BACK_UP - FIRST_DOWN ))
else
  DOWNTIME_MS=$(( END_MS - FIRST_DOWN ))
fi

read -r STATUS_AFTER _ AZ_AFTER SECONDARY_AFTER < <(describe)
EVENTS="$(aws rds describe-events --region "${REGION}" --source-type db-instance --source-identifier "${DB_ID}" \
  --start-time "${START_ISO}" --query 'Events[].[Date,Message]' --output text 2>/dev/null || true)"

ok=1
reasons=()
[[ "${recovered}" -eq 1 ]] || { ok=0; reasons+=("la sonda no se recuperó en ${TIMEOUT}s"); }
[[ "${AZ_AFTER}" != "${AZ_BEFORE}" ]] || { ok=0; reasons+=("la primaria sigue en ${AZ_BEFORE}"); }
(( DOWNTIME_MS <= MAX_DOWNTIME * 1000 )) || { ok=0; reasons+=("caída de ${DOWNTIME_MS} ms > ${MAX_DOWNTIME}s"); }

cat <<EOF

=== resultado del failover (${DB_ID}) ===
  AZ primaria:    ${AZ_BEFORE} -> ${AZ_AFTER} (standby ahora ${SECONDARY_AFTER}, estado ${STATUS_AFTER})
  caída medida:   ${DOWNTIME_MS} ms (${DOWN_PROBES} sondeos fallidos, sonda: ${PROBE_DESC})
  drill total:    $(( END_MS - START_MS )) ms
  eventos RDS:
$(printf '%s\n' "${EVENTS:-  (sin eventos)}" | sed 's/^/    /')
EOF

if [[ -n "${REPORT}" ]]; then
  printf '{"db_instance_id":"%s","region":"%s","started_at":"%s","az_before":"%s","az_after":"%s","downtime_ms":%d,"failed_probes":%d,"recovered":%s,"passed":%s}\n' \
    "${DB_ID}" "${REGION}" "${START_ISO}" "${AZ_BEFORE}" "${AZ_AFTER}" "${DOWNTIME_MS}" "${DOWN_PROBES}" \
    "$([[ "${recovered}" -eq 1 ]] && echo true || echo false)" "$([[ "${ok}" -eq 1 ]] && echo true || echo false)" > "${REPORT}"
  log "informe: ${REPORT}"
fi

if [[ "${ok}" -eq 1 ]]; then
  log "failover OK"
else
  printf 'FALLO: %s\n' "${reasons[@]}" >&2
  exit 1
fi

# Integración con Block Buzz (early release, spec §6)

## Versión fijada
Ver `infra/buzz/PIN`: commit `02c6309f` (2026-09-25) e imagen `ghcr.io/block/buzz@sha256:da30acf8…`.
Buzz está bajo Apache-2.0 y se usa **sin modificar** (ADR 0002): no hay fork ni código de Buzz en este repositorio; `NOTICE` lo atribuye.

## Qué se reutiliza / qué no se delega
Reutilizamos el relay (NIP-01, NIP-29, NIP-42), su Postgres/Redis, búsqueda NIP-50, audit log y Blossom
(`/media`). **No** delegamos: custodia y abstracción de identidades, panel de soberanía, resiliencia
multi-relay y máquina de estados de entrega, Tor-only, mirror/vault cifrado, Marmot/MLS y políticas
institucionales. Todo eso vive en este repositorio y habla Nostr, no APIs internas de Buzz.

## Sin fork: pin y actualización
Usamos la imagen publicada por Block fijada por digest. Las divergencias se resuelven con adaptadores en el
SDK o servicios aparte, nunca modificando el relay. Para probar una imagen nueva: ejecutar el workflow `ci`
manualmente con el input `buzz_image`; los criterios de adopción y el rollback están en ADR 0003.

**Revisión mensual automática (BUZZ-05).** El workflow `buzz-upstream` se ejecuta el primer lunes de cada
mes, a mano con `workflow_dispatch` y al fusionar en `main` un cambio del workflow o del script. `scripts/buzz-upstream.sh check` resuelve de forma anónima el digest
de `ghcr.io/block/buzz:main` (token de GHCR + `HEAD` del manifiesto, que acepta índices OCI) y lo compara con
`BUZZ_IMAGE` de `infra/buzz/PIN`. Si cambió, reutiliza el job `stack` de `ci.yml` (`workflow_call` con
`buzz_image` y `stack_only`) contra la imagen candidata. Si el gate pasa, abre una PR en la rama
`buzz-upstream/<digest>` que actualiza el PIN, el digest por defecto de `docker-compose.yml`, los flags de
despliegue (`infra/web/flags.json`, que llevan el commit del relay) y el informe en
`docs/interop/`. Solo ese job tiene `contents: write` y `pull-requests: write`. Requisitos y límites:
- Hay que activar *Allow GitHub Actions to create and approve pull requests* en los ajustes del repositorio.
  Sin él, el workflow deja la rama lista y abre un issue con el enlace para crear la PR a mano.
- Las PR que se crean con `GITHUB_TOKEN` no lanzan `ci` por sí solas. El job lanza `ci` con `workflow_dispatch`
  sobre la rama (necesita `actions: write`), y sus checks aparecen en la PR.
- Si falla el gate o la comprobación de flags, no se abre PR, la ejecución queda en rojo y se abre un issue
  "Buzz upstream: el gate falla con <digest>". Si ese issue ya existe, se comenta en él. La revisión es manual
  (ADR 0003).
- El commit upstream se lee de la etiqueta OCI `org.opencontainers.image.revision`. Si falta, la PR lo indica
  y `BUZZ_COMMIT` se actualiza a mano.

## Gate F0 → F0.5 (`npm run test:interop`)
```bash
docker compose up -d relay
BUZZ_RELAY_URL=ws://localhost:3000 npm run test:interop   # genera interop-report.json
```
Verifica NIP-11, NIP-42 + NIP-29 desde un cliente de terceros, aceptación de gift wraps con distintas
estrategias de timestamp, que las suscripciones a kind 1059 sin `#p` propio no filtren nada, y Blossom.
**NIP-17 solo se habilita en producción si `interop-report.json` → `nip17.enableFlag = true`**, y con el
`timestampJitterSeconds` recomendado configurado explícitamente (nunca en silencio).

## Resultado del gate (2026-09-26, commit `02c6309`, build local debug)
Evidencia: [`docs/interop/buzz-02c6309-report.json`](interop/buzz-02c6309-report.json).

| Verificación | Resultado |
|---|---|
| NIP-11 | ✅ `supported_nips` incluye 1, 17, 29, 42, 50 (versión relay 0.2.1) |
| NIP-42 + NIP-29 desde cliente de terceros (crear grupo, unirse, publicar, leer desde otro cliente) | ✅ |
| NIP-17 con timestamps NIP-59 estándar (hasta 2 días atrás) | ❌ 0/3 — `invalid: event timestamp too far from server time` (issue #4192) |
| NIP-17 con jitter acotado ±5 min | ✅ 3/3 aceptados y recibidos/descifrados por el destinatario |
| Suscripción kind 1059 sin `#p` propio | ✅ 0 fugas |
| Blossom `/media` con blob cifrado en cliente | ❌ 415 `disallowed content type` (el media de Buzz solo acepta imágenes/vídeo detectados por magic bytes) |
| Blossom `/media` con imagen en claro | ✅ aceptada y descargada con verificación de hash (backend S3: SeaweedFS). Buzz exige autorización BUD-01 `get` también para leer; el cliente reintenta con ella ante un 401 |
| Cliente soberano E2E (canal + DM) contra Buzz | ✅ |
| Kinds Marmot 30443 / 445 / 10051 | ❌ `restricted: unknown event kind` → grupos MLS por `secure-relay` (`docs/marmot.md`) |

**Decisiones derivadas**
- `BUZZ_PINNED_ADAPTER` (`packages/messaging/src/adapters.ts`): jitter de gift wrap 300 s, explícito y
  declarado en la UI. El flag NIP-17 puede habilitarse para esta versión fijada con este adaptador.
- Adjuntos cifrados en cliente → `services/blob-store` (Blossom agnóstico al contenido); Buzz `/media`
  queda para imágenes en claro ya saneadas (Buzz además rechaza imágenes con metadatos).

## Hallazgos del sprint S1 (2026-09-26)
- **MinIO ya no publica imágenes descargables** (Docker Hub y quay.io responden `unauthorized`); el compose upstream de Buzz también depende de ellas. El stack usa **SeaweedFS 4.47** (Apache-2.0, fijado por digest) como S3 compatible.
- Buzz rechaza las REQ **anónimas** con `NOTICE auth-required`: el indexer se autentica con una identidad de servicio (`INDEXER_NSEC`).
- El fan-out **en vivo** de Buzz separa las suscripciones globales de las de canal: los mensajes NIP-29 solo llegan a suscripciones con `#h`. El indexer descubre los canales y mantiene una suscripción `#h`.
- Buzz es multi-tenant por cabecera `Host`: un host no mapeado a una comunidad recibe **404**, y el tag `relay` del AUTH NIP-42 debe ser `ws(s)://<Host>`. Un servicio que conecta por la red interna (`ws://relay:3000`) debe presentar la URL pública: el indexer usa `INDEXER_RELAY_PUBLIC_URL` (por defecto `RELAY_URL`) para la cabecera `Host` y el tag `relay` (opción `authRelayUrl` del pool).
- Buzz exige autorización BUD-01 también para **descargar** media.

## Hallazgos conocidos
- Issues upstream #4677 (desktop no muestra ciertos kind 1059) y #4192 (rechazo de gift wraps con
  timestamps aleatorizados). El test `messaging.test.ts` reproduce este último contra un relay que emula
  la validación de frescura; `WrapOptions.timestampJitterSeconds` es el adaptador explícito.
- Buzz exige que las REQ que pueden devolver kinds 1059/44100/44101 incluyan `#p` = pubkey autenticada.
  El SDK (`dmInboxFilter`) y el indexer (`DEFAULT_MIRROR_KINDS`) respetan esta regla; el mirror nunca pide
  gift wraps ajenos.
- Con `BUZZ_REQUIRE_AUTH_TOKEN=false` los clientes de terceros se autentican solo con NIP-42; activar
  `BUZZ_PUBKEY_ALLOWLIST=true` (o el allowlist del policy-engine) para relays privados.

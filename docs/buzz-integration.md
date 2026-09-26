# Integración con Block Buzz (early release, spec §6)

## Versión fijada
Ver `infra/buzz/PIN`: commit `02c6309f` (2026-09-25) e imagen `ghcr.io/block/buzz@sha256:da30acf8…`.
Buzz está bajo Apache-2.0: al distribuir el fork conservar `LICENSE`/`NOTICE` y marcar archivos modificados.

## Qué se reutiliza / qué no se delega
Reutilizamos el relay (NIP-01, NIP-29, NIP-42), su Postgres/Redis, búsqueda NIP-50, audit log y Blossom
(`/media`). **No** delegamos: custodia y abstracción de identidades, panel de soberanía, resiliencia
multi-relay y máquina de estados de entrega, Tor-only, mirror/vault cifrado, Marmot/MLS y políticas
institucionales. Todo eso vive en este repositorio y habla Nostr, no APIs internas de Buzz.

## Estrategia de fork
`scripts/buzz-fork.sh` mantiene `vendor/upstream` = commit fijado y `product/main` con parches mínimos.
Preferimos adaptadores en el SDK antes que modificar el relay. Cada actualización de upstream exige pasar
el gate de interoperabilidad.

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
| Blossom `/media` con imagen en claro | ⚠️ no verificable en este entorno (sin S3/MinIO → 500); repetir con `docker compose` |
| Cliente soberano E2E (canal + DM) contra Buzz | ✅ |

**Decisiones derivadas**
- `BUZZ_PINNED_ADAPTER` (`packages/messaging/src/adapters.ts`): jitter de gift wrap 300 s, explícito y
  declarado en la UI. El flag NIP-17 puede habilitarse para esta versión fijada con este adaptador.
- Adjuntos cifrados en cliente → `services/blob-store` (Blossom agnóstico al contenido); Buzz `/media`
  queda para imágenes en claro ya saneadas (Buzz además rechaza imágenes con metadatos).

## Hallazgos conocidos
- Issues upstream #4677 (desktop no muestra ciertos kind 1059) y #4192 (rechazo de gift wraps con
  timestamps aleatorizados). El test `messaging.test.ts` reproduce este último contra un relay que emula
  la validación de frescura; `WrapOptions.timestampJitterSeconds` es el adaptador explícito.
- Buzz exige que las REQ que pueden devolver kinds 1059/44100/44101 incluyan `#p` = pubkey autenticada.
  El SDK (`dmInboxFilter`) y el indexer (`DEFAULT_MIRROR_KINDS`) respetan esta regla; el mirror nunca pide
  gift wraps ajenos.
- Con `BUZZ_REQUIRE_AUTH_TOKEN=false` los clientes de terceros se autentican solo con NIP-42; activar
  `BUZZ_PUBKEY_ALLOWLIST=true` (o el allowlist del policy-engine) para relays privados.

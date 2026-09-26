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

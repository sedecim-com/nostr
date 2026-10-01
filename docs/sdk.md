# SDK de Acceso Nostr

Los paquetes de `packages/` forman el SDK que usan la web, la consola de administración, el CLI soberano y los
servicios. Esta página es la portada de la referencia generada con TypeDoc (OPS-14). Cómo se distribuye el SDK fuera
del monorepo lo decide el ADR 0013 (`docs/adr/0013-distribucion-del-sdk.md`, propuesto).

## Generar la referencia

```bash
npm ci
npm run docs:api          # TypeDoc de todos los paquetes en ./docs-api (HTML); falla con cualquier aviso
npm run docs:openapi      # OpenAPI 3.1 de cada servicio en docs/openapi (se versionan)
```

En CI, el job `docs` comprueba que `docs/openapi` está al día y que cada ruta tiene su resumen, genera la referencia
con TypeDoc y la sube como artefacto (`sdk-api-reference`).

## Paquetes

| Paquete | Qué hace |
|---|---|
| `@sedecim/nostr-core` | Primitivas Nostr: eventos NIP-01, firmas BIP-340, NIP-19, NIP-44, NIP-49 y NIP-98. |
| `@sedecim/signer` | Firmantes: local, remoto NIP-46, NIP-07 y managed. |
| `@sedecim/relay-pool` | Pool de relays por WebSocket con NIP-42, salud, reintentos y deduplicación. |
| `@sedecim/messaging` | Canales NIP-29, DMs NIP-17 (NIP-44/NIP-59), acuses y feature flags de interoperabilidad. |
| `@sedecim/delivery-engine` | Máquina de estados de entrega, outbox persistente y quorum entre relays. |
| `@sedecim/marmot-adapter` | Grupos Marmot/MLS (RFC 9420): interfaz `GroupCryptoProvider` y proveedor marmot-ts. |
| `@sedecim/blossom-client` | Cliente Blossom (BUD-01/02) con saneamiento de metadatos, cifrado en el cliente y verificación de hash. |
| `@sedecim/identity` | Personas, modos de custodia, vínculos explícitos y compartimentación. |
| `@sedecim/encrypted-store` | Almacenamiento local cifrado (XChaCha20-Poly1305) en memoria, archivo o IndexedDB. |
| `@sedecim/continuity` | Continuity Vault: sobres de archivo sellados en el cliente (ADR 0011). |
| `@sedecim/sync` | Reconstrucción de historial: NIP-77 (Negentropy) con REQ por ventanas de respaldo, export/import JSONL. Caché local cifrada de eventos con lectura sin conexión, cursores por relay y NIP-77 desde el conjunto local ([event-cache.md](event-cache.md)). |
| `@sedecim/tor-network` | Política de red: directa o solo Tor, fail-closed y DNS remoto (socks5h). |
| `@sedecim/profiles` | Perfiles de soberanía, validación de configuración, disclosures y etiquetas de madurez. |
| `@sedecim/policy-client` | Evaluador RBAC/ABAC con confianza de dispositivo y cliente del policy-engine. |
| `@sedecim/rotation-worker` | Rotaciones MLS del modo institucional y propagación de revocaciones de dispositivo. |
| `@sedecim/qr` | Codificador QR sin dependencias ni red, con salida SVG. |
| `@sedecim/metrics` | Exportador Prometheus que respeta el perfil de telemetría. |
| `@sedecim/telemetry-policy` | Telemetría según el perfil y logger que redacta secretos. |
| `@sedecim/service-kit` | Base de los servicios HTTP: router JSON, NIP-98 y tokens, migraciones SQL, límites de tasa. Interno. |
| `@sedecim/test-relay` | Relay, Blossom y SOCKS en memoria para pruebas, con inyección de fallos. Solo para tests. |

## Madurez

El SDK hereda la madurez de lo que implementa (PANEL-07, `packages/profiles/src/maturity.ts`): hoy no hay ninguna
auditoría externa, y los grupos Marmot se basan en marmot-ts, que está en alpha. Una API documentada aquí puede
cambiar entre versiones 0.x.

## APIs de los servicios

La referencia de las APIs HTTP de los servicios está en `docs/openapi` (un OpenAPI 3.1 por servicio, con su índice en
`docs/openapi/README.md`).

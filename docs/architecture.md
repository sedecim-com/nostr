# Arquitectura (v0.1)

Nostr es el contrato de interoperabilidad. Los clientes propios y Buzz leen/escriben los mismos eventos
firmados; las bases de datos son índices derivados.

```
        CLIENTES                      SERVICIOS PROPIOS (API solo para cuenta/políticas/custodia)
  web-saas · sovereign-client ─┐      identity-service (NIP-98) · policy-engine · managed-signer
                               │      notification-gateway (push opaco, opt-in, ADR 0010)
  Buzz Desktop/Mobile          │                     │
                               ▼                     │
                     SDK (packages/*) ───────────────┘
   nostr-core · signer · relay-pool · delivery-engine · encrypted-store · identity
   messaging · blossom-client · tor-network · telemetry-policy · profiles · sync
                               │ WebSocket (NIP-01/29/42) — directo o vía Tor (socks5h)
             ┌─────────────────┼──────────────────┐
         Buzz relay       relay secundario     relay .onion
             └─────────────────┼──────────────────┘
                               ▼
                    indexer / mirror (ciphertext-first) ──► Postgres
                    Blossom: /media en Buzz (imágenes en claro) · blob-store (adjuntos cifrados)
```

## Paquetes (spec §17.1)
| Paquete | Responsabilidad |
|---|---|
| `nostr-core` | Eventos NIP-01, BIP-340, NIP-19, NIP-44 v2, NIP-49, NIP-98, filtros, head selection, interfaz `Signer` |
| `relay-pool` | WebSocket multi-relay, NIP-42, reconexión con backoff, dedupe, salud por relay |
| `signer` | `LocalSigner`, `Nip46Signer`/`Nip46Bunker`, `Nip07Signer`, `ManagedSignerClient` |
| `delivery-engine` | Máquina de estados DRAFT→…→READ, outbox persistente, quorum, reintentos idempotentes, reconciliación |
| `encrypted-store` | Store local cifrado (XChaCha20-Poly1305, nombres HMAC), backends memoria/archivo atómico/IndexedDB; `Vault` con contraseña o llave del dispositivo (ADR 0007) |
| `identity` | Personas, compartimentos, vínculos con consentimiento, backup/restore NIP-49 |
| `messaging` | NIP-29, NIP-17/NIP-59, receipts (provisionales), feature flags, propiedades por tipo de conversación |
| `marmot-adapter` | `GroupCryptoProvider`/`GroupSession`, proveedor marmot-ts (MLS), almacenamiento MLS cifrado, autoprueba de secreto post-expulsión, conformidad |
| `blossom-client` | Saneamiento EXIF, cifrado AES-GCM compatible con kind 15, BUD-01/02, verificación de hash |
| `tor-network` | `NetworkGuard`: direct / tor-only, onion-only, allowlist, aislamiento de circuitos, fail closed |
| `telemetry-policy` | Redacción de secretos, niveles standard/minimal/none |
| `profiles` | Configuración del panel, presets (Apéndice B), validación, disclosures y matriz de notificaciones push (ADR 0010) |
| `policy-client` | Evaluador RBAC/ABAC + device trust |
| `sync` | Reconstrucción de historial: NIP-77 (Negentropy) con detección NIP-11/sonda y fallback automático a REQ por ventanas; `rebuildHistory` (canales, DMs, evidencia para el outbox); export/import JSONL |
| `service-kit` | HTTP mínimo con NIP-98/bearer y migraciones SQL |
| `test-relay` | Relay/Blossom/SOCKS en memoria para E2E con inyección de fallos |

## Decisiones (ADR resumidas; ver §25.1)
1. **Biblioteca base TS**: `@noble/*` + `@scure/base` directamente (auditadas, sin dependencias); `nostr-tools`
   solo como oráculo de interoperabilidad en tests. Rust/Flutter: rust-nostr + MDK y `flutter_rust_bridge` (ADR 0004), diferido hasta que haya app nativa.
2. **Storage local**: XChaCha20-Poly1305 con clave scrypt; nombres de entrada HMAC; escritura atómica.
3. **Receipts**: rumor gift-wrapped kind `16914`; lectura opt-in (ADR 0005).
4. **Marmot**: marmot-ts 0.5.1 + ts-mls rc.16 detrás de `GroupCryptoProvider`; tráfico por el relay secundario porque Buzz rechaza los kinds (ADR 0006).
5. **Licencia/nombre**: Apache-2.0 con scope `@sedecim` (ADR 0001); Buzz upstream sin fork (ADR 0002). Marca comercial pendiente.
6. **Notificaciones móviles**, **región cloud/legal para managed**: abiertas. Threat models por perfil en `docs/threat-models/`.

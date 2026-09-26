# Arquitectura (v0.1)

Nostr es el contrato de interoperabilidad. Los clientes propios y Buzz leen/escriben los mismos eventos
firmados; las bases de datos son índices derivados.

```
        CLIENTES                      SERVICIOS PROPIOS (API solo para cuenta/políticas/custodia)
  web-saas · sovereign-client ─┐      identity-service (NIP-98) · policy-engine · managed-signer
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
| `encrypted-store` | Store local cifrado (XChaCha20-Poly1305, nombres HMAC), backends memoria/archivo atómico/localStorage |
| `identity` | Personas, compartimentos, vínculos con consentimiento, backup/restore NIP-49 |
| `messaging` | NIP-29, NIP-17/NIP-59, receipts (provisionales), feature flags, propiedades por tipo de conversación |
| `marmot-adapter` | Interfaz `GroupCryptoProvider` + conformidad (fail closed sin proveedor) |
| `blossom-client` | Saneamiento EXIF, cifrado AES-GCM compatible con kind 15, BUD-01/02, verificación de hash |
| `tor-network` | `NetworkGuard`: direct / tor-only, onion-only, allowlist, aislamiento de circuitos, fail closed |
| `telemetry-policy` | Redacción de secretos, niveles standard/minimal/none |
| `profiles` | Configuración del panel, presets (Apéndice B), validación y disclosures |
| `policy-client` | Evaluador RBAC/ABAC + device trust |
| `sync` | Reconstrucción de historial por ventanas; NIP-77 enchufable |
| `service-kit` | HTTP mínimo con NIP-98/bearer y migraciones SQL |
| `test-relay` | Relay/Blossom/SOCKS en memoria para E2E con inyección de fallos |

## Decisiones (ADR resumidas; ver §25.1)
1. **Biblioteca base TS**: `@noble/*` + `@scure/base` directamente (auditadas, sin dependencias); `nostr-tools`
   solo como oráculo de interoperabilidad en tests. Rust/Flutter: pendiente (móvil vía Buzz Flutter).
2. **Storage local**: XChaCha20-Poly1305 con clave scrypt; nombres de entrada HMAC; escritura atómica.
3. **Receipts**: rumor gift-wrapped kind provisional `16914`; lectura opt-in. Decisión abierta.
4. **Marmot**: detrás de interfaz; ningún proveedor habilitado hasta fijar MDK y pasar conformidad.
5. **Licencia/nombre**: MIT (repositorio actual) con scope `@sedecim`; revisar compatibilidad con Apache-2.0 del fork.
6. **Notificaciones móviles**, **región cloud/legal para managed** y **threat models por perfil formales**: abiertas.

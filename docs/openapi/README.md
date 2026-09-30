# OpenAPI de los servicios

> Generado por `npx tsx scripts/openapi.ts` (OPS-14) desde las rutas que registra cada servicio; no se edita a mano. El job `docs` de CI falla si no está al día o si una ruta no tiene resumen.

| Servicio | Operaciones | Qué hace |
|---|---|---|
| [policy-engine](policy-engine.json) | 27 | Modo institucional (spec §16): personas, recursos, dispositivos, revocación, auditoría y retención. docs/institutional.md. |
| [managed-signer](managed-signer.json) | 20 | Custodia gestionada de llaves Nostr en KMS (FR005): firma y NIP-44 con sesiones de dispositivo revocables. docs/managed-enclave.md. |
| [identity-service](identity-service.json) | 18 | Cuentas SaaS: personas, vínculos entre personas, login de Acceso asociado y backups cifrados en el cliente. |
| [continuity-vault](continuity-vault.json) | 8 | Continuity Vault (ADR 0011): sobres de archivo sellados en cada dispositivo; el operador ve cuentas, tamaños y fechas, nunca contenido ni llaves. |
| [indexer](indexer.json) | 8 | Mirror e índice de los relays: lecturas, no leídos y búsqueda; en modo institucional, filtrados por la política (FR023-05). |
| [notification-gateway](notification-gateway.json) | 5 | Notificaciones push opacas (ADR 0010): observa los relays que puede observar sin leer DMs. |
| [blob-store](blob-store.json) | 5 | Servidor Blossom agnóstico al contenido para adjuntos cifrados en el cliente (BUD-01/02). |
| [rotation-worker](rotation-worker.json) | 1 | Worker de rotaciones (FR024-05): une grupos, saca a los revocados con commits MLS y lleva las revocaciones al managed-signer. |
| [relay-allowlist](relay-allowlist.json) | 1 | Sincronía de los relays con el policy-engine: allowlist NIP-42 (FR023-04) y permisos de publicar por recurso (FR023-10), también como membresía NIP-29 en Buzz. La admisión de eventos del relay seguro es gRPC (`nauthz.Authorization/EventAdmit`, puerto 50051), fuera de este documento. |

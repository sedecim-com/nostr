# ADR 0004 · Bibliotecas Nostr para Rust y Flutter

- **Estado:** Propuesto · **Tarea:** DEC-04 (P1) · **Fecha:** 2026-09-26
- **Aprobación:** pendiente

## Contexto
TypeScript ya está decidido (`docs/architecture.md`): `@noble/*` + `@scure/base` con `nostr-tools` como
oráculo en los tests. Hace falta decidir Rust (desktop Tauri, servicios nativos, MLS) y Flutter (móvil).
Estado del ecosistema a 2026-09-26:

| Pieza | Qué usa hoy | Fuente |
|---|---|---|
| Relay de Buzz (Rust) | crate `nostr` 0.44 (rust-nostr), features `nip44`, `nip98` | `Cargo.toml` de Buzz |
| Móvil de Buzz (Flutter) | paquete Dart `nostr` ^2.0 + `bip340` + `pointycastle` (criptografía en Dart puro) | `mobile/pubspec.yaml` |
| Marmot de referencia | MDK 0.10.4 (Rust, MIT) sobre un fork de rust-nostr | `marmot-protocol/mdk` |

## Opciones para Flutter
| Opción | A favor | En contra |
|---|---|---|
| A · Dart puro, como Buzz mobile | Integración inmediata con el cliente de Buzz | Otra implementación criptográfica que auditar (NIP-44/49/59 en Dart); no hay MLS/Marmot en Dart |
| B · `flutter_rust_bridge` sobre un núcleo Rust (rust-nostr + MDK) | Un solo núcleo criptográfico para desktop y móvil; MLS disponible; es lo que hacen los clientes Marmot de referencia | Complejidad de build (NDK, iOS); más tamaño |

## Decisión propuesta
- **Rust: `nostr` (rust-nostr), en la misma línea de versiones que el relay de Buzz, y MDK para Marmot.**
  Así desktop, servicios nativos y relay comparten tipos y comportamiento.
- **Flutter: opción B para todo lo criptográfico** (llaves, NIP-44/49/59, firmas, MLS) mediante
  `flutter_rust_bridge` sobre ese núcleo Rust. La capa Dart de Buzz mobile se conserva para UI y
  plumbing mientras dure el early release (BUZZ-06).
- **Criterio de aceptación de cualquier implementación:** pasar los mismos vectores que el SDK TS. Para
  ello se añaden a `packages/nostr-core/test` vectores exportables (interop con nostr-tools, NIP-44 v2,
  NIP-49) que las suites de Rust y Dart consumen.

## Consecuencias
- FR025-04 (interoperabilidad con MDK) pasa a ser también la validación del núcleo Rust.
- Hay que exportar vectores de prueba en JSON (tarea derivada, SEC-03).

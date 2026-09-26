# Política de seguridad

## Estado y advertencia (spec §2.3)

Esta es una versión **v0.1 de early release**. Ningún release de este proyecto debe comercializarse ni
recomendarse para periodistas, fuentes, personal de inteligencia u otros perfiles de alto riesgo hasta
superar una **revisión de seguridad independiente** y pruebas específicas de filtración de metadatos.

- Nostr aporta identidad criptográfica y transporte por relays, **no anonimato de red**.
- NIP-44 / NIP-17 **no** ofrecen forward secrecy ni post-compromise security. Para esas propiedades se
  requiere Marmot/MLS (proveedor marmot-ts, alpha upstream; ver `docs/marmot.md`).
- El modo *managed* es **custodial**: la plataforma tiene capacidad técnica de firmar como el usuario.

## Reportar una vulnerabilidad

Envía un reporte privado mediante *GitHub Security Advisories* del repositorio
(`Security` → `Report a vulnerability`). No abras issues públicos para vulnerabilidades.

Incluye: componente afectado, versión/commit, pasos de reproducción, impacto y, si es posible, un test
que falle. Acusamos recibo en 3 días hábiles y acordamos una fecha de divulgación coordinada
(por defecto 90 días, antes si hay explotación activa).

## Alcance prioritario

- Manejo de llaves (`packages/nostr-core`, `packages/signer`, `packages/identity`, `services/managed-signer`).
- Cifrado (`nip44`, `nip49`, `messaging/nip59`, `encrypted-store`, `blossom-client`).
- Fugas de red en modo Tor (`packages/tor-network`, `apps/sovereign-client`).
- Autenticación NIP-42 / NIP-98 y autorización (`relay-pool`, `service-kit`, `policy-engine`).
- Registros que pudieran contener secretos (`telemetry-policy`).

## Reglas que el código hace cumplir (y que un reporte puede demostrar rotas)

- Nunca registrar nsec, seed, tokens de recuperación, credenciales ni plaintext E2EE (§18.1).
- Tor-only nunca cae a clearnet (§14).
- El backend SaaS no descifra contenido en modos zero-knowledge (§15.3).
- Las tablas de aplicación nunca guardan secretos de llaves (§19.4).

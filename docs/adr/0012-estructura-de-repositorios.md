# ADR 0012 · Un monorepo en lugar de los seis repositorios del scope

- **Estado:** Propuesto · **Tarea:** DEC-15 (#273) · **Fecha:** 2026-09-29
- **Aprobación:** pendiente (responsable de producto)
- **Cambio de scope:** el scope (§21.1) sugería seis repositorios. Esta decisión los sustituye por uno solo,
  `sedecim-com/nostr`, con los mismos seis contenidos en directorios.

## Contexto
El scope sugiere repartir el proyecto así:

| Repositorio sugerido | Contenido según el scope | Dónde está hoy |
|---|---|---|
| `platform` | SaaS web, admin, servicios, infra | `apps/web-saas`, `apps/admin-console`, `services/*`, `infra/`, `deploy/` |
| `nostr-sdk` | SDK compartido y adaptadores | `packages/*` (workspaces de npm, todos `private`) |
| `sovereign` | Cliente soberano, Docker Compose y Tor | `apps/sovereign-client`, `docker-compose.yml`, `infra/tor` |
| `key-tool` | Generador offline independiente | `apps/key-generator`; el release publica `keygen.html` y `keygen.mjs` firmados |
| `buzz-fork` | Fork de Buzz e integración con upstream | No existe: Buzz upstream sin fork, fijado por digest (ADR 0002 y 0003) |
| `security-specs` | Threat models, vectores de test, guías de hardening | `docs/threat-models`, `docs/security`, `packages/nostr-core/test/vectors`, `docs/sovereign-tor.md` |

El proyecto nació como monorepo y así se ha construido hasta hoy. Casi todo cambio relevante tocó a la vez
varias de esas piezas:

- **Protocolo y clientes a la vez.** Que los acuses lleguen a los relays de DM del emisor (FR009-03) cambió en
  una sola PR `packages/messaging`, la web, el CLI soberano, sus E2E y un ADR.
- **Código y documentos de seguridad a la vez.** Ligar el payload sellado del mirror a su `event_id` (SEC-06)
  cambió el indexer y su migración junto con el threat model y la revisión de seguridad que lo describen.
- **Un solo gate de interoperabilidad.** El job `stack` levanta el stack completo con Buzz fijado y prueba en
  una ejecución el SDK, los servicios y la web (`tests/interop` y los E2E de navegador, ADR 0003).
- **Un solo release.** `release.yml` aplica la Definition of Done (`docs/release-checklist.md`) al commit del
  tag: CI, restore drill, auditorías, notas del modelo de confianza, imágenes reproducibles, SBOM, firma y
  verificación.
- **Trazabilidad desde una sola fuente.** El backlog son los issues de este repositorio, y
  `scripts/traceability.mjs` (OPS-18) comprueba que la evidencia citada exista en él.

## Decisión
**Un único repositorio.** Los seis contenidos del scope son directorios de `sedecim-com/nostr`, con una sola
versión por release (`vX.Y.Z`) para todo lo que se publica.

- **Una versión para todo.** Las notas de cada release (`docs/releases/<tag>.md`) describen los cambios en el
  modelo de confianza de todos los componentes. No hace falta una matriz de compatibilidad entre versiones del
  SDK, de los servicios y de los clientes.
- **Una sola cadena de suministro.** La protección de `main` (OPS-12), el entorno `release` con aprobadores
  (OPS-08), Dependabot y CodeQL (OPS-13) y el escaneo de secretos se configuran y se revisan una vez. Seis
  repositorios multiplicarían por seis esa superficie, para un equipo de unas cuatro personas.
- **Los threat models y los vectores viajan con el código que describen.** El threat model de un release es
  el de su tag, como pide el scope («threat model versionado por release», §20.3). Los vectores JSON de NIP-44,
  NIP-49 y NIP-59 (SEC-07) se generan y comprueban en el mismo CI que el código que los cumple.
- **Sin fork de Buzz.** Mientras rija ADR 0002, no hay nada que poner en `buzz-fork`: los cambios que
  necesitemos se proponen upstream y, mientras tanto, se resuelven con un adaptador o un servicio propio.
- **Lo independiente se consigue con artefactos, no con repositorios:**
  - el generador offline se distribuye como `keygen.html`, un archivo único firmado con su SBOM, que se
    verifica sin clonar nada (`docs/keygen-air-gapped.md`);
  - quien opera un despliegue soberano usa las imágenes firmadas y reproducibles del release y
    `docker-compose.yml`; compilar desde el código fuente es opcional (`docs/building.md`).
- **El SDK no se publica todavía.** Sus paquetes son `private`. Cómo se distribuirá (npm, versión y
  estabilidad de la API) lo decide OPS-14 en su propio ADR. Publicar paquetes desde `packages/*` no exige
  sacarlos del monorepo.

## Consecuencias
- **El CI crece con el proyecto.** Cada PR ejecuta los nueve jobs de `ci.yml`. Los workflows caros o
  específicos ya se filtran por rutas: `reproducible-images`, `restore-drill`, `buzz-upstream`,
  `marmot-upstream` y `backlog-sync`.
- **Los permisos son del repositorio entero.** Quien puede escribir en `main` puede cambiar el generador de
  llaves o los threat models. La mitigación es la protección de `main` con revisión obligatoria (OPS-12) y,
  cuando haya un segundo mantenedor, un `CODEOWNERS` para las rutas sensibles: `apps/key-generator`, la
  criptografía de `packages/nostr-core` y `packages/messaging`, `docs/threat-models` y
  `deploy/production-gates.json`.
- **Clonar el repositorio trae todo.** Un operador soberano no lo necesita (usa los artefactos del release).
  Quien sí quiera compilar solo una parte puede usar `git sparse-checkout`.

## Cuándo reabrir esta decisión
- Si alguien externo consume el SDK y necesita versiones propias con su semver, y un prefijo de tag en este
  repositorio (por ejemplo `sdk-v*`) no basta.
- Si un componente necesita otros mantenedores u otro control de acceso que el resto; por ejemplo, un generador
  de llaves auditado y congelado.
- Si se reabre ADR 0002 y hace falta un fork real de Buzz. Ese fork sí iría en su propio repositorio, un fork de
  `block/buzz` que siga su historial upstream.
- Si el CI de una PR típica pasa de 30 minutos pese a los filtros por rutas.

# Fork controlado de Buzz (BUZZ-01, BUZZ-03)

## Crear el fork (acción manual, requiere permisos de la organización)
1. Crear el repositorio `sedecim-com/buzz-fork` como fork de `block/buzz`. Visibilidad: la que decida
   producto; la licencia Apache-2.0 permite ambas.
2. En un clon del fork:
   ```bash
   git clone https://github.com/sedecim-com/buzz-fork && cd buzz-fork
   sh ../nostr/scripts/buzz-fork.sh          # crea vendor/upstream = commit de infra/buzz/PIN
   git push origin vendor/upstream
   git checkout -b product/main vendor/upstream && git push -u origin product/main
   ```
3. Protección de ramas: `vendor/upstream` solo avanza con el sync de ADR 0003 (sin commits propios);
   `product/main` exige PR con revisión y el check del gate.
4. Añadir `NOTICE` y `PATCHES.md` (`legal-checklist.md`).
5. En este repositorio, definir las variables de Actions `BUZZ_FORK_REPO=sedecim-com/buzz-fork` y
   `BUZZ_FORK_REF=product/main`. Desde entonces `buzz-image.yml` construye desde el fork.

## Imagen del relay
`.github/workflows/buzz-image.yml` construye el target `runtime`. Mientras no exista el fork, usa
upstream en el commit de `infra/buzz/PIN`. Características:
- `SOURCE_DATE_EPOCH` = fecha del commit fuente y `rewrite-timestamp` (reproducibilidad);
- SBOM y provenance (`mode=max`);
- publicación en `ghcr.io/<owner>/buzz-relay:sha-<7>` con el digest en el resumen del job;
- opción `verify_reproducible`: dos builds sin caché y comparación de digests.

Solo se actualiza `BUZZ_IMAGE` (PIN y compose) cuando `test:interop` pasa contra el digest nuevo.

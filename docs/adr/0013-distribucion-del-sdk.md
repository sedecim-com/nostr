# ADR 0013 · Cómo se distribuye el SDK

- **Estado:** Propuesto · **Tarea:** OPS-14 (#274) · **Fecha:** 2026-09-30
- **Aprobación:** pendiente (responsable de producto)

## Contexto
El SDK son los paquetes de `packages/` (spec §17). Hoy solo se usan dentro del monorepo (ADR 0012):

- Son workspaces de npm, todos `private`. Nadie fuera de este repositorio puede instalarlos.
- Se exportan como TypeScript fuente (`"main": "./src/index.ts"`). No hay paso de build a JavaScript ni `.d.ts`.
- La web, la consola, el CLI soberano y los servicios los importan por el workspace. Un cambio en un paquete llega a
  todos en la misma PR.
- `release.yml` firma y publica imágenes y artefactos (cosign keyless, provenance SLSA, SBOM) desde el entorno
  protegido `release`, pero no publica paquetes.

Una organización que quiera integrar Acceso Nostr en su propio cliente (el caso del scope) necesita instalar el SDK
con una versión y una procedencia verificables. La referencia de sus APIs ya se genera con TypeDoc (`docs/sdk.md`).

No todos los paquetes son SDK de cliente:

| Grupo | Paquetes |
|---|---|
| Cliente (cierre de dependencias propio) | `nostr-core`, `signer`, `relay-pool`, `messaging`, `delivery-engine`, `encrypted-store`, `marmot-adapter`, `blossom-client`, `identity`, `continuity`, `sync`, `tor-network`, `profiles`, `policy-client`, `qr` |
| Servidor | `service-kit` (depende de `pg`), `metrics`, `telemetry-policy`, `rotation-worker` |
| Pruebas | `test-relay` |

Ningún paquete de cliente depende de uno de servidor o de pruebas.

## Opciones

1. **No publicar.** Quien integre copia el código (vendoring) o depende del repositorio por git.
   - Contras: sin semver ni procedencia; los workspaces no funcionan como dependencia git. Las correcciones de
     seguridad no llegan solas.
2. **npm público, scope `@sedecim`, desde `release.yml`.** JavaScript ESM con `.d.ts`, publicado con provenance.
   - Pros: la instalación que espera cualquier proyecto de Node, React Native o un bundler. Permite atestar el origen
     de cada versión.
   - Contras: exige un paso de build y reservar el scope.
3. **GitHub Packages.**
   - Contras: instalar exige un token incluso para paquetes públicos, una fricción que no compensa si el SDK es
     público.
4. **JSR.**
   - Pros: publica TypeScript tal cual, con provenance.
   - Contras: fuera de Deno la adopción es menor. Se puede añadir después como espejo sin cambiar esta decisión.

## Decisión (propuesta)
Opción 2, con estas reglas:

- **Qué se publica.** Los 15 paquetes de cliente, en npm público bajo `@sedecim`. Los de servidor y `test-relay` siguen
  `private`.
- **Formato.** JavaScript ESM compilado (`tsc`) con `.d.ts` y *source maps*, Node ≥ 22. El monorepo sigue importando
  el fuente; el build solo se hace al publicar.
- **Versiones.**
  - Todos los paquetes publicados llevan la versión del tag del release (`vX.Y.Z`), en *lockstep*.
  - Mientras sea 0.x, un minor puede romper la API. Las notas del release (`docs/releases`) lo dicen.
  - Desde 1.0, semver estricto.
- **Procedencia.**
  - Publicación desde `release.yml`, en el mismo entorno protegido `release` que firma las imágenes.
  - npm Trusted Publishing (OIDC de GitHub Actions, sin `NPM_TOKEN` guardado) y `npm publish --provenance`.
  - El SBOM del release incluye los paquetes publicados.
- **Madurez.** Cada paquete publicado declara en su README la etiqueta de madurez de lo que implementa (PANEL-07). Un
  paquete no dice más de lo que dice el panel.
- **ts-mls.** Los `overrides` del `package.json` raíz no llegan a quien instala `@sedecim/marmot-adapter`. Con
  marmot-ts 0.5.1 recibiría ts-mls rc.10, la versión vulnerable (`docs/marmot.md`).
  - La autoprueba de secreto post-expulsión falla cerrada en ese caso: los grupos no se abren, en vez de abrirse
    inseguros.
  - Hasta que marmot-ts dependa de ts-mls ≥ rc.11, el README de `marmot-adapter` indica el `overrides` que debe añadir
    quien lo instale.
  - `scripts/mls-negative-control.sh` sigue probando en CI que la autoprueba detecta rc.10.

## Consecuencias
- Hace falta un paso de build por paquete (`tsc -p` con emisión) y un job que compruebe que el paquete empaquetado
  (`npm pack`) se importa desde un proyecto limpio.
- Hay que reservar el scope `@sedecim` en npm y configurar Trusted Publishing para el repositorio. El entorno `release`
  necesita un aprobador distinto de quien sube el tag (OPS-08) antes de la primera publicación.
- La API pública de los paquetes pasa a tener compatibilidad: un cambio que rompa la API de un paquete publicado se
  anota en las notas del release.
- La referencia TypeDoc se publica con cada release, con la misma versión que los paquetes.
- Nada de esto cambia el monorepo (ADR 0012): el SDK se sigue desarrollando junto a sus consumidores y se publica
  desde el mismo commit que el resto del release.

## Fuera de esta decisión
- Los SDKs de Rust y Flutter (ADR 0004, diferido).
- Publicar los servicios como paquetes: se distribuyen como imágenes (NFR010).

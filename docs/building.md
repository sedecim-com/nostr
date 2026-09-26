# Build desde source y verificación de releases (OPS-09, NFR010-02, OPS-08)

Esta guía explica cómo construir cada artefacto desde el código de un tag, cómo compararlo con lo
publicado y qué partes son reproducibles bit a bit (y cuáles no). Los releases los genera
[`.github/workflows/release.yml`](../.github/workflows/release.yml) al publicar un tag `v*`.

## Qué publica un release

| Artefacto | Dónde | Firma y provenance |
|---|---|---|
| `keygen.html`: generador air-gapped en un solo archivo (FR003-05) | assets del GitHub Release | `keygen.html.sigstore.json` (cosign keyless), attestation SLSA y SBOM |
| `keygen.mjs`: CLI del generador en un solo archivo (Node 22) | assets del GitHub Release | `keygen.mjs.sigstore.json`, attestation SLSA y SBOM |
| `sbom.cdx.json`: SBOM CycloneDX de las dependencias de producción | assets del GitHub Release | `sbom.cdx.json.sigstore.json`, attestation SLSA |
| `images.txt`: lista `imagen@sha256:…` de las imágenes del release | assets del GitHub Release | `images.txt.sigstore.json` |
| `SHA256SUMS`: checksums de los cuatro archivos anteriores | assets del GitHub Release | `SHA256SUMS.sigstore.json` |
| Imágenes `ghcr.io/sedecim-com/nostr-<servicio>:<tag>`: `indexer`, `identity-service`, `policy-engine`, `blob-store`, `managed-signer`, `notification-gateway`, `web`, `tor` | GHCR, fijadas por digest en `images.txt` | firma cosign en el registry, attestation SLSA (y SBOM salvo `tor`) en el registry y en GitHub |

Las firmas son *keyless* (Sigstore): no hay una llave del proyecto que custodiar. El certificado de
cada firma lo emite Fulcio para la identidad OIDC del workflow, que es exactamente
`https://github.com/sedecim-com/nostr/.github/workflows/release.yml@refs/tags/<tag>`, y queda
registrado en el log público de transparencia (Rekor). Las attestations de provenance (SLSA v1) las
genera `actions/attest-build-provenance` y se consultan con `gh attestation verify`.

El relay Buzz no forma parte del release: se usa la imagen upstream sin modificar, fijada por digest en
`infra/buzz/PIN` (ADR 0002/0003).

## Verificar un release

Requisitos: [GitHub CLI](https://cli.github.com/) (`gh`, autenticado con `gh auth login`) y
[cosign](https://docs.sigstore.dev/cosign/system_config/installation/) 2.4 o superior.

```bash
sh scripts/verify-release.sh v0.2.0            # descarga en release-v0.2.0/ y verifica todo
SKIP_IMAGES=1 sh scripts/verify-release.sh v0.2.0 descargas/   # solo los archivos, sin tocar GHCR
```

El script se detiene en el primer fallo con un mensaje `FALLO: …` y termina en `OK` si todo cuadra.
Hace, en este orden:

1. `gh release download <tag>`: descarga todos los assets.
2. `cosign verify-blob` de `SHA256SUMS` contra la identidad exacta del workflow en ese tag.
3. `sha256sum -c SHA256SUMS` (en macOS `shasum -a 256 -c`).
4. `cosign verify-blob` de cada archivo con su `.sigstore.json`, y `gh attestation verify` (provenance
   SLSA, workflow `release.yml` de este repositorio) de `keygen.html`, `keygen.mjs` y `sbom.cdx.json`.
5. Por cada línea de `images.txt`: `cosign verify imagen@digest` y `gh attestation verify oci://imagen@digest`.

Los mismos pasos a mano, para un archivo:

```bash
cosign verify-blob --bundle keygen.html.sigstore.json \
  --certificate-identity-regexp 'https://github.com/sedecim-com/nostr/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com keygen.html
gh attestation verify keygen.html --repo sedecim-com/nostr
gh attestation verify keygen.html --repo sedecim-com/nostr --predicate-type https://cyclonedx.org/bom   # SBOM
```

Y para una imagen (el digest sale de `images.txt`):

```bash
cosign verify ghcr.io/sedecim-com/nostr-indexer@sha256:<digest> \
  --certificate-identity https://github.com/sedecim-com/nostr/.github/workflows/release.yml@refs/tags/v0.2.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/sedecim-com/nostr-indexer@sha256:<digest> --repo sedecim-com/nostr
```

Despliega siempre por digest (`imagen@sha256:…`), no por tag: el tag de una imagen se puede mover, el
digest no. Para usar el generador en un equipo sin red, sigue [keygen-air-gapped.md](keygen-air-gapped.md).

## Construir desde source

Requisitos: git, Node 22 (`.nvmrc`) con npm, y Docker con Buildx para las imágenes.

```bash
git clone https://github.com/sedecim-com/nostr.git && cd nostr
git checkout v0.2.0
npm ci --no-audit --no-fund          # versiones exactas del package-lock.json
```

Ejecuta todos los comandos desde la raíz del repositorio (algunos bundles registran rutas relativas al
directorio de trabajo). En Windows desactiva la conversión de finales de línea (`git config core.autocrlf
false` antes de clonar): cambiar `\n` por `\r\n` en las fuentes cambia el resultado.

### Generador de llaves (HTML y CLI): reproducible bit a bit

```bash
node apps/key-generator/build-html.mjs   # apps/key-generator/dist/keygen.html (+ .sha256)
node apps/key-generator/build.mjs        # apps/key-generator/dist/keygen.mjs  (+ .sha256)
sha256sum apps/key-generator/dist/keygen.html apps/key-generator/dist/keygen.mjs
grep -E ' keygen\.(html|mjs)$' release-v0.2.0/SHA256SUMS    # deben coincidir
```

Son los mismos comandos que usan `ci.yml` y `release.yml`. La salida depende solo de las fuentes y de
la versión de esbuild fijada en el lockfile: no incluye marcas de tiempo ni rutas absolutas, y la CSP
del HTML fija el script y los estilos por SHA-256. Se comprobó construyendo dos veces sobre el mismo
checkout (el SHA-256 de `keygen.html` y el de `keygen.mjs` fueron idénticos en ambas) y en dos checkouts
del mismo commit en directorios distintos (mismo `keygen.html`). No se ha comprobado todavía entre
sistemas operativos distintos; si tu checksum no coincide con el del release,
revisa que el checkout esté en el tag exacto, sin cambios (`git status`), con `npm ci` y desde la raíz.

`keygen.mjs` conserva comentarios con la ruta relativa de cada módulo: construirlo desde otro directorio
o con los paquetes enlazados desde otra ubicación cambia esos comentarios y, por tanto, el checksum.
`keygen.html` está minificado y no contiene rutas.

### Web SaaS

```bash
npm run build:web                        # apps/web-saas/dist
```

El resultado fue idéntico en dos builds consecutivos del mismo checkout. En el release la web solo se
publica dentro de la imagen `nostr-web` (construida con la imagen oficial de Node indicada en el
`Dockerfile`); para compararla, extrae sus archivos y compáralos con tu build:

```bash
cid=$(docker create ghcr.io/sedecim-com/nostr-web@sha256:<digest>)
docker cp "$cid:/usr/share/nginx/html" web-publicada && docker rm "$cid"
diff -r apps/web-saas/dist web-publicada
```

### SBOM: reproducible salvo metadatos

```bash
npm run sbom                             # sbom.cdx.json (npm sbom, CycloneDX, sin dependencias de desarrollo)
jq -S 'del(.serialNumber, .metadata.timestamp)' sbom.cdx.json > local.json
jq -S 'del(.serialNumber, .metadata.timestamp)' release-v0.2.0/sbom.cdx.json > publicado.json
diff local.json publicado.json
```

`npm sbom` pone un `serialNumber` aleatorio y la fecha en `metadata.timestamp`, así que el archivo nunca
coincide bit a bit; sin esos dos campos, dos ejecuciones sobre el mismo checkout dieron el mismo
resultado. Puede variar con otra versión de npm.

### Imágenes de los servicios: no reproducibles bit a bit

```bash
docker compose build                                                     # todas, como el stack local
docker buildx build --target service --build-arg SERVICE=indexer -t nostr-indexer .   # una a una:
#   SERVICE = indexer | identity-service | policy-engine | blob-store | managed-signer | notification-gateway
docker buildx build --target web -t nostr-web .
docker buildx build -t nostr-tor infra/tor
```

`release.yml` construye exactamente esas combinaciones (contexto, `target`, `SERVICE`). El digest de una
imagen construida en local **no** coincidirá con el publicado: las imágenes base (`node:26-alpine`,
`nginx:1.31-alpine`, `alpine:3.20`) se referencian por tag y cambian con el tiempo, `apk add` instala la
versión vigente de Tor, y las capas llevan marcas de tiempo. Lo que sí se puede comprobar:

- **Origen**: la firma cosign y la provenance SLSA (sección anterior) prueban que la imagen la construyó
  `release.yml` desde el commit del tag; la provenance registra el commit exacto.
- **Contenido propio**: las imágenes de servicio ejecutan el TypeScript de las fuentes con `tsx`, sin
  compilar. Extrae el código y compáralo con el checkout del tag:

  ```bash
  cid=$(docker create ghcr.io/sedecim-com/nostr-indexer@sha256:<digest>)
  docker cp "$cid:/app" app-publicada && docker rm "$cid"
  for d in packages services apps; do diff -r --exclude node_modules --exclude dist "$d" "app-publicada/$d"; done
  cmp package-lock.json app-publicada/package-lock.json
  ```

## Publicar un release (mantenedores)

1. Asegúrate de que `main` está en verde (`ci`).
2. Crea y sube un tag anotado: `git tag -a v0.2.0 -m v0.2.0 && git push origin v0.2.0`.
3. `release.yml` construye sin permisos de escritura (job `build`: generador, E2E del HTML sin red y SBOM;
   job `images`: una imagen OCI por servicio, sin subirla).
4. Los jobs `publish-images` y `publish` esperan aprobación en el entorno `release`. Una persona distinta
   de quien subió el tag revisa el run y aprueba. Son dos aprobaciones: primero las imágenes (suben los
   bytes exactos del build, comprobando el digest, firman y atestan) y después los archivos (firma,
   attestations y GitHub Release con `images.txt`).
5. Verifica el resultado con `sh scripts/verify-release.sh v0.2.0`.

Para repetir un release que falló: *Actions → release → Run workflow*, elige el **tag** en «Use workflow
from» y escríbelo de nuevo en el campo `tag`. El workflow se niega a ejecutarse desde una rama, porque la
identidad de la firma sería otra y la verificación la rechazaría.

### Configuración del repositorio (una vez, OPS-08)

Separación de funciones: nadie puede publicar solo lo que él mismo ha etiquetado. Requiere estos ajustes,
que no se pueden versionar en el repositorio:

- **Settings → Environments → New environment `release`**:
  - *Required reviewers*: al menos una persona o equipo mantenedor (idealmente dos o más, para que
    siempre haya alguien distinto del autor).
  - *Prevent self-review*: activado (quien lanzó el run no puede aprobarlo).
  - *Allow administrators to bypass configured protection rules*: desactivado.
  - *Deployment branches and tags*: *Selected branches and tags* → añadir la regla de **tag** `v*`.
- **Settings → Rules → Rulesets → New tag ruleset** para `v*`: restringe crear, actualizar y borrar tags
  a los mantenedores (y bloquea el force-push de tags).
- **GHCR**: tras el primer release, en cada paquete `nostr-*` (*Package settings*) cambia la visibilidad a
  pública para que cualquiera pueda descargar y verificar las imágenes sin credenciales.

Los jobs de build solo tienen `contents: read`. Solo `publish-images` (`packages: write`, `id-token: write`,
`attestations: write`) y `publish` (`contents: write`, `id-token: write`, `attestations: write`) pueden
escribir, y ambos corren en el entorno protegido.

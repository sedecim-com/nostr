# Build desde source y verificación de releases (OPS-09, NFR010-02, NFR010-03, NFR010-04, OPS-08)

Esta guía explica cómo construir cada artefacto desde el código de un tag, cómo compararlo con lo
publicado y qué partes son reproducibles bit a bit (y cuáles no). Los releases los genera
[`.github/workflows/release.yml`](../.github/workflows/release.yml) al publicar un tag `v*`.

## Qué publica un release

| Artefacto | Dónde | Firma y provenance |
|---|---|---|
| `keygen.html`: generador air-gapped en un solo archivo (FR003-05) | assets del GitHub Release | `keygen.html.sigstore.json` (cosign keyless), attestation SLSA y SBOM |
| `keygen.mjs`: CLI del generador en un solo archivo (Node 22) | assets del GitHub Release | `keygen.mjs.sigstore.json`, attestation SLSA y SBOM |
| `sbom.cdx.json`: SBOM CycloneDX de las dependencias de producción | assets del GitHub Release | `sbom.cdx.json.sigstore.json`, attestation SLSA |
| `sbom-buzz.cdx.json`: SBOM de la imagen de Buzz fijada, hecho por syft desde la imagen (NFR010-04) | assets del GitHub Release | `sbom-buzz.cdx.json.sigstore.json`, attestation SLSA, y attestation SBOM del digest de Buzz |
| `buzz-image.txt`: la imagen de Buzz fijada (`infra/buzz/PIN`), `imagen@sha256:…` | assets del GitHub Release | `buzz-image.txt.sigstore.json` |
| `images.txt`: lista `imagen@sha256:…` de las imágenes del release | assets del GitHub Release | `images.txt.sigstore.json` |
| `SHA256SUMS`: checksums de los seis archivos anteriores | assets del GitHub Release | `SHA256SUMS.sigstore.json` |
| Imágenes `ghcr.io/sedecim-com/nostr-<servicio>:<tag>`: `indexer`, `identity-service`, `policy-engine`, `blob-store`, `managed-signer`, `notification-gateway`, `continuity-vault`, `web`, `tor` | GHCR, fijadas por digest en `images.txt` | firma cosign en el registry; attestation SLSA y el SBOM de la propia imagen (syft, NFR010-04), en el registry y en GitHub |

Las firmas son *keyless* (Sigstore): no hay una llave del proyecto que custodiar. El certificado de
cada firma lo emite Fulcio para la identidad OIDC del workflow, que es exactamente
`https://github.com/sedecim-com/nostr/.github/workflows/release.yml@refs/tags/<tag>`, y queda
registrado en el log público de transparencia (Rekor). Las attestations de provenance (SLSA v1) las
genera `actions/attest-build-provenance` y se consultan con `gh attestation verify`.

El relay Buzz no forma parte del release: se usa la imagen upstream sin modificar, fijada por digest en
`infra/buzz/PIN` (ADR 0002/0003). El release no la firma, pero sí publica y atesta su SBOM para ese digest.

### SBOM por imagen (NFR010-04)

Cada imagen lleva el SBOM de lo que contiene: `scripts/image-sbom.sh` lo genera con syft (versión y
checksum fijados en el script) a partir del archivo OCI que se publica, y `release.yml` lo atesta sobre el digest
de esa imagen. Antes, `scripts/image-sbom-check.mjs` comprueba que ningún paquete npm instalado en `/app` sea
solo de desarrollo en `package-lock.json`. La imagen de los servicios se instala con `npm ci --omit=dev` (etapa
`prod-deps` del `Dockerfile`), y `tsx`, que los ejecuta, es una dependencia. `reproducible-images.yml` hace lo
mismo en cada PR que toca las imágenes y guarda el SBOM como artefacto:

```bash
sh scripts/build-image.sh indexer image.tar
sh scripts/image-sbom.sh oci-archive:image.tar sbom-indexer.cdx.json
node scripts/image-sbom-check.mjs sbom-indexer.cdx.json      # falla si hay una devDependency en /app
gh attestation verify oci://ghcr.io/sedecim-com/nostr-indexer@sha256:<digest> --repo sedecim-com/nostr \
  --predicate-type https://cyclonedx.org/bom                # el SBOM atestado de una imagen publicada
```

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
   SLSA, workflow `release.yml` de este repositorio) de `keygen.html`, `keygen.mjs`, `sbom.cdx.json` y
   `sbom-buzz.cdx.json`.
5. Por cada línea de `images.txt`: `cosign verify imagen@digest` y `gh attestation verify oci://imagen@digest`,
   de la provenance y del SBOM (`--predicate-type https://cyclonedx.org/bom`).
6. El SBOM atestado de la imagen de Buzz de `buzz-image.txt`.

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
npm run build:admin                      # apps/admin-console/dist (en la imagen, bajo /admin/)
```

El resultado fue idéntico en dos builds consecutivos del mismo checkout. En el release la web solo se
publica dentro de la imagen `nostr-web` (construida con la imagen oficial de Node indicada en el
`Dockerfile`); para compararla, extrae sus archivos y compáralos con tu build:

```bash
cid=$(docker create ghcr.io/sedecim-com/nostr-web@sha256:<digest>)
docker cp "$cid:/usr/share/nginx/html" web-publicada && docker rm "$cid"
diff -r -x admin apps/web-saas/dist web-publicada
diff -r apps/admin-console/dist web-publicada/admin
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

### Imágenes de los servicios: reproducibles bit a bit (NFR010-03)

Dos builds del mismo commit producen el mismo digest. Estado: se da por comprobado cuando
`reproducible-images.yml` pase en GitHub para las ocho imágenes (sin Docker local no se pudo probar
antes de añadirlo). Requisitos: Docker con Buildx (driver
`docker-container`, que el script crea), git, jq y `gh` para descargar `images.txt`.

```bash
sh scripts/verify-release.sh v0.2.0                 # primero: images.txt firmado por el release
sh scripts/rebuild-image.sh v0.2.0 indexer release-v0.2.0/images.txt
#   servicio = indexer | identity-service | policy-engine | blob-store | managed-signer |
#              notification-gateway | continuity-vault | web | tor
```

`rebuild-image.sh` clona el tag en un directorio temporal (con `umask 022`), construye la imagen con
`scripts/build-image.sh` en un builder nuevo y compara el digest con el de `images.txt`. Termina en `OK` o
en `FALLO` con los comandos para ver la diferencia (`skopeo copy` de la imagen publicada a un archivo OCI y
`scripts/image-diff.sh`, que muestra el config y, por cada capa distinta, los archivos que cambian; para un
análisis más fino, [diffoci](https://github.com/reproducible-containers/diffoci)). Sin tercer argumento
descarga `images.txt` con `gh`.

`scripts/build-image.sh <servicio> <salida.tar>` es la única forma de construir una imagen de release:
lo usan el job `images` de `release.yml`, el workflow
[`reproducible-images.yml`](../.github/workflows/reproducible-images.yml) y `rebuild-image.sh`. Qué lo hace
reproducible:

- **Entradas fijadas**: imágenes base por digest (`node`, `nginx` y `alpine` en los `Dockerfile`, con el tag
  al lado), frontend del Dockerfile (`# syntax=…@sha256:…`) y BuildKit por digest (en el script: la
  compresión de capas y los metadatos dependen de su versión). `npm ci` instala exactamente el
  `package-lock.json` (integridad por hash, sin scripts de instalación).
- **Sin marcas de tiempo**: `SOURCE_DATE_EPOCH` = hora del commit (`git log -1 --format=%ct`) para los
  metadatos de la imagen, y el exportador OCI con `rewrite-timestamp=true` lleva a esa fecha la de todos los
  archivos creados en el build. `adduser` escribe el día actual en `/etc/shadow`: los Dockerfiles vacían ese
  campo (las cuentas están bloqueadas).
- **Sin attestations embebidas**: `--provenance=false --sbom=false`, porque llevan la hora del build. La
  provenance SLSA y el SBOM se añaden aparte en `publish-images`, sobre el mismo digest.
- **Permisos estables**: los archivos copiados del repositorio conservan el modo del checkout; con
  `umask 022` (el de los runners de GitHub) coinciden. `nginx.conf`, `torrc` y `entrypoint.sh` se copian
  con `--chmod` explícito.
- **Plataforma fija**: `linux/amd64` (en Apple Silicon se emula; tarda más, pero el digest es el mismo).
- **Build sin aleatoriedad**: Vite nombra los assets por el hash de su contenido; el web se construye
  dentro de la imagen con el Node fijado.
- **Mismas etiquetas**: `org.opencontainers.image.{source,revision,version,licenses}` salen del tag y del
  commit, así que se reproducen. El nombre `imagen:tag` solo va en el índice del archivo OCI, no en el
  manifiesto, y no cambia el digest.

Cómo se comprueba: `reproducible-images.yml` construye cada imagen dos veces, en dos builders nuevos sin
caché, y falla si los digests difieren (en las PR que tocan `Dockerfile`, `infra/`, `package*.json` o los
scripts, en `main` y cada lunes). El job `images` de `release.yml` hace lo mismo con cada imagen del
release y se detiene si no coinciden, así que todo digest publicado ya se ha reconstruido una vez.

#### Imagen `tor`: excepción

`infra/tor/Dockerfile` instala Tor con `apk` fijando la versión exacta de cada paquete (`tor`, `su-exec`
y las librerías que Tor enlaza y la base no trae). Alpine no mantiene archivo histórico: cada rama
conserva solo la última compilación de cada paquete. Por eso:

- Mientras esas versiones sigan publicadas, la imagen `tor` es reproducible como las demás.
- Cuando Alpine publica una actualización de alguno de esos paquetes (normalmente de seguridad), el build
  **falla** en lugar de producir otra imagen; el run semanal de `reproducible-images.yml` lo detecta. Hay
  que subir las versiones (lista actual: `docker run --rm alpine:<tag>@<digest> apk add -s tor su-exec`
  muestra lo que instalaría) en una PR.
- Desde ese momento, los releases anteriores **ya no se pueden reconstruir** para `tor`. Su origen se sigue
  verificando con la firma cosign y la provenance SLSA, y el contenido con los paquetes listados en
  `/lib/apk/db/installed` de la imagen publicada.

Las otras siete imágenes no instalan paquetes del sistema: solo dependen de imágenes base fijadas por
digest y de npm, que conserva todas las versiones publicadas.

Para construir sin comparar (desarrollo): `docker compose build`, o una sola imagen con
`sh scripts/build-image.sh indexer indexer.tar` (imprime el digest en la última línea).

## Publicar un release (mantenedores)

La lista completa de condiciones y el job que hace cumplir cada una está en
[release-checklist.md](release-checklist.md). En resumen:

1. Prepara en una PR las notas `docs/releases/v0.2.0.md` (plantilla `docs/releases/TEMPLATE.md`) y el
   informe de auditoría o el waiver aprobado de `docs/security/audits/`.
2. Asegúrate de que `ci` y el restore drill están en verde en el commit que vas a etiquetar.
3. Crea y sube un tag anotado: `git tag -a v0.2.0 -m v0.2.0 && git push origin v0.2.0`.
4. `release.yml` construye sin permisos de escritura (job `build`: generador, E2E del HTML sin red y SBOM;
   job `images`: cada imagen dos veces, que deben dar el mismo digest, sin subirla) y el job `dod`
   comprueba la Definition of Done (CI, restore drill, SBOM, auditorías, notas).
5. Los jobs `publish-images`, `publish` y `verify` esperan aprobación en el entorno `release`. Una persona
   distinta de quien subió el tag revisa el run y aprueba. Son tres aprobaciones: primero las imágenes
   (suben los bytes exactos del build, comprobando el digest, firman y atestan), después los archivos
   (firma, attestations y GitHub Release **en borrador** con las notas e `images.txt`) y por último la
   verificación (`scripts/verify-release.sh` sobre lo publicado), que hace público el release solo si todo
   verifica.

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

Los jobs de build solo tienen `contents: read` (y `dod`, además, `actions: read` para consultar las
ejecuciones de CI). Solo `publish-images` (`packages: write`, `id-token: write`, `attestations: write`),
`publish` (`contents: write`, `id-token: write`, `attestations: write`) y `verify` (`contents: write` para
publicar el borrador, `packages: read`) pueden escribir, y los tres corren en el entorno protegido.

# Generador de llaves en un equipo air-gapped (FR003-07)

Guía paso a paso para crear una identidad Nostr en un equipo que nunca se conecta a la red, usando el
generador en un solo archivo (`keygen.html`) de un release firmado. Cada paso deja algo comprobable: si
una comprobación falla, detente y no uses ese archivo.

Necesitas:

- **Equipo con red** (para descargar y verificar): `gh` (GitHub CLI) y `cosign` 2.4 o superior; ver
  [building.md](building.md#verificar-un-release).
- **Equipo air-gapped**: sin red (Wi-Fi y Bluetooth apagados, cable desconectado), con un navegador
  actual (Firefox, Chromium/Chrome, Edge o Safari). Opcional: Node 22 para verificar el backup con la CLI.
- Un medio extraíble recién formateado para mover los archivos, y papel o una impresora conectada
  por cable al equipo air-gapped si vas a imprimir la hoja de respaldo.

## 1. Descargar el release (equipo con red)

Elige el tag del release en <https://github.com/sedecim-com/nostr/releases> (por ejemplo `v0.2.0`):

```bash
gh release download v0.2.0 --repo sedecim-com/nostr --dir keygen-v0.2.0 \
  --pattern 'keygen.*' --pattern 'SHA256SUMS*'
cd keygen-v0.2.0
```

Quedan `keygen.html`, `keygen.mjs` (la CLI, opcional), sus `.sigstore.json`, `SHA256SUMS` y
`SHA256SUMS.sigstore.json`. También puedes bajarlos a mano desde la página del release.

## 2. Verificar firma, checksum y provenance (equipo con red)

```bash
# a) SHA256SUMS lo firmó el workflow de release de este repositorio, en un tag v*
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp 'https://github.com/sedecim-com/nostr/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS

# b) los archivos descargados coinciden con SHA256SUMS (en macOS: shasum -a 256 --ignore-missing -c)
sha256sum --ignore-missing -c SHA256SUMS

# c) firma propia de keygen.html y su provenance SLSA (qué workflow y qué commit lo construyeron)
cosign verify-blob --bundle keygen.html.sigstore.json \
  --certificate-identity-regexp 'https://github.com/sedecim-com/nostr/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com keygen.html
gh attestation verify keygen.html --repo sedecim-com/nostr
```

Debes ver `Verified OK` en cada `cosign verify-blob`, `keygen.html: OK` en el checksum y
`✓ Verification succeeded!` en `gh attestation verify`. Si usarás la CLI, repite la parte c) con
`keygen.mjs`. Todo lo anterior lo hace también `SKIP_IMAGES=1 sh scripts/verify-release.sh v0.2.0`
(descarga el release completo).

La regexp acepta cualquier tag `v*` del workflow; para exigir exactamente este release usa
`--certificate-identity https://github.com/sedecim-com/nostr/.github/workflows/release.yml@refs/tags/v0.2.0`.
Si quieres además comprobar que el archivo corresponde al código fuente, reconstrúyelo: el build de
`keygen.html` es reproducible bit a bit ([building.md](building.md#generador-de-llaves-html-y-cli-reproducible-bit-a-bit)).

**Apunta en papel el SHA-256 de `keygen.html`** (la línea correspondiente de `SHA256SUMS`): lo usarás en
el equipo air-gapped para comprobar que el archivo no cambió en el medio extraíble.

## 3. Mover los archivos al equipo air-gapped

Copia al medio extraíble solo `keygen.html` (y `keygen.mjs` si verificarás el backup con la CLI). En el
equipo air-gapped, cópialos al disco y recalcula el checksum:

```bash
sha256sum keygen.html                       # Linux
shasum -a 256 keygen.html                   # macOS
certutil -hashfile keygen.html SHA256       # Windows (o en PowerShell: Get-FileHash keygen.html)
```

Debe coincidir con el valor que apuntaste. No vuelvas a conectar ese medio a un equipo con red después
de generar la llave si guardas en él el backup.

## 4. Generar la identidad (equipo air-gapped)

1. Abre `keygen.html` directamente desde el disco (doble clic, o `file:///ruta/keygen.html` en la barra
   del navegador). No hace falta servidor: la página es un solo archivo y su política de seguridad
   (CSP `default-src 'none'`, `connect-src 'none'`, script y estilos fijados por SHA-256) bloquea toda
   conexión de red.
2. Espera el mensaje **«Página cargada sin conexión: lista para generar.»**. Si no aparece, el navegador
   no ejecutó el script (por ejemplo, el archivo se modificó y la CSP lo bloqueó): no continúes.
3. Escribe la **contraseña del backup** (mínimo 12 caracteres) y repítela. Protege la llave privada
   cifrada: sin ella el backup no sirve, y nadie puede recuperarla por ti.
4. Elige el **coste de scrypt**: 2^18 (recomendado), 2^16 (rápido) o 2^20 (más lento de atacar y de abrir).
5. Pulsa **«Generar llave»**. Tarda unos segundos. La página muestra:
   - `npub`: tu identidad pública.
   - `ncryptsec`: la llave privada cifrada con tu contraseña (NIP-49). La nsec en claro nunca se muestra.
   - La autoprueba: derivación, firma BIP-340 y rechazo de manipulación deben decir **correcta/correcto**.
     Si alguna dice FALLIDA, descarta esa llave.
6. Guarda el respaldo:
   - **«Imprimir hoja de respaldo»**: npub, ncryptsec, sus códigos QR, la fecha y los pasos de
     recuperación. Imprime en papel; evita «Guardar como PDF» salvo en un medio que vaya a quedar offline.
   - **«Descargar backup cifrado (.json)»**: descarga `nostr-backup-AAAA-MM-DD.json` (npub + ncryptsec).
7. Pulsa **«Borrar de la página»** y cierra la pestaña. La contraseña no se guarda en ningún sitio.

## 5. Verificar el backup antes de confiar en él

Comprueba que el backup se puede abrir con tu contraseña y que corresponde al npub mostrado. Hazlo antes
de publicar ese npub o de pasar a usar la identidad.

**Con la CLI en el propio equipo air-gapped** (Node 22; `keygen.mjs` verificado en los pasos 2 y 3):

```bash
node keygen.mjs verify nostr-backup-AAAA-MM-DD.json
# Contraseña del backup (mín. 12 caracteres): …
# OK: backup válido para npub1…
```

`verify` descifra el ncryptsec, vuelve a derivar la llave pública, firma y verifica un mensaje de prueba
y compara el npub con el declarado en el archivo; si no cuadra, termina con
`ERROR: el backup no corresponde al npub declarado`. La CLI bloquea todas las primitivas de red de Node
antes de tocar ninguna llave.

**Al importar la identidad en el cliente** (cuando vayas a usarla): en la web, *Personas → Importar
archivo de backup (generador offline o esta web)*; en la terminal,
`npm run sovereign -- persona import --backup nostr-backup-AAAA-MM-DD.json --label NOMBRE --relay wss://…`.
Ambos descifran con tu contraseña y comprueban el npub. Comprueba además que el npub que muestra el
cliente es idéntico, carácter a carácter, al de la hoja impresa.

Para la hoja impresa sin archivo `.json`: escanea el QR del ncryptsec (o copia el texto) en un cliente
compatible con NIP-49, introduce la contraseña y compara el npub con el de la hoja.

## Qué protege y qué no

- La firma keyless y la provenance prueban que `keygen.html` lo construyó `release.yml` de este
  repositorio a partir del commit del tag, y el checksum que no cambió desde entonces. No prueban que
  ese código no tenga errores: el proyecto está en *early release* y sin auditoría independiente
  ([SECURITY.md](../SECURITY.md)).
- La CSP impide que la página abra conexiones; el equipo sin red protege además frente a un navegador o
  sistema comprometido que intentara exfiltrar datos por otra vía. Un equipo comprometido sigue pudiendo
  ver la contraseña o la llave mientras la generas: usa un sistema de confianza (por ejemplo, un live USB
  recién descargado y verificado).
- La hoja impresa y el `.json` contienen la llave cifrada: guárdalos separados de la contraseña.

#!/bin/sh
# Verifies a GitHub Release built by .github/workflows/release.yml (OPS-09, FR003-07, NFR010-02):
# SHA256SUMS, the cosign keyless bundle of every file, the GitHub attestations (SLSA provenance) of the
# key generator and SBOMs and, unless SKIP_IMAGES=1, the signature, provenance and SBOM of every image, and
# the SBOM attested for the pinned Buzz image (NFR010-04).
#   sh scripts/verify-release.sh v0.2.0 [DIR]      (needs gh, cosign >= 2.4; files land in DIR)
set -eu

REPO=${REPO:-sedecim-com/nostr}
ISSUER=https://token.actions.githubusercontent.com

tag=${1:-}
case "$tag" in
  v*) ;;
  *) echo "uso: sh scripts/verify-release.sh vX.Y.Z [DIR]" >&2; exit 2 ;;
esac
dir=${2:-release-$tag}
# Only the release workflow running on this exact tag may have signed the files.
identity="https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$tag"

for tool in gh cosign; do
  command -v "$tool" >/dev/null 2>&1 || { echo "falta $tool en el PATH (ver docs/building.md)" >&2; exit 2; }
done
if command -v sha256sum >/dev/null 2>&1; then sha256check='sha256sum -c'; else sha256check='shasum -a 256 -c'; fi

fail() { echo "FALLO: $*" >&2; exit 1; }

echo "== Descargando los assets de $REPO $tag en $dir"
mkdir -p "$dir"
gh release download "$tag" --repo "$REPO" --dir "$dir" --clobber
cd "$dir"

echo "== 1/4 Firma de SHA256SUMS (cosign, identidad $identity)"
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "$identity" --certificate-oidc-issuer "$ISSUER" SHA256SUMS \
  || fail "la firma de SHA256SUMS no es válida para $identity"

echo "== 2/4 Checksums"
$sha256check SHA256SUMS || fail "algún archivo no coincide con SHA256SUMS"

echo "== 3/4 Firma de cada archivo y attestations de GitHub"
while read -r _sum file; do
  cosign verify-blob --bundle "$file.sigstore.json" \
    --certificate-identity "$identity" --certificate-oidc-issuer "$ISSUER" "$file" </dev/null \
    || fail "la firma de $file no es válida"
done < SHA256SUMS
for file in keygen.html keygen.mjs sbom.cdx.json sbom-buzz.cdx.json; do
  gh attestation verify "$file" --repo "$REPO" --signer-workflow "$REPO/.github/workflows/release.yml" \
    || fail "sin attestation de provenance válida para $file"
done

if [ "${SKIP_IMAGES:-0}" = 1 ]; then
  echo "== 4/4 Imágenes: omitido (SKIP_IMAGES=1)"
else
  echo "== 4/4 Imágenes (firma cosign, provenance y SBOM de cada una), según images.txt"
  while read -r ref; do
    [ -n "$ref" ] || continue
    case "$ref" in *@sha256:*) ;; *) fail "images.txt: $ref no está fijada por digest" ;; esac
    cosign verify --certificate-identity "$identity" --certificate-oidc-issuer "$ISSUER" "$ref" </dev/null >/dev/null \
      || fail "la firma de $ref no es válida"
    gh attestation verify "oci://$ref" --repo "$REPO" --signer-workflow "$REPO/.github/workflows/release.yml" </dev/null \
      || fail "sin attestation de provenance válida para $ref"
    gh attestation verify "oci://$ref" --repo "$REPO" --signer-workflow "$REPO/.github/workflows/release.yml" \
      --predicate-type https://cyclonedx.org/bom </dev/null >/dev/null \
      || fail "sin SBOM atestado para $ref"
  done < images.txt
  # NFR010-04: the pinned Buzz image is upstream's; its SBOM is attested by this release, for that digest.
  buzz=$(cat buzz-image.txt)
  case "$buzz" in *@sha256:*) ;; *) fail "buzz-image.txt: $buzz no está fijada por digest" ;; esac
  gh attestation verify "oci://$buzz" --repo "$REPO" --signer-workflow "$REPO/.github/workflows/release.yml" \
    --predicate-type https://cyclonedx.org/bom >/dev/null \
    || fail "sin SBOM atestado para la imagen de Buzz $buzz"
fi

echo "OK: release $tag verificada ($dir)"

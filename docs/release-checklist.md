# Checklist de release: Definition of Done (REL-01, REL-02, NFR010-03)

Un release (`v*`) solo se publica si se cumple todo lo de esta lista **para el commit exacto del tag**.
Cada punto lo hace cumplir un job de [`release.yml`](../.github/workflows/release.yml): nada depende de
que alguien se acuerde de revisarlo. Cómo se construye y se verifica lo publicado:
[building.md](building.md).

## Gates y quién los hace cumplir

| # | Gate | Dónde se comprueba | Qué bloquea si falla |
|---|---|---|---|
| 1 | CI en verde en el commit del tag: typecheck, tests unitarios y E2E en proceso, `lint:claims`, **E2E de navegador** (Playwright), generador HTML sin red (job `test`); escaneo de secretos (`secrets`); Compose y Caddyfile (`compose`); Kubernetes, Terraform, SLO y shellcheck (`deploy-config`); interop marmot-ts ↔ MDK (`marmot-mdk`); **tests de fugas** con captura de red (`leak-tests`); **perfil Tor** de extremo a extremo (`tor-profile`); **gate de interop** contra el stack completo y escaneo de logs (`stack`) | `dod` → `release-gate.mjs ci`: busca con `gh api` (token del job, `actions: read`) las ejecuciones de `ci.yml` con `head_sha` = commit del tag y exige una terminada en `success` con esos ocho jobs en `success` (un job omitido no cuenta) | todo lo que publica |
| 2 | **Restore drill** con éxito en ese commit en las últimas 72 h (`RESTORE_MAX_AGE_HOURS`) | `dod` → `release-gate.mjs restore`: ejecuciones de `restore-drill.yml` con ese `head_sha` | todo lo que publica |
| 3 | **SBOM** generado (CycloneDX con componentes) | `build` lo genera (`npm run sbom`); `dod` → `release-gate.mjs sbom` lo valida | todo lo que publica |
| 4 | **Auditorías** SEC-01 y SEC-02: informe en `docs/security/audits/<tag>.md` o waiver revisado en `docs/security/audits/waivers/<tag>.md` con motivo y aprobador distinto de quien publica | `dod` → `release-gate.mjs audits` ([formato](security/audits/README.md)) | todo lo que publica |
| 5 | **Notas de release** `docs/releases/<tag>.md` con la sección «Cambios en el modelo de confianza» completa | `dod` y `publish` → `release-gate.mjs notes` ([plantilla](releases/TEMPLATE.md)); `publish` las usa como cuerpo del GitHub Release | todo lo que publica |
| 6 | **Imágenes reproducibles**: cada imagen construida dos veces, en builders limpios, da el mismo digest | `images` (`scripts/build-image.sh` dos veces + comparación) | todo lo que publica |
| 7 | **Firma** cosign keyless de imágenes y archivos, **attestations** SLSA y SBOM | `publish-images` y `publish` (entorno protegido `release`) | — (son los pasos de publicación) |
| 8 | **Verificación** de lo publicado como lo haría un usuario (firmas, checksums, attestations, imágenes de `images.txt`) | `verify` → `scripts/verify-release.sh`; el release se crea como **borrador** en `publish` y `verify` lo hace público solo si todo verifica | la publicación del GitHub Release |

Aprobaciones: `publish-images`, `publish` y `verify` corren en el entorno protegido `release`; cada uno
espera la aprobación de una persona distinta de quien lanzó el workflow (tres aprobaciones por release).

## Antes de subir el tag

1. `main` en verde en el commit que se va a etiquetar (`ci`), o lanza `ci` sobre el tag si el commit no
   pasó por `main`: `gh workflow run ci.yml --ref vX.Y.Z`.
2. Restore drill reciente en ese commit. El nocturno cubre el `HEAD` de `main`; si no, lánzalo:
   `gh workflow run restore-drill.yml --ref vX.Y.Z` (unos 60 min).
3. `docs/releases/vX.Y.Z.md` desde la plantilla, revisado en una PR (`npm run lint:claims` lo revisa).
4. Informe de auditoría o waiver para `vX.Y.Z`, aprobado en su PR por quien figure como aprobador.
5. Tag anotado: `git tag -a vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z`.

Si `dod` falla, el mensaje dice qué falta. Corrígelo y vuelve a ejecutar el run (*Re-run failed jobs*) o
lanza *Actions → release → Run workflow* sobre el tag. Un cambio en el repositorio (notas, waiver) exige un
commit nuevo y, por tanto, un tag nuevo: el gate mira siempre el contenido del commit etiquetado.

## Si falla la verificación

El GitHub Release queda en **borrador** (no visible para el público) y las imágenes ya subidas no figuran
en ningún release publicado. Revisa el log de `verify`; si el fallo es transitorio (Rekor, GHCR), vuelve a
ejecutar `verify`. Si lo publicado está mal, borra el borrador (`gh release delete vX.Y.Z`) y publica un tag
nuevo. Un release ya publicado nunca se sobrescribe: `publish` se niega a reemplazar sus assets.

## Primer release (v0.1.0)

- SEC-01 y SEC-02 no están hechas: hace falta el waiver
  [`docs/security/audits/waivers/v0.1.0.md`](security/audits/waivers/v0.1.0.md) con `Aprobado por` y
  `Fecha` rellenos por alguien distinto de quien sube el tag, en una PR que esa persona apruebe.
- Notas: [`docs/releases/v0.1.0.md`](releases/v0.1.0.md).
- Tras publicarlo, cambia a pública la visibilidad de cada paquete `nostr-*` en GHCR (building.md).

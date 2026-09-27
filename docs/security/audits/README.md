# Auditorías de seguridad por release (REL-01)

Cada release necesita, para su tag, las auditorías externas **SEC-01** (revisión criptográfica
independiente) y **SEC-02** (pentest). El job `dod` de `release.yml` (`node scripts/release-gate.mjs
audits`) bloquea el release si alguna no está cubierta por un informe o por un waiver válido.

## Informe: `docs/security/audits/<tag>.md`

```markdown
# Auditorías de v0.2.0

- Tag: v0.2.0
- Auditorías: SEC-01, SEC-02
- Informe: https://… (o ruta al PDF en este directorio)
- Hallazgos abiertos: ninguno / enlaces a los issues
```

`Auditorías` lista las que cubre el informe; `Informe` no puede quedar vacío ni en `PENDIENTE`.

## Waiver: `docs/security/audits/waivers/<tag>.md`

Excepción explícita para publicar sin una auditoría. Solo vale para ese tag.

```markdown
# Waiver de auditorías: v0.2.0

- Tag: v0.2.0
- Auditorías: SEC-01, SEC-02
- Motivo: por qué se publica sin ellas, qué riesgo se acepta y qué lo mitiga
- Aprobado por: @usuario-de-github
- Fecha: 2026-10-01
```

Reglas que comprueba el gate:

- `Motivo` concreto (30 caracteres o más).
- `Aprobado por` es un `@usuario` de GitHub **distinto** de quien sube el tag o lanza el workflow.
- `Fecha` en formato `AAAA-MM-DD`.

El waiver entra por una PR revisada y aprobada por la persona que figura en `Aprobado por`: esa aprobación
de la PR es la revisión del waiver. El gate no puede comprobarla; lo hace la protección de `main`.

## Estado

SEC-01 y SEC-02 no se han realizado. El primer release (v0.1.0) necesita el waiver
[`waivers/v0.1.0.md`](waivers/v0.1.0.md), que está preparado con el motivo pero **sin aprobador**: hasta
que alguien distinto de quien publica lo apruebe (rellenando `Aprobado por` y `Fecha` en una PR que esa
persona revise), el job `dod` detiene el release.

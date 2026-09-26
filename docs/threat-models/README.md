# Threat models por perfil (DEC-10)

- **Versión:** v0.1 (2026-09-26) · **Estado:** Propuesto (pendiente de revisión de seguridad) · **Base:**
  `docs/threat-model.md` (general) y presets de `packages/profiles/src/presets.ts`.
- Se revisan en cada release (Apéndice D del scope). Un cambio en un preset o en una mitigación obliga a
  actualizar el documento del perfil afectado en el mismo PR.

| Perfil | Para quién | Documento |
|---|---|---|
| convenience | Usuario convencional: facilidad y recuperación | [convenience.md](convenience.md) |
| private-resilient | Usuario Bitcoin/Nostr, equipo privado | [private-resilient.md](private-resilient.md) |
| institutional | Organizaciones con roles y auditoría | [institutional.md](institutional.md) |
| sovereign | Operador soberano sin dependencia del SaaS | [sovereign.md](sovereign.md) |
| sovereign-tor | Periodista, fuente, alto riesgo | [sovereign-tor.md](sovereign-tor.md) |

Escala de riesgo residual: **Alto** (explotable por un adversario del perfil sin controles adicionales) ·
**Medio** (requiere un error del usuario o capacidades superiores) · **Bajo** (mitigado y probado).

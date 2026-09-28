# El backlog vive en GitHub Issues

Desde OPS-10, **los issues con el label `backlog` son la fuente del backlog**. `backlog.json`, `README.md` y
`backlog.csv` de esta carpeta se generan a partir de ellos: no se editan a mano, y si se editan, la siguiente
sincronización los sobrescribe.

Excepción: `meta` de `backlog.json` (sprints, `baseline`, `version`, `source`, prioridades) no sale de los
issues. Se edita a mano por PR y la sincronización lo conserva; después, `node scripts/backlog.mjs` regenera
`README.md` y `backlog.csv`. Al traer la salida de la rama `backlog-sync` a una PR, primero se trae esa salida y
después se edita `meta`, para no volver a su valor anterior.

## Cómo se representa una tarea

| Backlog | En GitHub |
|---|---|
| ID y título | Título del issue `[ID] título`, p. ej. `[FR012-05] Reintentos del mirror` |
| Sprint | Milestone `S4 · …` (`v0.1` cerrado, `Diferido` sin fecha) |
| Prioridad | Label `P0`–`P3`. Se copia al campo de la organización **Priority** (Urgent/High/Medium/Low) |
| Story points | Sección *Story points* del cuerpo. Se copia al campo **Effort** (1–2 Low, 3 Medium, 5–8 High) |
| Fechas | Campos **Start date** / **Target date** = fechas del sprint (al crear el issue) |
| Epic | Label `epic:…` y sub-issue del issue `[Epic] …` |
| Tipo | Sección *Tipo* del cuerpo (y label `tipo:…`) |
| Requisito, criterio de hecho, evidencia | Secciones del cuerpo (mismo formato que el formulario *Tarea del backlog*) |
| Dependencias | Sección *Depende de* (fuente para el validador) y enlaces nativos **blocked by** |
| Estado | Abierto = Pendiente · abierto con `status:parcial` = Parcial · cerrado *completed* = Hecho · cerrado *not planned* = Descartado |
| En pausa | Label `pausado`: el equipo decidió no trabajarla por ahora. Solo se ve en GitHub; no cambia el sprint ni el estado del backlog |
| Estado de la evidencia | Label `evidencia:…` (ver abajo). Solo se ve en GitHub |

Si hay diferencias, mandan los labels y el cuerpo: los campos de la organización son un espejo para las vistas
de GitHub Projects.

## Trabajo diario

- **Nueva tarea:** *New issue → Tarea del backlog*, título `[ID] …`. Después asigna milestone, prioridad,
  `epic:…`, el sub-issue del epic y los "blocked by". Un issue sin prioridad, epic o milestone no pasa al backlog:
  la sincronización lo deja como aviso.
- **Avance:** añade `status:parcial` y actualiza *Evidencia*. Para terminar, cierra el issue como *completed*,
  o con `Closes #N` en la PR. La evidencia es obligatoria para cerrar o marcar como parcial.
- **Terminar:** para que la tarea pase a Hecho, *Evidencia* debe citar el SHA de un commit de `main` (7 o más
  caracteres). Sirve el de un commit de la PR que la cierra, porque las PR se fusionan con commit de merge.
  Rellénala antes de fusionar. Nada pasa a Hecho desde una rama (OPS-17).
- **Descartar:** cierra el issue como *not planned* y cita el ADR en *Evidencia*.
- **Cambiar de sprint:** cambia el milestone. Los sprints cerrados (`"closed": true` en `meta.sprints`) no admiten
  tareas abiertas: el validador lo rechaza.

## Estados de la evidencia (OPS-17)

Una tarea «hecha» puede estar más o menos probada. Cada issue lleva como mucho un label `evidencia:…`: el estado
más alto que alcanzó. Al subir de estado se cambia el label y se añade la prueba a *Evidencia*.

| Estado | Label | Cuándo | Quién lo pone |
|---|---|---|---|
| Proposed | `evidencia:proposed` | Abierta, sin PR | Opcional: GitHub ya lo muestra (issue abierto, sin PR en *Development*) |
| In PR | `evidencia:in-pr` | Una PR abierta la implementa | Opcional: GitHub enlaza la PR que dice `Closes #N` |
| Merged | `evidencia:merged` | *Evidencia* cita un commit de `main` | La sincronización, al aceptarla como Hecho |
| CI Verified | `evidencia:ci-verified` | El CI de `main` pasa con ese commit | Quien lo comprueba (enlace a la ejecución) |
| Stage Verified | `evidencia:stage-verified` | Verificada en stage | Quien la verifica (enlace o registro del smoke) |
| Externally Audited | `evidencia:externally-audited` | Cubierta por la auditoría externa | Quien recibe el informe |
| Production Enabled | `evidencia:production-enabled` | Activa en producción | Quien la activa |

La regla que aplica la sincronización (`pull`):

- **Un issue cerrado como *completed* pasa a Hecho solo si *Evidencia* cita un commit de `main`**, es decir,
  el propio `main` o uno de sus ancestros. Lo comprueba con la API de comparación de GitHub.
- Si no lo cita, la tarea mantiene su estado anterior y la ejecución deja un aviso con el issue. Se corrige
  añadiendo el SHA a *Evidencia*; la siguiente sincronización la acepta.
- Al aceptarla, si el issue no tiene ningún label `evidencia:…`, le pone `evidencia:merged`.
- Las tareas que ya estaban hechas antes de esta regla se mantienen. La ejecución resume en un aviso las que
  no citan ningún commit.

## Sincronización (`.github/workflows/backlog-sync.yml`)

1. Se ejecuta con cada cambio en un issue `backlog`/`epic`, una vez al día y a mano.
2. Lanza `node scripts/backlog-github.mjs pull --write`, después `node scripts/backlog.mjs` (valida y regenera),
   y abre o actualiza la PR **"backlog: sync desde GitHub Issues"** en la rama `backlog-sync`.
3. Si el validador falla (p. ej. una tarea cerrada que depende de otra abierta, o una dependencia hacia un sprint
   posterior), la ejecución queda en rojo con el error. Se corrige en los issues.
4. Las PR que abre `GITHUB_TOKEN` no lanzan `ci`: la sync solo toca `docs/backlog`, y el validador ya corrió en
   el workflow.

`pull` solo escribe en GitHub para poner `evidencia:merged` (ver arriba).

`node scripts/backlog-github.mjs seed` crea en GitHub lo que tiene `backlog.json` y falta en los issues:
labels (también los `evidencia:…`), milestones, epics, tareas, estados y relaciones. Nunca edita un issue.
Solo ajusta dos cosas derivadas:

- el título y la descripción de cada milestone siguen a `meta.sprints`, que no se regenera desde los issues (así
  se renombra un sprint), y un sprint con `"closed": true` cierra su milestone (nunca reabre uno cerrado a mano);
- los enlaces «blocked by» siguen a la sección *Depende de* de cada issue: añade los que faltan y, en los issues
  abiertos, retira los que apuntan a tareas que la sección ya no cita. No toca enlaces a otros issues.

Además:

- Si se interrumpe (límites de la API de GitHub), la siguiente ejecución lo completa.
- Corre al fusionar en `main` un cambio del script o del workflow; así se sembró el backlog la primera vez.
- También se puede lanzar a mano (*Run workflow* → `seed`).

Requisito del repositorio: *Settings → Actions → General → Allow GitHub Actions to create and approve pull
requests*. Sin él, la rama `backlog-sync` se actualiza igual y el workflow deja un aviso con el enlace para
abrir la PR a mano.

Pruebas locales: `npx vitest run tests/scripts/backlog-github.test.ts` (API de GitHub simulada en memoria). La
prueba verifica el viaje completo backlog → issues → backlog.

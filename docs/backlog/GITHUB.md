# El backlog vive en GitHub Issues

Desde OPS-10, **los issues con el label `backlog` son la fuente del backlog**. `backlog.json`, `README.md` y
`backlog.csv` de esta carpeta se generan a partir de ellos: no se editan a mano, y si se editan, la siguiente
sincronización los sobrescribe.

Excepción: `meta` de `backlog.json` (sprints, `baseline`, `version`, `source`, prioridades, nombres de los
requisitos, filas del estado del README, bloqueos externos) no sale de los issues. Se edita a mano por PR y la sincronización lo conserva; después, `node scripts/backlog.mjs` regenera
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

## Orden de desbloqueo

`README.md` lleva, generada, la sección «Orden de desbloqueo» (`scripts/backlog-order.mjs`): las tareas abiertas en
olas según sus dependencias abiertas, para ver qué destraba qué y qué se puede trabajar ya. Sale de `backlog.json` y
la sincronización la regenera; no hay nada que mantener aparte de los bloqueos externos.

| Columna | Qué es |
|---|---|
| Ola | La ola 0 no espera a ninguna tarea abierta; cada ola siguiente espera solo a las anteriores. Un ciclo lo rechaza el validador |
| Desbloquea | Las tareas abiertas que esperan a esta, directa o indirectamente. Dentro de una ola van primero las que más desbloquean, después por prioridad |
| Espera a | Sus dependencias que siguen abiertas |
| Bloqueo | Lo que impide cerrarla aunque el código esté listo (ver abajo), `en PR` si la tarea tiene una PR abierta (`evidencia:in-pr`), o `lista` |

`lista` es una tarea sin bloqueo propio, sin PR abierta y sin dependencias abiertas que aún necesiten código: una
dependencia parcial con bloqueo externo cuenta como código ya fusionado, así que se puede construir encima.

El bloqueo externo no sale de los issues. Está en `meta.externalBlockers` (id de tarea → tipo), con los tipos y su
significado en `meta.blockerKinds`: `persona` (alguien aprueba, configura o ejecuta algo), `aws` (cuenta, región o
stage reales) y `externo` (auditor, asesoría legal, publicación upstream, hardware). Se edita a mano por PR, como el
resto de `meta`. La entrada de una tarea que ya no está abierta se ignora, así que cerrar una tarea por la
sincronización no rompe nada; un id que no existe sí lo rechaza el validador.

## Trazabilidad y tablero de estado (OPS-18)

`docs/requirements-traceability.md` y `docs/status.md` se generan con `node scripts/traceability.mjs`. Salen de
`backlog.json` (los issues) y del código: los tests que citan en su texto una tarea (`FR001-03`) o un requisito
(`FR-001`). No se editan a mano. La sincronización los regenera. El job `traceability` de CI falla si no están al
día, o si la evidencia de una tarea que no está Pendiente cita algo que no existe:

| Referencia | Cómo se escribe | Qué se comprueba |
|---|---|---|
| Archivo o directorio | Ruta desde la raíz (`apps/web-saas/src/lib/session.ts`). En prosa solo cuenta si tiene extensión; entre backticks, también sin ella | Que exista en el árbol. Una ruta que no empieza en la raíz (`lib/groups.ts`) tiene que ser el final de alguna. `*` vale dentro de un directorio |
| Prueba | Ruta o solo el nombre del archivo (`identity.test.ts`) | Que exista un archivo con ese nombre |
| Commit | SHA de 7 a 40 caracteres, suelto en la prosa; también `main@sha` | Que exista y, si la tarea está Hecha, que sea de la historia de `main` |
| ADR | `ADR 0011`, `ADR 0002/0003` | Que exista `docs/adr/0011-….md` |

No se comprueban:

- los commits de otro repositorio, escritos `repo@sha` (`buzz@02c6309`);
- los hashes que no son commits (digests, ids), que van entre backticks;
- las URLs y los hosts (`ghcr.io/…`);
- las salidas de build (`dist/…`);
- la prosa con barras sin extensión («deploy/update/teardown»).

**Estado de un requisito:**

- **Hecho**: lo están todas sus tareas del programa, sin las descartadas ni las diferidas a después de v1.0.
- **Parcial**: alguna está hecha o parcial.
- **Pendiente**: ninguna.

Los nombres de los requisitos están en `meta.requirements`.

**El tablero** muestra:

- las tareas por estado;
- las hechas por nivel de evidencia: `evidenceState` es el label `evidencia:…` más alto del issue, que `pull` guarda y `seed` vuelve a poner;
- los sprints abiertos;
- las P0 abiertas.

**El README** lleva, entre `<!-- status:start … -->` y `<!-- status:end -->`, el estado de cada perfil y
capacidad por nivel de evidencia (OPS-19), también generado:

- Las filas son `meta.capabilities`. Cada una elige sus tareas por requisito (`FR-017`), por prefijo de ID
  (`VAULT-*`) o por tarea (`OPS-06`).
- El nivel de una fila es el más bajo que alcanzan todas sus tareas del programa. Una tarea hecha antes de
  OPS-17, sin label, cuenta como Merged.
- Mientras falte alguna tarea, la fila está «En curso».
- La advertencia de no aptitud para alto riesgo se mantiene mientras ninguna fila tenga auditoría externa.

**Si el job falla en una PR:**

1. Corrige la referencia en el issue.
2. Lleva el mismo texto a `backlog.json`, o espera a la sincronización.
3. Regenera con `node scripts/traceability.mjs`.

## Sincronización (`.github/workflows/backlog-sync.yml`)

1. Se ejecuta con cada cambio en un issue `backlog`/`epic`, una vez al día y a mano.
2. Lanza `node scripts/backlog-github.mjs pull --write`, después `node scripts/backlog.mjs` (valida y regenera) y
   `node scripts/traceability.mjs` (regenera la trazabilidad y el tablero, y comprueba la evidencia con la
   historia completa). Luego abre o actualiza la PR **"backlog: sync desde GitHub Issues"** en la rama
   `backlog-sync`.
3. Si `main` ya coincide con los issues (p. ej. porque otra PR trajo la salida de `backlog-sync`, ver arriba),
   cierra con un comentario la PR de sincronización que siga abierta y borra la rama. Fusionar esa PR no
   cambiaría nada o chocaría con líneas que `main` ya movió, y una rama vieja se podría traer por error a otra PR.
   La siguiente ejecución con diferencias vuelve a crear la rama desde `main` y abre una PR nueva.
4. Si el validador falla (p. ej. una tarea cerrada que depende de otra abierta, o una dependencia hacia un sprint
   posterior) o la evidencia de un issue cita algo que no existe, la ejecución queda en rojo con el error. Se
   corrige en los issues.
5. Las PR que abre `GITHUB_TOKEN` no lanzan `ci`: la sync solo toca `docs/backlog`, la trazabilidad y el tablero,
   y sus comprobaciones ya corrieron en el workflow.

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

### Quién abre la PR de sincronización (OPS-12)

Una PR que abre el `GITHUB_TOKEN` del workflow no lanza ningún workflow, así que no tiene checks, y con los
checks obligatorios en `main` no se podría fusionar. Por eso la rama y la PR las sube una GitHub App de los bots
cuando está configurada:

- La App: *Organization settings → Developer settings → GitHub Apps*, sin webhook, con *Contents* y *Pull
  requests* en escritura e instalada solo en este repositorio.
- En el repositorio, *Settings → Secrets and variables → Actions*: la variable `BOT_APP_CLIENT_ID` (el *Client
  ID* de la App) y el secreto `BOT_APP_PRIVATE_KEY` (su clave privada `.pem` entera).
- El workflow pide un token de la App solo con esos dos permisos (`actions/create-github-app-token`), empuja la
  rama y abre, actualiza o cierra la PR con él. Los issues los sigue leyendo y escribiendo con el `GITHUB_TOKEN`.

Sin la variable, todo va con el `GITHUB_TOKEN`, como antes, y hace falta *Settings → Actions → General → Allow
GitHub Actions to create and approve pull requests*. Si no se puede abrir la PR, la rama `backlog-sync` se
actualiza igual y el workflow deja un aviso con el enlace para abrirla a mano.

Pruebas locales: `npx vitest run tests/scripts/backlog-github.test.ts` (API de GitHub simulada en memoria). La
prueba verifica el viaje completo backlog → issues → backlog.

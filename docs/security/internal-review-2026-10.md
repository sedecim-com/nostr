# Revisión interna de seguridad (2026-10)

- **Fecha:** 2026-09-30 · **Commit revisado:** `d6aaee8` (main) · **Base:** lo fusionado desde `9355003`, el merge
  de las correcciones de la [primera revisión](internal-review-2026-09.md) (246 commits) · **Tarea:** SEC-13 (#331).
- **Correcciones:** IR-2026-10-01, -02, -04 y -06 en la misma PR que este documento; IR-2026-10-37 en la PR #391
  (FR026-04); IR-2026-10-03 e IR-2026-10-11 en la PR #393. El resto sigue abierto con su plan en la sección 3.
- **Alcance:** lo que entró después de la primera revisión, por áreas:
  - Continuity Vault (VAULT-01 a VAULT-06);
  - motor de entrega, mensajería y persistencia MLS (FR009-03, FR011-05/06, FR017-06, FR025-12);
  - custodia gestionada, sesiones e identidad (FR005-08, FR005-11, FR005-12, FR024-03, VAULT-02) y feature gates
    de producción (OPS-20);
  - modo institucional, espejo e indexer (FR014-05, FR023-10, FR023-12, FR024-05, SEC-06) y notification-gateway
    (OPS-06);
  - cliente soberano por Tor (FR006-06, FR021-03);
  - cadena de suministro: workflows, gate de release (REL-01, OPS-08), OPS-13, OPS-18, OPS-12 (bots) y SEC-07.

> **Esto es una revisión interna, no es SEC-01 ni SEC-02.** Igual que la primera, sirve para llegar a la auditoría
> externa sin hallazgos fáciles. No es independiente ni tiene la cobertura de un pentest.

## 1. Metodología

La hizo el equipo con agentes de Claude Code, uno por área, y cada hallazgo se verificó antes de anotarlo. Mismo
método que la primera revisión, con dos cambios: cada promesa de la documentación (ADR, threat models,
`docs/disclosures.md`, runbooks, `SECURITY.md`) se contrastó con el código, y una promesa que el código no cumple
cuenta como hallazgo; y cada hallazgo confirmado se reprodujo con una prueba de concepto.

1. **Dependencias:** `npm audit --omit=dev` y `npm audit` completo: **0 vulnerabilidades** (334 dependencias de
   producción, 464 en total).
2. **Análisis estático:** CodeQL `security-extended` corre en cada PR y en `main` (última ejecución sobre `d6aaee8`,
   verde). Sus alertas abiertas no se ven sin acceso a la pestaña de seguridad del repositorio: hay que triarlas antes
   del tag (sección 3).
3. **Búsquedas dirigidas** sobre el diff, con los patrones de la primera revisión, más: inyección en workflows
   (`${{ github.event.* }}` en `run:`, `pull_request_target`, `workflow_run`), credenciales al alcance de scripts de
   instalación, rutas que confían en datos que declara el cliente y aislamiento entre cuentas (IDOR).
4. **Revisión manual** por área, con los threat models y los ADR al lado.
5. **Pruebas de concepto:** contra el código real (APIs en proceso, Cognito de prueba, llaves generadas en la
   prueba), con el binario fijado de SeaweedFS (4.47) para el despliegue del vault, o, donde no se puede ejecutar aquí
   (GitHub Actions), con la traza del flujo y la documentación del proveedor. Cada fila dice cuál.
6. **Tests de regresión** para cada corrección (columna *Test*).
7. **SEC-07:** el archivo de vectores de NIP-44 tiene el SHA-256 publicado en la NIP; los vectores de NIP-44, NIP-49
   y NIP-59 se ejecutan contra los módulos de producción, y dos mutaciones del código (quitar la comprobación del
   padding de NIP-44 y la normalización NFKC de NIP-49) los hacen fallar.

**Resultados que no fueron hallazgos:**

- Aislamiento por dueño sin IDOR en el managed-signer, el vault y el espejo.
- NIP-98 con anti-replay compartido en todas las rutas nuevas.
- Sobres del vault con AAD ligado a la cuenta y al id, y restauración que verifica firma e id de cada evento.
- Autenticidad de los acuses (ligados al rumor y al firmante del seal), con el ACK de relay separado de la
  recepción.
- Sin reutilización de nonce al reintentar mensajes de grupo; commits MLS aplicados solo en su época.
- Aislamiento de circuitos por persona; el tag `relay` de NIP-42 es correcto.
- SEC-06 bien ligado (AAD con el `event_id`, filas antiguas solo en su fila, re-sellado condicional).
- Membresía comprobada en todas las lecturas del espejo; SQL parametrizado; B1 y B2 siguen corregidos.
- La consola escapa todo y firma cada petición.
- El modo legado del signer está retirado; ScryptGate y el tope de logN siguen en import y export; la exportación
  del enclave sigue apagada por defecto.
- Workflows sin inyección, acciones fijadas por SHA, PR de forks sin secretos.
- El gate de release falla cerrado; `verify-release.sh` fija la identidad exacta de cosign.
- Los manifiestos nuevos de k8s son non-root, de solo lectura y sin token de service account.

## 2. Hallazgos

Severidad según la escala de [audit-scope.md](audit-scope.md) §7. Líneas en `d6aaee8`.

| Id | Componente | Severidad | Descripción | Estado | Test / verificación |
|---|---|---|---|---|---|
| IR-2026-10-01 | policy-engine | Media | Los tokens de servicio no tenían ámbito: cualquiera de `POLICY_SERVICE_TOKENS` llamaba a toda ruta de servicio. Regresión de FR024-05 (`fa567f8`): `GET /v1/rotations` pasó de solo admin a admin o servicio. Con el token del indexer, expuesto a Internet, se listaban las rotaciones MLS pendientes y se cerraban sin commit, y el miembro revocado seguía en sus grupos. El token del worker además evaluaba accesos y leía los permisos de publicación. | **Corregido:** cada principal solo llega a las rutas de su ámbito (`indexer`: evaluate y retention; `relay-allowlist`: allowlist y grants; `rotation-worker`: rotaciones y revocaciones); otros principales, con `POLICY_SERVICE_SCOPES`. | `services/policy-engine/test/service-scopes.test.ts` |
| IR-2026-10-02 | sovereign-client (Tor) | Media | `onion-only` no se aplicaba al HTTP de la media de grupo (`blobHttp`, `app.ts:905`) ni al worker de rotaciones (`app.ts:981`). Una persona onion-only se conectaba, por Tor, al servidor clearnet que eligiera un miembro del grupo en su `imeta`, en contra de `docs/sovereign-tor.md`. | **Corregido:** todos los guards de una persona salen de un solo `guardFor`, con su política completa. | `apps/sovereign-client/test/tor-hardening.test.ts` (sin CONNECT a hosts clearnet) |
| IR-2026-10-03 | managed-signer | **Alta** | Exportar, confirmar la migración y borrar una llave gestionada (`api.ts:187-198`) no exige reautenticación: basta el token de Acceso o cualquier sesión `sds_` abierta con él. Quien tenga un navegador robado con la sesión abierta exporta la nsec con una contraseña suya, confirma y borra: la víctima pierde la identidad y todo el historial NIP-44, y después ni siquiera ve el log (404). Contradice el runbook de pérdida, ADR 0008 y los threat models. La cancelación de FR026-04 (#391) tiene la misma exposición. | **Corregido** en la PR #393: esas rutas, y cerrar las demás sesiones, solo aceptan un token de Acceso con `auth_time` de los últimos 300 s (`MANAGED_SIGNER_REAUTH_MAX_AGE_S`), nunca `sds_`: 401 `insufficient_user_authentication` (RFC 9470). La web pide la contraseña de Acceso y el log sigue visible tras borrar. | PoC contra la API en proceso: el ladrón exporta, la nsec deriva la pubkey de la víctima, confirma y borra; la víctima recibe 404. Regresión: `services/managed-signer/test/reauth.test.ts` |
| IR-2026-10-04 | continuity (restauración) | Media | El aviso de archivos que faltan, la mitigación documentada contra el borrado por el operador, se anulaba repitiendo entradas del listado: `missing = contados − listados`, sin deduplicar. Un `next` repetido dejaba al cliente en bucle. | **Corregido:** `listAll` exige ids estrictamente crecientes y que `next` sea el último id de la página. Rellenar el listado con otro contenido ya no es silencioso: aparece como archivos que no abren. | `services/continuity-vault/test/history.test.ts` (entrada repetida, relleno y `next` que no avanza) |
| IR-2026-10-05 | release (CI) | **Alta** | Quien puede subir un tag `v*` elude la separación de funciones. GitHub ejecuta el `release.yml` del commit etiquetado: basta quitar `environment: release` de publish-images, publish y verify, y `dod` de `needs`. Los permisos de escritura vienen del YAML y no del entorno, y el certificado de Fulcio no dice el entorno, así que `verify-release.sh` acepta la firma. Ni OPS-08 ni OPS-12 lo cierran: el tag no tiene que estar en main. | Abierto: que publicar dependa de algo que solo tenga el entorno. Opciones: firma con una llave KMS cuyo rol solo acepte el OIDC `environment:release`, o firma y publicación en un workflow reutilizable de un repo aparte, solo para administradores. Mientras tanto, un control en `verify-release.sh` que exija la aprobación del entorno por otra persona. | Traza del flujo y documentación de GitHub (entornos y permisos del `GITHUB_TOKEN`); el `release.yml` editado conserva todos los permisos de escritura |
| IR-2026-10-06 | CI (`buzz-upstream.yml`) | **Alta** | `pin-pr` ejecutaba `npm ci` con scripts de instalación teniendo el token de la GitHub App en la configuración de git, el `GITHUB_TOKEN` con `actions` y `contents` en escritura y la llave de la App en el runner. Una versión comprometida de cualquier paquete del lockfile ejecutaba código con permisos de escritura. | **Corregido:** npm corre en un job nuevo, `pin-files`, de solo lectura, con `--ignore-scripts` y sin credenciales persistidas, que solo calcula el parche. `pin-pr`, que tiene el token, ya no ejecuta npm ni scripts del árbol: aplica el parche, hace commit y push. | `tests/scripts/bot-token.test.ts` |
| IR-2026-10-07 | CI (bots) | Media | La llave de la GitHub App de los bots es un secreto de repositorio, así que cualquier persona con escritura la lee desde un workflow de su rama. Si la App puede crear tags `v*` (no hay ruleset de tags o la App está en su lista de bypass), el mismo escritor sube el tag como el bot y aprueba él mismo el entorno. | Abierto: la llave como secreto de un entorno `bots` limitado a la rama por defecto; un ruleset de tags sin la App en el bypass; el gate rechaza actores bot. | PoC del gate con actor `…[bot]` |
| IR-2026-10-08 | gate de release | Media | Las aprobaciones de threat models (DEC-10) y los waivers son texto: el gate solo exige un `@login` distinto del actor. Nada comprueba que esa persona exista, tenga acceso o haya revisado algo, ni que el commit del tag esté en main. | Abierto: la PR que tocó el registro, fusionada en main con una review APPROVED de ese login, y el commit del tag como ancestro de main. Depende de IR-2026-10-05, porque el gate corre desde el tag. | PoC: alice sube el tag con `@octocat` escrito por ella y los dos controles dan OK |
| IR-2026-10-09 | mensajería | Media | El acuse de entrega automático (`inbox.ts:124-158`) se envía a cualquier emisor, no solo a contactos, y va a los relays 10050 que publicó el emisor. Allí el pool firma AUTH NIP-42 automáticamente. Un desconocido obtiene sin interacción la conexión y la IP de la víctima (en perfiles sin Tor) y un AUTH firmado con su llave en su propio relay: un oráculo de presencia. La divulgación solo habla de «tus contactos». | **Corregido** en la PR #394: el inbox solo acusa recibo a contactos (quien la persona ya escribió, según su outbox); un desconocido que escribe primero no recibe acuse ni hace que el dispositivo se conecte a sus relays. | PoC con relay del atacante: se conecta, publica el wrap y firma AUTH para su URL. Regresión: `packages/messaging/test/inbox.test.ts` |
| IR-2026-10-10 | managed-signer | Media | La vinculación al dispositivo de la organización (FR024-03) y el dispositivo del log de uso los declara el cliente: `x-device-id` es opcional, las sesiones se abren con cualquier `device_id` y `MANAGED_SIGNER_REQUIRE_DEVICE_SESSION` no está activado en k8s. Tras revocar el dispositivo, el mismo login sigue firmando, incluso con el id del navegador legítimo. | Abierto: activar la variable en k8s; fijar en el servidor el dispositivo que registra la organización; el log registra el dispositivo en todas las filas y no lo toma de la cabecera. | PoC: revocado `org-laptop-7`, el login firma con otro id |
| IR-2026-10-11 | managed-signer | Media | Las sesiones `sds_` sobreviven al procedimiento de pérdida: el cliente pide hasta 30 días de vida, y «cerrar todas» no impide abrir otra con un token de Acceso aún válido. El atacante firma y descifra hasta 30 días después de que la víctima siga el runbook. | **Corregido** en la PR #393: ninguna sesión dura más que el TTL configurado (12 h), y cerrar las demás sesiones guarda un corte por dueño: los logins anteriores, salvo el que las cerró, no abren sesiones ni operan aunque se refresquen. El runbook lo refleja. | PoC: sesión de 400 días pedida → 30 días concedidos, tras cerrar todas. Regresión: `reauth.test.ts`, `tests/browser/web-saas.e2e.ts` |
| IR-2026-10-12 | despliegue del vault | Media | SeaweedFS no aísla el bucket del vault, al contrario de lo que dicen el threat model (l. 55) y ADR 0011 (l. 275). `weed server -s3` abre también master, volumen y filer sin autenticación. Desde cualquier contenedor de la red interna se borran o sobrescriben los sobres de todas las cuentas y la media de Buzz, y la identidad S3 de Buzz tiene Admin global. | **Corregido** en la PR #395: solo la API S3 (8333) está en la red (master, volumen y filer en `127.0.0.1`, Iceberg y Lance apagados); Buzz limitado a su bucket, sin Admin global; NetworkPolicy en k8s. | Binario 4.47 con las flags e identidades del compose: DELETE sin credenciales al filer → 204; con la corrección el filer no es accesible y S3 responde 403. Comprobado con el SDK de S3 |
| IR-2026-10-13 | rotation-worker | Baja | El worker se une a cualquier grupo que lo invite y se conecta a los relays que elija el creador del grupo: SSRF ciego dentro del clúster (sin NetworkPolicy) y AUTH ante relays arbitrarios. Requiere una cuenta del allowlist. | Abierto | Traza del código |
| IR-2026-10-14 | policy-engine | Baja | Una retención legal se anula cambiando el `kind` del recurso a `group`: el hold deja de listarse, el indexer borra la copia y el registro de accesos se poda. La auditoría solo guarda `sensitivity`. Requiere un admin. | Abierto: 409 al cambiar el `kind` con hold activo; auditar `kind`, `members` y `rules`. | PoC contra el engine en memoria |
| IR-2026-10-15 | indexer | Baja | SEC-06 falla en abierto si falta `MIRROR_AT_REST_KEY` (el secreto es `optional` en k8s): las filas nuevas se guardan en claro sin aviso. | Abierto: no arrancar con filas selladas y sin clave. | Traza del código |
| IR-2026-10-16 | indexer | Baja | Con varios relays NIP-29, una lista 39002 firmada por cualquier relay de confianza da acceso al canal con ese id, lo aloje quien lo aloje, en contra de `docs/architecture.md:260`. Por defecto hay un solo relay. | Abierto | PoC unitario |
| IR-2026-10-17 | despliegue k8s | Baja | Sin NetworkPolicy; el `EventAdmit` gRPC del relay-allowlist no autentica (oráculo de pertenencia) y los health muestran estado. | Abierto | Lectura de manifiestos |
| IR-2026-10-18 | web | Baja | La vista de DM marca como leídos todos los mensajes cargados al abrirse, y envía acuses de lectura de mensajes que el usuario no vio. Solo con read receipts activos (opt-in). | Abierto | Traza del código |
| IR-2026-10-19 | web | Baja | «Salir de Acceso» no cierra ni olvida la sesión del signer: otro usuario del mismo vault del navegador la reutiliza y ve y firma con las llaves del anterior. | Abierto | PoC con dos usuarios sobre el mismo almacén |
| IR-2026-10-20 | gate de release (OPS-20) | Baja | La búsqueda de configuración de producción no detecta formas habituales: dotfiles, parches JSON6902 o `.json`, ConfigMaps en JSON, `main.tf.json`, `{name, value}` en una línea, overlays fuera de las rutas declaradas o rutas con `./`. | Abierto: renderizar los overlays con `kubectl kustomize` y escanear el resultado. | Sondas con nueve variantes |
| IR-2026-10-21 | gate de release (OPS-20) | Baja | La exportación del enclave va ligada a la madurez del tier: en Beta, `ENCLAVE_ALLOW_EXPORT=1` pasa el gate. Sobre IR-2026-09-01, que FR005-09 corrigió en código sin medirlo en un Nitro real: el gate debería seguir cerrado hasta esa medición y no solo por la madurez del tier. | Abierto | PoC del gate |
| IR-2026-10-22 | continuity | Baja | Un objeto perdido o dañado hace fallar toda la restauración y la exportación, y reintentar no sirve (500 fijo). | Abierto: contar el archivo como no disponible y seguir. | PoC: 1 objeto borrado → restauración fallida |
| IR-2026-10-23 | continuity-vault | Baja | El barrido de huérfanos puede borrar el objeto de una subida cuya transacción espera más de un intervalo: queda una fila sin objeto, en contra del invariante documentado. | Abierto: no borrar objetos recientes, o acotar las transacciones. | PoC con un repositorio que retiene el `upsert` |
| IR-2026-10-24 | marmot-adapter / motor de entrega | Baja | Los mensajes de grupos MLS no pasan por la copia de VAULT-04, aunque los textos de `best-effort` y `required-for-resilient` dicen que cada evento se copia. | Abierto: sellarlos con el sink antes de publicar, o acotar los textos. | Traza del código |
| IR-2026-10-25 | web | Baja | Restaurar la llave de archivo sustituye en silencio la llave aleatoria con la que ya se sellaron copias automáticas: esas copias quedan huérfanas y fuera del borrado. | Abierto | Traza del código |
| IR-2026-10-26 | documentación del vault | Baja | ADR 0011, el threat model y el texto `sealed` dicen que el operador no liga la cuenta del vault a la persona. Si también ve los relays, lo hace por tiempo, IP y circuito (el CLI comparte la credencial SOCKS). | Abierto: matizar los textos. | Lectura del código |
| IR-2026-10-27 | `verify-release.sh` | Baja | `gh attestation verify --signer-workflow` va sin ref: acepta provenance o SBOM de `release.yml` ejecutado en cualquier rama. | Abierto: `@refs/tags/$tag` y `--source-ref`. | Lectura de gh (`policy.go`) |
| IR-2026-10-28 | gate de release | Baja | El control de CodeQL solo lee la rama por defecto y la primera página de alertas. | Abierto: `ref` del tag y paginación. | Lectura de la API |
| IR-2026-10-29 | `scripts/backup.sh`, `restore.sh` | Baja | Usan `postgres:17-alpine` por tag mutable, con acceso a todos los volúmenes (llaves onion, vault del signer, estado del worker). | Abierto: fijar por digest, como el compose. | Lectura |
| IR-2026-10-30 | indexer (SEC-06) | Informativa | El códec sellado acepta filas `raw` y solo compara el campo `id` del JSON, sin recalcular el hash. Requiere escribir en la base. | Abierto | Lectura |
| IR-2026-10-31 | relay-allowlist | Informativa | Todas las identidades de servicio (`ALLOWLIST_EXTRA_PUBKEYS`) saltan los permisos por `h`; solo el worker lo necesita. | Abierto | Lectura |
| IR-2026-10-32 | managed-signer | Informativa | `consent_version` es declarativo: firmar no mira el consentimiento vigente, y la reapertura (FR005-11) no lo vuelve a pedir. | Abierto | Lectura |
| IR-2026-10-33 | identity (backups) | Informativa | La llave de archivo de un backup v2 sin nsec no está ligada a la persona (la npub declarada no está autenticada). Requiere ingeniería social. | Abierto | Lectura |
| IR-2026-10-34 | vault | Informativa | Con la copia del backup en la nube del mismo despliegue, el vault frente al operador vale lo que la contraseña del backup (logN 16, mínimo 8 caracteres en la web). | Abierto: decirlo en el threat model; logN 18 en la web. | Lectura |
| IR-2026-10-35 | continuity-vault | Informativa | El barrido carga en memoria todas las llaves de objeto (unos 190 MiB por millón), también al arrancar, con un límite de 512 Mi. | Abierto | Medido |
| IR-2026-10-36 | continuity-vault (S3) | Informativa | Supuestos sin documentar: con versionado, borrar deja versiones no actuales; con un prefijo compartido, el barrido borra objetos ajenos. | Abierto | Lectura |
| IR-2026-10-37 | web (preexistente) | Informativa | El JSON del asistente de migración no llevaba la npub y `parseKeyBackup` lo rechazaba: ese respaldo no se podía restaurar. | **Corregido** en la PR #391 (FR026-04) | `apps/web-saas/test/managed-exit.test.ts` |
| IR-2026-10-38 | managed-signer | Informativa | `GET /v1/keys/:id/usage` devuelve 12 meses de log sin paginar. Posible presión de memoria con una llave muy usada; no medido. | Abierto | Lectura |
| IR-2026-10-39 | backlog-sync | Informativa | `seed` confía en cualquier issue con la label `backlog` por el id del título, así que alguien puede ocupar el id de una tarea aún no creada (se vería en la PR de sincronización). | Abierto | Lectura |
| IR-2026-10-40 | CI | Informativa | El SBOM de Buzz (syft sobre una imagen de terceros) corre en el job `build` entre la construcción de keygen y su recolección. | Abierto: moverlo a otro job. | Lectura |
| IR-2026-10-41 | compose TLS (preexistente) | Informativa | `docker-compose.tls.yml` no anula los puertos de managed-signer (8084), notification-gateway (8086) ni indexer-2 (8091), aunque dice que solo Caddy publica puertos. | Abierto | Lectura |

Resumen (41 hallazgos): 3 altas (2 corregidas), 9 medias (6 corregidas), 17 bajas y 12 informativas (1 corregida).
No se encontraron hallazgos críticos. Igual que en la primera revisión, eso **no** equivale a «sin críticos».

## 3. Qué queda antes del tag de auditoría (SEC-11)

SEC-13 exige que cada hallazgo medio o superior esté corregido, o aceptado con un ADR, antes del tag. Por orden:

IR-2026-10-03 (Alta) e IR-2026-10-11 (Media) quedaron corregidos en la PR #393; IR-2026-10-09 (Media) en la #394;
IR-2026-10-12 (Media) en la #395. Lo que queda:

1. **IR-2026-10-05 y IR-2026-10-08 (Alta y Media):** separación de funciones del release. Hay que decidir entre la
   llave KMS ligada al entorno y el workflow reutilizable en un repo aparte (necesita un admin de la organización y,
   para la primera, AWS). Mientras tanto, el control en `verify-release.sh`. Lo mejor es registrar la decisión en un ADR.
2. **IR-2026-10-07 (Media):** la llave de la App en un entorno `bots` y el ruleset de tags. Es configuración de
   GitHub (admin), junto con OPS-12.
3. **IR-2026-10-10 (Media):** dispositivo fijado en el servidor. Hay que decidir cómo sabe el managed-signer qué
   dispositivos registró la organización para cada llave, y activar `MANAGED_SIGNER_REQUIRE_DEVICE_SESSION` en k8s.
4. Triar las alertas abiertas de CodeQL (primera ejecución de `security-extended`).
7. Los hallazgos bajos e informativos no bloquean el tag, pero entran en el paquete de SEC-01 y SEC-02 tal cual.

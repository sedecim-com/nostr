# Threat model · Continuity Vault (v0.1)

- **Estado:** Propuesto. Pendiente de la revisión de seguridad y de la aprobación de alguien distinto del
  autor, como los threat models por perfil (DEC-10).
- **Tareas:** VAULT-01, VAULT-02, VAULT-03, VAULT-07 · **Decisión:** [ADR 0011](../adr/0011-continuity-vault.md) ·
  **Fecha:** 2026-09-28

**Qué es.** `services/continuity-vault` guarda sobres de archivo sellados en el cliente para que el historial no
dependa solo de los relays.
- **Hoy.** La web y el CLI guardan el historial de cada persona (VAULT-03): los eventos canónicos de sus canales
  NIP-29, los gift wraps de sus DMs (los recibidos y la copia propia de los enviados), los mensajes Marmot ya
  descifrados, el estado MLS de sus grupos y el ledger de entrega. Un dispositivo limpio con el backup lo recupera
  aunque los relays lo hayan perdido.
- **VAULT-04 (S11).** Añade el estado `CONTINUITY_BACKED_UP` en el envío.

## Activos
- **El contenido de los archivos:** el historial de conversaciones, el estado MLS de los grupos y el ledger de
  entrega.
- **La llave de archivo de cada persona.** Abre todos sus archivos.
- **Los metadatos:** qué cuenta guarda archivos, cuántos y cuándo.
- **La disponibilidad del historial,** que es la razón de ser del vault.

## Adversarios relevantes
| Adversario | Capacidad supuesta |
|---|---|
| Operador del vault curioso | Lee la base, el object store y los logs; ve cada petición y su IP |
| Operador malicioso | Borra, reemplaza o sirve sobres antiguos |
| Quien roba la base o el object store | Copia offline de todo lo guardado |
| Quien obtiene un token de Acceso vinculado | Actúa como esa cuenta del vault (lista, descarga, borra) |
| Cliente con errores | Sube texto plano por equivocación |
| Abusador | Crea cuentas NIP-98 para ocupar espacio |

## Mitigaciones
| Riesgo | Mitigación | Evidencia |
|---|---|---|
| El operador lee el contenido | Sellado XChaCha20-Poly1305 en el cliente con una llave aleatoria de 256 bits que el servidor nunca recibe. La llave solo viaja dentro del backup de identidad, cifrada con la contraseña del usuario | `services/continuity-vault/test`: ni la base, ni el object store, ni los logs contienen el texto, el evento, su id, la npub, la nsec ni las etiquetas. Lo mismo en `apps/sovereign-client/test/vault.test.ts` y `vault-restore.test.ts`, `apps/web-saas/test/continuity.test.ts` y los E2E `web-saas` y `web-groups` (canal, DMs, mensajes de grupo y nombre del grupo) |
| Un archivo manipulado entra en el historial restaurado | Solo se acepta lo que abre con la llave, está guardado bajo el id que implica su contenido, tiene firma válida (eventos) y es de la persona (snapshots y mensajes); lo demás se cuenta como omitido | `services/continuity-vault/test/history.test.ts` |
| Un cliente sube texto plano por error | El validador compartido rechaza campos de más, una nsec o 64 dígitos hex, sobres cortos o sin relleno y un «ciphertext» legible. El servidor lo aplica venga del cliente que venga | `packages/continuity/test/continuity.test.ts`; `continuity-vault.test.ts` (peticiones directas) |
| Ligar la cuenta del vault a la persona | NIP-98 con una llave derivada de la llave de archivo, no con la de la persona; ids opacos (HMAC de una etiqueta) | Tests: la cuenta es `nostr:<llave derivada>`, distinta de la npub; ninguna etiqueta llega al servidor |
| Servir un archivo en lugar de otro | El AAD liga cada sobre a su `key_id` y a su id | Tests de intercambio de ids y de bytes alterados |
| Tamaño exacto de cada mensaje | Relleno al estilo NIP-44 con un mínimo de 256 bytes | Tests de relleno; el servidor rechaza sobres sin relleno |
| La llave de archivo es la nsec | Se rechaza al crearla y al restaurarla (web, CLI, backups) | `identity.test.ts`, `continuity.test.ts` de la web |
| Un backup con un coste scrypt enorme agota el dispositivo que lo restaura | Se rechaza un logN mayor que 20 antes de ejecutar scrypt; el generador offline no escribe más | `identity.test.ts` |
| Una persona Tor-only sale por clearnet | El CLI habla con el vault a través del guard de la persona: Tor o nada. La web no admite Tor-only | `apps/sovereign-client/test/vault.test.ts` |
| Abuso del almacenamiento | Cuotas por cuenta comprobadas con la fila bloqueada, límites de tasa y política NIP-98 `allowlist` u `off` | `continuity-vault.test.ts` (cuotas, 12 subidas simultáneas) |
| Inconsistencia entre la base y los objetos | Primero el objeto, después la fila. Un fallo deja objetos huérfanos, nunca filas sin objeto. Al descargar se comprueba el sha256 | `continuity-vault.test.ts` (reinicio, reemplazo sin huérfanos) |

## Riesgos residuales
| Riesgo | Nivel | Nota |
|---|---|---|
| Metadatos visibles al operador | Medio | Ve la cuenta, el número de archivos y su tamaño aproximado, las horas de subida, lectura y borrado, y la IP de cada conexión. Se declara en los textos del vault (VAULT-07, `docs/disclosures.md`) |
| Con Acceso, la cuenta es el usuario de Acceso | Medio | El operador liga los archivos a esa identidad; la cuenta NIP-98 derivada no lo hace |
| Versión antigua o borrado por el operador | Medio | El AEAD no detecta que se sirva una versión anterior del mismo id. Mitigación parcial (VAULT-03): restaurar nunca pisa el estado local más nuevo (el ledger se une por operación y el estado MLS solo se escribe sin grupos locales); cada snapshot sella su fecha y cuántos archivos tenía la cuenta, y la restauración dice de cuándo es la copia y avisa si faltan archivos (`history.test.ts`). Si el operador sirve un snapshot antiguo junto con sus archivos, en un dispositivo limpio solo lo delata la fecha |
| Mensajes de grupo fuera de MLS | Medio | El vault guarda los mensajes Marmot ya descifrados, sellados con la llave de archivo: con el backup, su contraseña y acceso a la cuenta del vault se lee ese historial, algo que MLS por sí solo no permite con llaves obtenidas después. El dispositivo ya los guarda así en su almacén local cifrado. Se declara (`CONTINUITY_VAULT_TEXTS.groups`) |
| Estado MLS copiado de otro dispositivo | Bajo | Restaurado, cada grupo es una copia de la hoja del dispositivo anterior y no puede enviar hasta entrar otra vez como hoja nueva (FR025-06): dos dispositivos nunca envían con la misma hoja. Los key packages privados no se guardan en el vault |
| Pérdida de la llave de archivo | Alto para la continuidad | Sin el backup y sin el dispositivo no hay forma de recuperarla; el operador tampoco puede. Se declara |
| Robo del backup de identidad | Medio | Fuerza bruta offline de NIP-49 (scrypt) contra la contraseña del backup; depende de su fortaleza |
| Cuentas NIP-98 ilimitadas con la política `open` | Bajo en self-hosted, Medio en SaaS | El SaaS usa `allowlist` u `off` |
| Copias de seguridad del operador | Bajo | Conservan metadatos y sobres cifrados hasta que caducan; la retención se documenta en VAULT-05 |
| El vault aún no participa en el envío | — | VAULT-04 (S11). Hasta entonces private-resilient no se declara GA |

## Supuestos
- XChaCha20-Poly1305, HKDF-SHA256, HMAC-SHA256 y scrypt (NIP-49) de `@noble` son correctos.
- El dispositivo del usuario no está comprometido: quien controla el cliente tiene la llave de archivo.
- La contraseña del backup es fuerte.

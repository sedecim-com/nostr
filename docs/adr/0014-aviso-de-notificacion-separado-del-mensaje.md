# ADR 0014 · Un aviso de notificación separado del mensaje

- **Estado:** Propuesto · **Tarea:** DEC-13 (#297) · **Fecha:** 2026-09-30
- **Aprobación:** pendiente (responsable de producto). No bloquea el RC: solo se retoma con un cliente móvil (ADR 0004).

## Contexto
El [ADR 0010](0010-notificaciones-push-por-perfil.md) fijó el push opaco por perfil y OPS-06 lo dejó detrás de un flag
por relay. El gateway vigila la llegada de gift wraps (kind 1059) a los npubs registrados y solo acepta registros en
relays donde puede hacerlo. Con los relays de referencia no puede: Buzz y el secure relay (nostr-rs-relay con
`nip42_dms`) entregan los gift wraps solo a su destinatario autenticado. Por eso, con el stack de referencia, no hay
push web.

La pregunta de DEC-13 es si el aviso podría ser un evento aparte, separado del mensaje, de modo que «hay actividad
para X» no dependa de que el gateway lea el gift wrap. El PRD (epic G) lo deja para cuando se retome un cliente móvil.

## Lo que cualquier solución debe cumplir
Son las reglas del ADR 0010, que este ADR no cambia:
- El gateway nunca lee DMs ni recibe metadatos que el relay no le daría ya.
- El aviso es opaco: sin contenido, remitente ni recuento.
- Sovereign y Tor siguen sin push (polling local).
- El mensaje nunca pasa por el aviso: si el aviso falla, el mensaje llega igual.

## Opciones
1. **Observar el gift wrap (hoy, ADR 0010).** El gateway pide al relay los wraps de los npubs registrados.
   - Contras: solo sirve en relays que entregan wraps ajenos al gateway, que es justo lo que los relays de
     referencia evitan a propósito.
2. **Aviso publicado por el remitente y cifrado al gateway.** Tras enviar, el cliente del remitente publica un
   evento aparte: clave desechable, `p` = clave del gateway, contenido NIP-44 al gateway con el destinatario a
   despertar. El gateway lo lee porque es para él, sin pedir nada del destinatario al relay.
   - Pros: no exige que el relay entregue wraps ajenos; el mensaje y el aviso son independientes.
   - Contras:
     - El remitente tiene que saber qué gateway usa el destinatario. Eso obliga a que el destinatario publique
       «este npub recibe avisos por el gateway G», un dato público que hoy no existe y que dice quién usa push y con
       qué operador.
     - Cada mensaje publica un segundo evento: el gateway ve el par (destinatario, hora) y el relay ve un evento
       extra dirigido al gateway. El remitente real queda oculto solo si la clave es desechable.
     - Depende de que todos los clientes remitentes lo implementen. Uno que no lo haga no dispara aviso, y el
       destinatario no puede saber por qué.
     - Cualquiera puede publicar avisos falsos para despertar a una persona: hace falta un límite (solo de
       contactos, prueba de trabajo o fichas).
3. **Push del propio relay (NIP-PL de Buzz).** El relay guarda un filtro firmado y es él quien despierta la
   instalación. En v1 solo es conforme el perfil APNs con App Attest (FCM y UnifiedPush aún no) y no hay Web Push.
   Cada aviso es una señal constante de «reconectar».
   - Pros: el relay ya ve los mensajes, así que no entra un observador nuevo ni un operador de gateway.
   - Contras: solo nativo iOS por ahora, y ata el push a un relay concreto.
4. **Sin push (polling local).** Es lo que hacen sovereign y Tor. Sin cambios.

## Decisión (propuesta)
**No construir ahora el aviso separado.**
- Hoy se mantiene la opción 1 con el flag por relay (OPS-06). Sin cambios de código.
- Al retomar un cliente móvil: iOS usa la opción 3 (NIP-PL); el resto queda en la opción 4.
- La opción 2 se reevalúa solo si aparece un relay sin push propio que el producto deba soportar. Si se construye,
  con estas condiciones mínimas:
  1. clave desechable por aviso y contenido cifrado al gateway, constante;
  2. el destino de los avisos se publica solo por elección explícita de la persona, nunca por defecto, con el aviso
     de consecuencias en el panel;
  3. límite contra avisos falsos;
  4. fuera de sovereign y Tor;
  5. el gateway sigue sin persistir nada (ADR 0010).

### Qué ve cada parte si se construyera la opción 2
| Parte | Qué ve de más que hoy |
|---|---|
| Gateway | Por cada mensaje, el destinatario a despertar y la hora, sin el remitente real. Hoy ve lo mismo al vigilar el wrap, pero solo donde el relay se lo entrega. |
| Relay | Un evento extra por mensaje, con `p` = gateway, publicado con una clave desechable. |
| Público | Quién publica un destino de avisos y con qué gateway. Es un dato nuevo y permanente: por eso debe ser opt-in. |
| Remitente | Una publicación más por mensaje y la obligación de conocer el gateway del destinatario. |

## Consecuencias
- Sin código ni cambios de textos: el ADR fija por qué no se construye y con qué condiciones se reabriría.
- Se reabre al retomar el cliente móvil, o si un despliegue necesita push web con un relay que no entrega gift wraps
  ajenos.
- Al aprobarse, DEC-13 pasa a Hecho.

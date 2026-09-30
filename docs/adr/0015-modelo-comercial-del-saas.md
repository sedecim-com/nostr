# ADR 0015 · Modelo comercial del SaaS: organizaciones, planes y facturación

- **Estado:** Propuesto · **Tarea:** DEC-14 (#292) · **Fecha:** 2026-09-30
- **Aprobación:** pendiente (Dirección). Las decisiones de negocio están marcadas «Por decidir»: este documento no las toma.

## Contexto
El scope (§15.2) dejó fuera del programa de cierre las organizaciones, los planes y la facturación del SaaS. OPS-15
(#293) las construiría después de v1.0 y necesita este modelo antes de empezar. Lo que hay hoy:

- **Un despliegue es una organización.** El policy-engine guarda sujetos, recursos, dispositivos y políticas sin
  identificador de organización (`services/policy-engine/migrations/001_policy.sql`). El perfil institucional
  funciona como «un despliegue por organización».
- **Las cuentas son personas.** Las cuentas de Acceso (Cognito, [ADR 0008](0008-login-acceso-en-saas.md)) y las
  personas del identity-service cuelgan de una cuenta, no de una organización.
- **Buzz es multi-tenant por cabecera `Host`** (`docs/buzz-integration.md`): una comunidad por host.
- **No hay ningún dato de cobro** en el sistema.

## Lo que el producto ya fija (no se negocia aquí)
1. **El cobro no se une a las personas.** Quien paga es una organización o una cuenta de Acceso, nunca un pubkey. Los
   datos de facturación no llegan a los relays, al indexer ni a los logs (NFR-006).
2. **Sovereign y Tor siguen sin cuenta ni cobro.** El SaaS es una conveniencia, no una puerta.
3. **La custodia managed** vive en us-east-1 bajo la LFPDPPP ([ADR 0009](0009-custodia-managed-region-y-marco-legal.md)).
   El cobro y su aviso de privacidad tienen que ser coherentes con esos términos.
4. **Salir nunca se bloquea.** Quien deja de pagar puede exportar o cancelar su llave gestionada (FR026-04).
5. **Nada se vende como más seguro de lo que está auditado** (etiquetas de madurez, PANEL-07 y REL-04).

## Opciones técnicas
| Opción | Qué es | Pros | Contras |
|---|---|---|---|
| A. Un despliegue por organización (hoy) | Cada cliente tiene su stack. | Aislamiento máximo; nada nuevo que construir. | Coste operativo por cliente; no hay alta self-service ni planes. |
| B. Tenants lógicos en un despliegue compartido | `organization_id` en identity, policy y managed-signer; una comunidad (host) de Buzz por tenant. | Alta self-service; un solo stack que operar. | El aislamiento pasa a ser un invariante de código: cada consulta filtra por tenant. Migra las tablas y abre el riesgo de fugas entre tenants. |
| C. B para el resto e institucionales en despliegue propio (A) | Dos modos. | Aislamiento fuerte donde lo pide el perfil institucional. | Dos modos que mantener y probar. |

## Por decidir (Dirección)
1. **Quién paga:** la organización, la persona, o ambas.
2. **Planes y límites:** qué planes existen y qué acota cada uno (personas, espacio del Continuity Vault, relays,
   retención de auditoría, SLO de NFR-001). Este ADR no fija precios ni límites.
3. **Proveedor de cobro y de facturación electrónica.** En México la factura es el CFDI: a confirmar con asesoría
   fiscal. Criterios para evaluar: emite o se integra con CFDI, cobra en MXN, el pago se aloja en el proveedor (el
   sistema no toca datos de tarjeta), webhooks firmados, exportación de datos.
4. **Qué pasa al dejar de pagar:** congelar, solo lectura, o exportar y borrar. Siempre con la regla 4 de arriba.
5. **Plan gratuito o prueba** para el perfil convenience.

## Recomendación técnica (solo técnica)
Si Dirección aprueba vender planes self-service:
- Modelo B para convenience y C para institucional.
- `organization_id` entra primero en identity y policy (OPS-15). El cobro es un servicio aparte que solo conoce
  (`organization_id`, plan, estado), sin pubkeys ni contenido.
- Un test de aislamiento entre tenants como gate de cada tabla con `organization_id`, antes de aceptar la primera
  organización.

## Consecuencias
- Sin código ni cambios de textos.
- Al aprobarse con las decisiones de arriba, OPS-15 (#293) se desbloquea con el modelo elegido y DEC-14 pasa a Hecho.

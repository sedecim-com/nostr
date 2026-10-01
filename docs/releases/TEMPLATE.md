# Acceso Nostr {{vX.Y.Z}}

<!--
Plantilla de notas de release (REL-02). Copia este archivo a docs/releases/<tag>.md en la PR que prepara
el release. release.yml usa ese archivo como cuerpo del GitHub Release y se detiene si falta, si no tiene la
sección "Cambios en el modelo de confianza" con sus cinco subsecciones rellenas o si quedan marcadores {{…}}.
Si una subsección no cambia, escribe "Sin cambios." (no la borres). Los comentarios HTML no cuentan como
contenido. `npm run lint:claims` revisa también este directorio: nada de afirmaciones absolutas de
privacidad; describe lo que se verifica y cómo.
-->

Fecha: {{AAAA-MM-DD}} · Commit: {{sha corto}} · Estado: {{early release / estable}}

## Resumen

{{Dos o tres frases: para quién es este release y qué cambia para quien lo despliega o lo usa.}}

## Novedades

- {{Cambio visible, con el requisito (FR/NFR) o la PR.}}

## Madurez por perfil y función

<!-- maturity:start (scripts/maturity.ts desde packages/profiles/src/maturity.ts; no editar a mano) -->
| Perfil o función | Tipo | Hoy | Por qué | En v1.0 |
|---|---|---|---|---|
| convenience (SaaS) | Perfil | Early release | Sin revisión externa ni stage en AWS todavía. | GA controlado, con SEC-01, SEC-02, el stage y la release firmada. |
| private-resilient | Perfil | Early release | Sin revisión externa. Sin Continuity Vault en el despliegue, el historial depende de los relays y el perfil queda en Beta. | GA controlado, solo con el Continuity Vault. |
| institutional | Perfil | Early release | Sin pentest sobre stage todavía. | GA controlado, con el pentest sobre stage y la auditoría. |
| sovereign (self-hosted) | Perfil | Early release | Todavía no hay una release firmada. | GA técnico, con la release firmada, la instalación reproducible y el restore drill. |
| sovereign-tor | Perfil | Experimental | Falla cerrado y tiene pruebas de fugas propias, pero ni el cliente ni sus dependencias tienen revisión independiente. | Experimental: nada lo declara apto para alto riesgo sin una auditoría específica y un cliente dedicado. |
| DMs NIP-17 | Función | Early release | Solo se habilitan con el gate de interoperabilidad contra el Buzz fijado en verde. No ofrecen forward secrecy. | Con el perfil que los usa, y siempre detrás del gate de interoperabilidad. |
| Grupos Marmot/MLS | Función | Beta | marmot-ts es alpha y ts-mls está en release candidate. | Beta mientras marmot-ts o ts-mls sean alpha o release candidate. |
| Continuity Vault | Función | Early release | Falta aprobar su threat model (VAULT-07) y la revisión externa. | Con private-resilient. |
| Custodia gestionada básica | Función | Early release | Espera la aprobación legal (DEC-12) y la validación en AWS; el gate de release no la deja en producción. | GA opcional, con la aprobación legal y KMS y Secrets Manager reales. |
| Custodia en Nitro Enclave | Función | Preview | Prototipo: la attestation solo se verificó en local, y va apagada en producción. | Preview: EIF, PCR, attestation y KMS reales más auditoría. |
| Notificaciones push | Función | Experimental | Con Buzz y el secure relay, el gateway no puede ver la actividad sin leer DMs, así que no se ofrecen. | Experimental, detrás de un flag. |
| Estado de presencia (NIP-38) | Función | Experimental | Solo en la web y apagado salvo que la persona lo active. No está probado contra el Buzz fijado: el gate de interoperabilidad registra si acepta el kind 30315, sin exigirlo. | Fuera del programa de v1.0: sigue Experimental. |
<!-- maturity:end -->

## Cambios en el modelo de confianza

<!-- Obligatoria. Responde a "¿en quién confío ahora y qué puede hacer?" frente al release anterior. -->

### Custodia de llaves

{{Modos de custodia añadidos o cambiados; quién puede firmar como el usuario; dónde viven las llaves.}}

### Qué puede ver y hacer el operador

{{Metadatos, contenido o acciones nuevas al alcance del operador (relay, mirror, gateways, managed signer).}}

### Dependencias criptográficas y su estabilidad

{{Versión fijada y estado upstream (alpha, rc, estable) de cada librería criptográfica que cambió.}}

### Datos nuevos que se recopilan

{{Campos, logs o telemetría nuevos; retención; quién los ve.}}

### Valores por defecto que cambian

{{Presets o ajustes cuyo valor por defecto cambia, y su consecuencia.}}

## Verificación

Firmas cosign keyless, provenance SLSA y SBOM: `sh scripts/verify-release.sh {{vX.Y.Z}}`
([docs/building.md](../building.md)). Imágenes reconstruibles bit a bit:
`sh scripts/rebuild-image.sh {{vX.Y.Z}} <servicio>`.

## Limitaciones conocidas

- {{Lo que no está listo o no se ha verificado.}}

## Auditorías de seguridad

{{Informes en docs/security/audits/ o waiver aprobado en docs/security/audits/waivers/ para este tag.}}

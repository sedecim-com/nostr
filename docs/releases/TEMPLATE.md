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

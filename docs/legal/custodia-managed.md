# Términos de custodia managed · Acceso Nostr (BORRADOR)

> Estado: **borrador para revisión legal** (DEC-09, FR028-02). No publicar hasta su aprobación, que se registra
> en [`approvals/custodia-managed.md`](approvals/custodia-managed.md) (DEC-12).
> Marco: Ley Federal de Protección de Datos Personales en Posesión de los Particulares (LFPDPPP, México).

## 1. Qué es la custodia managed
Es un modo **opcional**. Sedecim guarda tu llave privada Nostr cifrada y firma en tu nombre cuando tú
lo pides desde la aplicación, autenticado con tu cuenta de Acceso. **Es un modo custodial: la
plataforma tiene la capacidad técnica de firmar como tú.** Puedes salir de él en cualquier momento
exportando tu llave (migración a custodia local).

## 2. Dónde y cómo se guarda
- La llave se guarda en Amazon Web Services, región `us-east-1` (Virginia, EE. UU.).
- La llave está cifrada con una llave de AWS KMS de uso exclusivo y solo se descifra en memoria para cada operación.
- El personal de Sedecim no tiene acceso a la llave en claro. El acceso administrativo a KMS y Secrets Manager se registra en AWS CloudTrail.

## 3. Datos que se tratan
| Dato | Finalidad | Conservación |
|---|---|---|
| Llave privada cifrada | Firmar en tu nombre cuando lo pides | Mientras uses el modo; 30 días tras borrarla |
| Identificador de tu cuenta de Acceso (issuer y sub) | Autorizar que solo tú uses tu llave | Mientras exista la llave |
| Log de uso (llave, fecha, kind firmado, cliente) | Seguridad, auditoría y atención de incidentes | 12 meses |
| Versión de los textos y términos que aceptaste, y la fecha | Demostrar tu consentimiento expreso para el modo custodial | Mientras exista la llave |

**No se guardan** el contenido de tus mensajes cifrados ni tu contraseña local. Pero tus mensajes directos
(NIP-44) **se cifran y descifran en el servidor de firma** cada vez que los envías o los lees: el servicio ve su
contenido en claro en memoria mientras lo procesa.

## 4. Tus derechos (ARCO)
Puedes acceder, rectificar, cancelar u oponerte al tratamiento escribiendo a [contacto de privacidad de
Sedecim]. La cancelación también la puedes hacer tú desde la aplicación (sección 6). Cancelar implica borrar la
llave: deja de firmar en ese momento y, pasados 30 días, se destruye y no se puede recuperar, así que exporta un
respaldo antes. Al destruirse la llave se borran también el identificador de tu cuenta de Acceso y la versión de
los textos que aceptaste; el log de uso se conserva hasta cumplir sus 12 meses.

## 5. Transferencias
AWS actúa como encargado del tratamiento (infraestructura) en EE. UU. No se transfieren datos a
terceros con fines distintos.

## 6. Salida del modo managed
Para seguir usando tu identidad con tu propia llave (migración a custodia local):
1. Exporta tu llave desde la aplicación.
2. La aplicación comprueba que la tienes: firma un reto con la llave exportada.
3. Confirma el borrado.
4. El material cifrado se destruye a los 30 días.

Para dejar la custodia sin migrar (cancelación):
1. Descarga el respaldo cifrado de tu llave con una contraseña que elijas. La aplicación comprueba que es tu llave.
2. Confirma escribiendo el final de tu npub. La llave deja de firmar en todos tus dispositivos.
3. Mientras dura la ventana de 30 días, la aplicación te muestra la fecha en que se destruirá. Después se destruye.

## Consentimiento
La aplicación muestra, antes de crear la llave, los textos revisados de `docs/disclosures.md` (custodia managed y
su consentimiento) y un enlace a estos términos. Aceptarlos es un acto expreso: la llave no se crea sin él. El
servicio de firma guarda con la llave la versión de lo aceptado (por ejemplo, `textos 1.3.0; términos 2026-10`)
y la fecha, y rechaza crear o importar una llave sin esa versión.

## Pendiente de legal
- Identidad y domicilio del responsable, contacto del departamento de datos personales.
- Redacción final del aviso de privacidad integral y del consentimiento expreso para el modo custodial.

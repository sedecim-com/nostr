# Términos de custodia managed · Acceso Nostr (BORRADOR)

> Estado: **borrador para revisión legal** (DEC-09, FR028-02). No publicar hasta su aprobación.
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

**No se guardan** el contenido de tus mensajes cifrados ni tu contraseña local.

## 4. Tus derechos (ARCO)
Puedes acceder, rectificar, cancelar u oponerte al tratamiento escribiendo a [contacto de privacidad de
Sedecim]. Cancelar implica borrar la llave. Pasados 30 días no se puede recuperar, así que exporta un
respaldo antes.

## 5. Transferencias
AWS actúa como encargado del tratamiento (infraestructura) en EE. UU. No se transfieren datos a
terceros con fines distintos.

## 6. Salida del modo managed
1. Exporta tu llave desde la aplicación.
2. La aplicación comprueba que la tienes: firma un reto con la llave exportada.
3. Confirma el borrado.
4. El material cifrado se destruye a los 30 días.

## Pendiente de legal
- Identidad y domicilio del responsable, contacto del departamento de datos personales.
- Redacción final del aviso de privacidad integral y del consentimiento expreso para el modo custodial.

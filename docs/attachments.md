# Adjuntos: tamaño, tipo y antivirus (FR018-06)

Qué puede pesar un adjunto, qué tipos se aceptan y qué se hace —y qué no— contra el malware, sin romper la
confidencialidad. Lo que dice este documento lo comprueban las pruebas citadas; lo que no hace el producto está dicho
aparte, en «Lo que no hace».

## Tamaño

El cliente (la web y el CLI) mide el archivo **antes de leerlo en memoria**, porque lo tiene entero en memoria en cada
paso: leerlo, quitarle los metadatos, cifrarlo, calcular su hash y subirlo. Un archivo que pasa del límite de su destino
se rechaza con un mensaje que dice cuánto pesa y cuánto se permite, antes de hacer cualquier otra cosa: sin calcular
nada, sin preguntar por la reutilización del archivo entre personas (FR006-07), sin conectar a ningún servidor.

| Destino | Límite | Dónde se comprueba |
|---|---:|---|
| Adjunto de un mensaje directo (cifrado en el cliente) | 25 MB | web (`DmView`), `prepareBlob` |
| Media de un grupo seguro (MIP-04, cifrada) | 25 MB | CLI (`group send-file`, antes de leer el archivo y de nuevo al enviarlo) |
| Imagen de un canal (en claro para sus miembros y el operador) | 10 MB | web (`ChannelsView`), `prepareBlob` |
| Avatar del perfil público | 1 MB | web (`Profile`, antes de leer el archivo, y `uploadAvatar`) |

1 MB son 1 000 000 bytes (los que ve el usuario). Los límites están en `packages/blossom-client/src/policy.ts`
(`MAX_ATTACHMENT_BYTES`) y `prepareBlob` los aplica a cualquier archivo que prepara (por defecto, el de mensajes
directos) aunque quien lo llame no haya comprobado antes.

**Por qué estos números.** Son más bajos que los topes de los servidores, para que un archivo que el cliente acepta sea
uno que los servidores toman: el blob-store acepta 50 MiB por defecto (`BLOB_MAX_BYTES`, `services/blob-store`), y Buzz
tiene topes propios en `/media` (en el código de Buzz, `buzz@b0d6fb8`, la última versión que se puede leer aquí: 50 MiB
una imagen, 500 MiB un vídeo y 100 MiB cualquier otro archivo; el pin fijado es posterior y su valor real lo fija el
operador). Y por la memoria: un navegador de móvil no debería cargar, descifrar y volver a cifrar un archivo de cientos
de megas. Un despliegue con otro tope en sus servidores no cambia el del cliente: el más bajo de los dos manda.

**Al descargar**, el cliente tampoco abre un blob de más de 26 MB (`MAX_DOWNLOAD_BYTES`: el mayor adjunto que se puede
subir más lo que añade el cifrado). Deja de leer en cuanto sabe que se pasa, por la longitud que declara el servidor y, si
no la declara, en cuanto el cuerpo lleva más de lo permitido: lo hacen `fetch` (la web) y `NetworkGuard.fetch` (el CLI,
también por Tor). Cualquier otro transporte que se le pase al cliente recibe el cuerpo entero y la comprobación llega
después, pero antes de calcular su hash o de descifrarlo. Una imagen de canal de más de 26 MB que subió otro cliente
(Buzz admite más) no se muestra aquí, y el cliente lo dice.

## Tipo (MIME)

- **El tipo que dice el remitente no decide nada de seguridad.** El saneador (FR019) reconoce el formato por el
  **contenido** del archivo (JPEG, PNG, WebP, y detecta los que no sabe limpiar, como HEIC o TIFF); el tipo que declara un
  servidor o un nombre de archivo se usa solo para mostrar.
- **Mensajes directos y grupos**: cualquier tipo de archivo, cifrado antes de subirlo, así que el servidor no ve ni el
  tipo (se sube como `application/octet-stream`). Con la opción de quitar metadatos (`stripFileMetadata`), una imagen cuyo
  formato no se puede limpiar se rechaza antes de subir nada; un documento de otro tipo sale tal cual, con los
  metadatos que lleve, y eso está dicho en los textos del panel.
- **Canales**: solo imágenes (el selector de la web pide `image/*`), sin metadatos y en claro para el canal.
- **Al recibir** un adjunto, la web no lo ejecuta ni lo previsualiza si no es una imagen de canal ya verificada: lo
  descarga, comprueba el hash **antes** de descifrar, y lo ofrece como archivo local con un nombre neutro
  (`adjunto-<hash>`) y sin extensión, para que el sistema no lo abra solo con el programa de su tipo.

## Antivirus

**Lo que no hace el producto: no analiza los archivos en busca de malware.** No hay un escáner en el servidor ni en el
cliente, y no es un descuido: en los mensajes directos y los grupos seguros el archivo llega cifrado y el servidor no lo
puede leer, así que analizarlo allí exigiría que el servidor lo descifrara (la confidencialidad que el producto promete)
o que recibiera la llave (también). Tampoco se analizan las imágenes de los canales, que el operador sí puede leer:
ninguna parte del código lo hace hoy.

Lo que sí limita el daño, y las pruebas lo comprueban:

1. **Nada se abre solo**: ni se ejecuta, ni se previsualiza (salvo las imágenes de canal, que el navegador decodifica
   desde un `blob:` después de comprobar su hash y su tamaño).
2. **Hash antes de descifrar y de abrir**: el contenido que llega es el que se anunció, o no se abre.
3. **Tamaño acotado** (arriba), para que un archivo enorme no agote la memoria del navegador o del CLI.
4. **Sin metadatos** en lo que sale (FR019), con la excepción dicha arriba para documentos que no se pueden limpiar.

**Qué puede hacer cada operador, sin romper nada.** Quien despliegue y quiera análisis de malware puede escanear en
**su** borde lo que sí puede leer (las imágenes de los canales, en `/media`), o pedir a los usuarios que analicen lo
que descargan con su propio sistema, que es lo único que ve el archivo descifrado. Quedan fuera del producto hasta que
haya un diseño que no obligue a elegir entre escanear y cifrar (un escáner en el dispositivo del destinatario, por
ejemplo): es una decisión de producto, no una promesa pendiente de código.

## Pruebas

- `packages/blossom-client/test/policy.test.ts`: los límites, el mensaje, `prepareBlob` (25 MB por defecto y 10 MB para una
  imagen de canal), la descarga acotada y `fetchHttpClient` contra un servidor real (longitud declarada, cuerpo sin
  longitud y cuerpo que cabe).
- `packages/tor-network/test/fetch-limit.test.ts`: lo mismo para `NetworkGuard.fetch`, la ruta del CLI.
- `apps/sovereign-client/test/attachments.test.ts`: un archivo de grupo de más de 25 MB se rechaza sin tocar el relay ni
  el servidor de archivos, y el CLI mide el archivo antes de leerlo.

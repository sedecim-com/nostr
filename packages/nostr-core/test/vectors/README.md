# Vectores de prueba criptográficos

Vectores en JSON para que un cliente en otro lenguaje (el núcleo Rust y la capa Flutter del [ADR 0004](../../../../docs/adr/0004-bibliotecas-nostr-rust-flutter.md)) compruebe que cifra, descifra y valida igual que el SDK en TypeScript (SEC-07). Todas las llaves son de prueba: no protegen nada.

| Archivo | Origen | Qué comprueba el SDK |
|---|---|---|
| `nip44.vectors.json` | Oficial, de [paulmillr/nip44](https://github.com/paulmillr/nip44). El test compara su SHA-256 con el publicado en NIP-44 (`269ed0f6…5040`) | [`nip44-vectors.test.ts`](../nip44-vectors.test.ts): llaves de conversación y de mensaje, padding, cifrado y descifrado en ambos sentidos, mensajes largos y todos los casos inválidos |
| `nip49.vectors.json` | Propio, más el vector publicado en NIP-49 | [`nip49-vectors.test.ts`](../nip49-vectors.test.ts) |
| `nip59.vectors.json` | Propio | [`packages/messaging/test/nip59-vectors.test.ts`](../../../messaging/test/nip59-vectors.test.ts) |

## Cómo se generan

Los vectores propios los escribe [`generate.ts`](generate.ts):

```sh
npx tsx packages/nostr-core/test/vectors/generate.ts           # reescribe nip49 y nip59
npx tsx packages/nostr-core/test/vectors/generate.ts --check   # falla si un archivo no coincide
```

La generación es determinista:

- Cada llave, sal, nonce y valor auxiliar de firma es `sha256("acceso-nostr/vectors/<etiqueta>")`, recortado a la longitud que toque. Por eso los archivos se pueden reproducir y sirven para probar también el cifrado.
- `generate.ts` construye los payloads con las primitivas de `@noble` (scrypt, XChaCha20-Poly1305, Schnorr con `auxRand` fijo), no con las funciones del SDK que se prueban. Del SDK solo usa el cifrado NIP-44, ya cubierto por los vectores oficiales, el hash del evento y la derivación de la llave pública.

Un test compara los archivos con lo que escribe el generador, así que no pueden desviarse sin que CI lo note.

## Formato

**NIP-49** (`nip49.vectors.json`):

- `official`: el vector publicado en NIP-49. Con `password` y `log_n` 16 abre la llave `sec`.
- `normalization`: el ejemplo de NIP-49. `password_utf8` pasa a `password_nfkc_utf8` con NFKC antes de scrypt.
- `valid`: cada caso tiene `sec`, `password`, `password_nfkc_utf8`, `log_n`, `key_security`, `salt` (16 bytes), `nonce` (24 bytes) y el `ncryptsec` resultante.
  - Para probar el cifrado: scrypt(NFKC(password), salt, N = 2^log_n, r = 8, p = 1, 32 bytes) y luego XChaCha20-Poly1305(nonce, AAD = byte `key_security`). Con eso se reconstruye `ncryptsec`.
  - Para probar el descifrado: `ncryptsec` con `password` da `sec`, y también con la contraseña ya normalizada.
- `invalid`: cada `ncryptsec` con su `password` debe rechazarse.
  - Los motivos: contraseña errónea, ciphertext alterado, byte de key security alterado (es la AAD) y versión no soportada.
  - Con `max_log_n`, el lector debe rechazarlo antes de ejecutar scrypt.

**NIP-59** (`nip59.vectors.json`):

- `valid`: desenvolver `wrap` con `recipient_sec` debe dar exactamente `seal` y `rumor`, y el remitente autenticado es `sender_pub` (el firmante del seal, igual al autor del rumor).
  - `wrap_conversation_key` y `seal_conversation_key` son las llaves NIP-44 intermedias, para depurar.
  - El segundo caso es la copia que el emisor se envuelve a sí mismo.
- `invalid`: cada `wrap` debe rechazarse con `recipient_sec`. `note` dice por qué:
  - destinatario equivocado;
  - firma del wrap que no verifica;
  - seal que no es kind 13;
  - seal firmado por alguien distinto del autor del rumor (suplantación);
  - rumor editado después de calcular su id.

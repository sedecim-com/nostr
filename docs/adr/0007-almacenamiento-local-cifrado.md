# ADR 0007 · Almacenamiento local cifrado por plataforma y perfil

- **Estado:** Aceptado · **Tarea:** DEC-05 (P1) · **Fecha:** 2026-09-26
- **Aprobación:** responsable de producto (vic2099), 2026-09-26

## Contexto
El cliente guarda llaves, outbox y configuración en el dispositivo (§12). La v0.1 de la web usaba
`localStorage` con un store protegido por contraseña. El responsable pidió que la solución fuera
congruente con el sistema Acceso de Sedecim. La revisión de `acceso-frontend`, `acceso-backend` y
`authentication-server-api` dio este resultado:
- Acceso no cifra nada en el cliente.
- Los tokens de Cognito viven en cookies de `.acce.so` que el JavaScript puede leer (Amplify `CookieStorage`).
- `localStorage` solo guarda preferencias de UI.
- No hay precedente para guardar una llave privada, así que esta decisión lo crea.
- De Acceso se adopta lo que sí aplica: preferencias en `localStorage`, cierre de sesión entre pestañas con `BroadcastChannel('auth')` y el stack React 19 + MUI 7 + Vite.

## Decisión
**Vault local** (`packages/encrypted-store`, `Vault`):
- Una llave maestra aleatoria abre el `EncryptedStore`, que cifra los valores con XChaCha20-Poly1305 y aplica HMAC a los nombres.
- La llave maestra se envuelve de una de dos formas:
  - **Contraseña**: scrypt, con logN 15 en la web para un desbloqueo interactivo.
  - **Llave del dispositivo**: una llave AES-GCM de WebCrypto **no extraíble**, guardada en IndexedDB.
- Cambiar de protección solo vuelve a envolver la llave maestra; los registros no se recifran.

| Plataforma | Backend | Protección |
|---|---|---|
| Web | IndexedDB (`IndexedDBBackend`, una base `acceso-nostr` por navegador) | Contraseña, o llave del dispositivo solo en el perfil convenience |
| CLI / servicios | Archivo con escritura atómica (`FileBackend`) | Contraseña |
| Desktop / móvil (cuando existan, ADR 0004) | Archivo cifrado / Keychain / Keystore | A definir con la app nativa |

**Regla por perfil** (control `localProtection` del panel, validado en `profiles`):
- `device` solo es válido con custodia local, red directa e identidad vinculada, es decir, en el perfil convenience.
- Soberano, Tor, institucional y private-resilient exigen contraseña.
- La web solo abre el vault sin contraseña si **todas** las personas eligieron `device`.
- Crear una persona con un perfil más estricto obliga a poner contraseña antes.

**La llave de la persona**:
- Se guarda dentro del vault sellado, nunca en claro.
- El backup se exporta como NIP-49 con una contraseña elegida en ese momento.
- La web importa automáticamente la llave de la v0.1 si se usa la misma contraseña.

## Consecuencias
- Con la llave del dispositivo, cualquiera con acceso al perfil del navegador abre las llaves. El panel lo declara (disclosure y aviso `DEVICE_KEY`).
- Borrar los datos del sitio o la llave del dispositivo hace irrecuperable el vault sin backup. Hay una acción "Olvidar este navegador" para hacerlo de forma deliberada.
- La E2E de navegador comprueba que IndexedDB solo contiene registros sellados y que la nsec no aparece en ninguna petición ni frame WebSocket (FR001-05).

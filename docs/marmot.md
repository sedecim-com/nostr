# Grupos high-security: Marmot / MLS (spec §10.3, FR-025)

## Proveedor
`packages/marmot-adapter` expone `GroupCryptoProvider` → `GroupSession` (sesión por identidad y
dispositivo). La implementación por defecto es `MarmotTsProvider`:

| Componente | Versión fijada | Licencia | Nota |
|---|---|---|---|
| `@internet-privacy/marmot-ts` | 0.5.1 | MIT | Implementación TS del proyecto Marmot (MIP-00…03). Upstream: **alpha** |
| `ts-mls` | **2.0.0-rc.11** (override) | MIT | RFC 9420. marmot-ts 0.5.1 pide rc.10, que es vulnerable (ver abajo) |

Kinds: key package `30443` (lee también el legado `443`), Welcome `444` dentro de gift wrap `1059`,
mensajes de grupo `445` (firmante efímero por mensaje, tag `h` = id Nostr del grupo), lista de relays
`10051`. Ciphersuite por defecto `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.

## Garantías verificadas por tests
`runConformance` (en `packages/marmot-adapter` y `apps/sovereign-client`), contra relay en memoria,
relay autenticado con compuerta `#p` y relay `.onion` vía SOCKS:
- alta de miembros por key package + Welcome, mensajes descifrables por los miembros;
- **expulsión**: el expulsado no descifra mensajes posteriores (secreto post-expulsión);
- **self-update** (`rotate`): avanza la época → post-compromise security; el grupo sigue operativo;
- relays solo ven ciphertext; el estado MLS (claves privadas, árbol) se guarda **cifrado** en el
  `encrypted-store` de la persona (XChaCha20-Poly1305, nombres HMAC) y sobrevive reinicios;
- compartimentación: no se puede invitar a otra identidad high-risk propia.

## Vulnerabilidad encontrada y mitigada (ts-mls ≤ 2.0.0-rc.10)
`ts-mls` rc.10 solo exigía `UpdatePath` en commits con **más de una** propuesta Update/Remove.
Un commit con un único Remove salía sin path, `commit_secret` = 0 y el miembro expulsado podía derivar
la época siguiente y leer mensajes posteriores (viola RFC 9420 §12.4). Corregido upstream en rc.11.
Mitigación en este repo:
1. `overrides` en `package.json` fuerza `ts-mls@2.0.0-rc.11` para marmot-ts;
2. **autoprueba de comportamiento** (`assertRemovalSecrecy`) al abrir la primera sesión del proceso:
   crea un grupo en memoria, expulsa a un miembro y comprueba que no descifra. Si falla, el proveedor
   **falla cerrado** (`UnsafeMlsImplementationError`). Verificado: falla con rc.10, pasa con rc.11.

## Integración con Buzz: no soportado por el relay fijado
El Buzz fijado (`02c6309`) tiene una lista cerrada de kinds y responde
`restricted: unknown event kind` a 30443, 445 y 10051 (`docs/interop/`). Por eso los grupos Marmot
van por el **relay secundario** del stack (`secure-relay`: nostr-rs-relay 0.9.0 fijado por digest,
NIP-42 obligatorio, gift wraps solo al destinatario, también publicado como onion service).
Incluye su URL en los relays de la persona (`--relay ws://localhost:7000`); la política de red de la
persona (Tor-only, allowlist) se aplica también al tráfico MLS.

Alternativa pendiente de decisión: parchear el fork de Buzz para aceptar 30443/445/10051 (y 444 dentro
de 1059, ya aceptado). Contradice "minimizar modificaciones al relay" (§6.3) y exige revisar cómo Buzz
interpreta el tag `h` de 445 como canal NIP-29.

## Interoperabilidad con un relay real
La suite de conformidad pasa contra **nostr-rs-relay 0.9.0** (el `secure-relay` del stack) con NIP-42
obligatorio: [`docs/interop/marmot-nostr-rs-relay-0.9.0-report.json`](interop/marmot-nostr-rs-relay-0.9.0-report.json).
Hallazgos corregidos en el SDK: ese relay no envía `OK` tras un `AUTH` correcto (el pool acepta un AUTH
silencioso tras `authTimeoutMs`) y confirma antes de persistir (la verificación del key package reintenta).
Reproducir: `MARMOT_RELAY_URL=ws://localhost:7000 npm run test:interop`.

## Uso (CLI soberano)
```bash
sovereign group keypackage --persona B                 # B publica su key package
sovereign group create --persona A --name "Redacción"
sovereign group invite --persona A --group <gid> --to <npub-B>
sovereign group accept --persona B
sovereign group send   --persona A --group <gid> "texto"
sovereign group read   --persona B --group <gid>
sovereign group remove --persona A --group <gid> --member <npub-B>
sovereign group rotate --persona A --group <gid>
```

## Límites
- marmot-ts es alpha: no apto para producción high-risk sin revisión independiente (spec §20.3).
- Solo el creador/admin puede hacer commits (política de marmot-ts); miembros no admin proponen.
- MIP-04 (media cifrada en grupos) y la rama Marmot v2 de marmot-ts (no publicada) no se integran aún.
- Interoperabilidad con MDK/whitenoise no verificada en este repo.

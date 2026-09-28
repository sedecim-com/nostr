# Threat model — v0.1 (versionado por release, spec §20)

## Activos
nsec / material de llave · contenido de mensajes · grafo social y vínculos entre personas · metadatos de
red (IP, horarios) · outbox local · backups · credenciales de servicio (KEK, tokens).

## Adversarios (§20.1) y mitigaciones implementadas

| Adversario | Mitigaciones en código | Riesgo residual |
|---|---|---|
| Relay curioso o comprometido | Gift wrap NIP-59 (remitente oculto, timestamps aleatorios), NIP-44, verificación de firmas en cliente, multi-relay con quorum, suscripciones `#p` acotadas | Ve destinatario (tag `p`), IP sin Tor, tamaños (padding NIP-44 parcial), canales NIP-29 en claro |
| Operador SaaS comprometido | Llaves locales/NIP-46 por defecto; backups NIP-49 con clave del usuario; mirror ciphertext-first y sellado opcional en reposo; indexer nunca descifra | En modo managed puede firmar y ve en claro los DMs NIP-44 que descifra el managed-signer (custodial, declarado); ve metadatos de canales; el sellado en reposo del mirror aún no liga cada fila a su evento (IR-2026-09-15, SEC-06) |
| Atacante de red / ISP | TLS (wss), Tor-only con socks5h y fail-closed, allowlist de hosts por persona; tests de fugas con captura real (netns + tcpdump) del CLI soberano: cero DNS, cero IPv6 y cero conexiones fuera del proxy SOCKS en perfil Tor, egress solo a los relays de la persona en perfil directo, con controles negativos (`scripts/leak-test.sh`, FR020-03/FR022-02); perfil `tor` del compose probado de punta a punta contra los .onion de relay y secure-relay (`scripts/tor-profile-check.sh`, FR021-02) | Correlación temporal; fingerprint de tráfico; el lado Tor de los tests de fugas es un stub SOCKS local (la propiedad probada es qué emite el cliente, no la calidad de Tor); la captura cubre crear persona, canales e historial, y faltan DMs, grupos, media y el worker (FR020-05) |
| Fugas desde el navegador (WebRTC, previews) | La web elimina `RTCPeerConnection` y el resto de constructores WebRTC antes de arrancar (sin candidatos ICE en ningún perfil); en perfiles sensibles (`private-resilient`, `sovereign`) enlaces e imágenes remotas no generan peticiones hasta un clic explícito; E2E con interceptación de todas las peticiones y controles negativos (`tests/browser/web-leaks.e2e.ts`, SEC-05) | Un iframe same-origin creado por script tendría WebRTC (lo impide `script-src 'self'`); el navegador estándar no garantiza Tor-only |
| Malware en endpoint | Stores cifrados (XChaCha20-Poly1305 + scrypt), wipe de llaves en memoria best-effort | Un endpoint comprometido controla la sesión: fuera de alcance |
| Robo físico del dispositivo | Passphrase + scrypt en stores y NIP-49; revocación de dispositivo (policy-engine) | Passphrase débil |
| Compromiso de cuenta cloud | El backup cloud solo contiene ciphertext (vault `/v1/backups`: el servidor valida que el sobre sea NIP-49/XChaCha20 y rechaza nsec o hex en claro; la contraseña del backup no sale del cliente); NIP-98 en APIs (sin contraseñas de servidor). El Continuity Vault (ADR 0011) guarda solo sobres sellados en el cliente con la llave de archivo (256 bits, que el servidor no recibe) y rechaza texto plano ([threat model](threat-models/continuity-vault.md)) | Disponibilidad; quien obtenga el login de Acceso vinculado o el volcado de la base puede descargar el ciphertext e intentar fuerza bruta offline (scrypt): depende de la fortaleza de la contraseña del backup. El operador ve npub, tamaño y fechas de las copias; en el vault, la cuenta, cuántos archivos, su tamaño aproximado y cuándo cambian |
| Correlación entre identidades | Personas sin vínculo por defecto, compartimentos con store/relays/circuito Tor separados (IsolateSOCKSAuth), avisos de reutilización de contactos en el CLI (en la web y para archivos: FR006-07, después de v1.0), banner "Enviando como…" | Estilo de escritura, horarios, errores humanos |
| Insider organizacional | RBAC/ABAC default-deny, auditoría sin plaintext, dispositivos registrados para recursos sensibles | Admins con privilegios amplios |
| Bug en biblioteca criptográfica | Autoprueba de secreto post-expulsión al abrir sesiones MLS (fail closed); override de ts-mls (hoy 2.0.0-rc.16; la corrección llegó en rc.11) tras hallar que rc.10 omitía UpdatePath en un Remove (RFC 9420 §12.4); tests de propiedades/fuzz con fast-check (`tests/fuzz`, SEC-03: eventos NIP-01, NIP-44, NIP-49, TLV NIP-19, codecs MLS y parsers de backup, con pruebas diferenciales contra nostr-tools; `FUZZ_RUNS=2000 npx vitest run tests/fuzz --testTimeout=0` para una campaña larga) | Otros fallos no cubiertos por la autoprueba; revisión independiente pendiente |
| Supply chain | Dependencias fijadas (versiones exactas + lockfile), noble/scure auditadas, keygen sin dependencias en runtime y bundle reproducible, SBOM, gitleaks, Dependabot, CodeQL y dependency review en CI, imágenes reproducibles bit a bit (NFR010-03), releases firmados con cosign keyless + provenance SLSA desde un entorno protegido (`release.yml`, docs/building.md) | Primer release firmado pendiente y entorno `release` sin segundo aprobador (OPS-08, OPS-12); `main` sin protección; Dependabot no cubre `infra/tor` ni las imágenes del compose, y postgres y redis van por tag |
| Servicio push / operador del gateway de notificaciones (ADR 0010) | Push opt-in y opaco (payload constante cifrado RFC 8291 o vacío; sin contenido, remitente ni recuento), retardo aleatorio + agrupación + ticks comunes por perfil, registro NIP-98 (solo el propio npub), un scope de service worker por persona, registros solo en memoria, baja ante 404/410, logs con HMAC truncado; sin push en sovereign y Tor (validación + 403 en el gateway) | El servicio push ve cuándo llega un aviso al dispositivo y la IP del gateway; el gateway conoce npub ↔ endpoint mientras el push esté activo; correlación temporal relay↔push posible con poco tráfico |
| Usuario de la plataforma fuera de un canal | El espejo solo sirve un canal (mensajes, estado NIP-29, no leídos y búsqueda) a quien figura en sus listas 39001/39002 firmadas por el relay (NIP-11 `self` o `INDEXER_GROUP_AUTHORITIES`), y aplica los 9005 de moderación como Buzz: autor o admin del canal (FR014-05) | Las listas se consultan en cada refresco de canales (`INDEXER_CHANNEL_REFRESH_MS`, 30 s por defecto): quien sale de un canal puede seguir leyéndolo por el espejo hasta el siguiente refresco |
| Error humano | Advertencia antes de mostrar nsec, confirmación explícita para vínculos, no sobrescribir backups, disclosures por opción | — |

## Propiedades por modo (§20.2)

| Propiedad | Standard SaaS | Zero-knowledge | Tor high-risk |
|---|---|---|---|
| Servidor asocia cuenta↔npub | Sí (si el usuario registra la persona) | Opcional | No (no se registra) |
| Servidor obtiene nsec | Solo managed | No | No (validación rechaza managed) |
| Servidor ve plaintext de DMs | Solo managed (el managed-signer descifra NIP-44) | No | No |
| Relay ve IP | Sí | Sí | Mitigado por Tor |
| Relay ve plaintext de canal | Canales NIP-29 sí | No si cifrado cliente | No si cifrado cliente |
| Forward secrecy | Solo Marmot/MLS | Solo Marmot/MLS | Solo Marmot/MLS (marmot-ts alpha, vía relay secundario) |
| Cloud recovery | Sí | Solo ciphertext | Off por defecto |

## Gates de seguridad (§20.3) — estado

- [ ] Revisión criptográfica independiente.
- [ ] Pentest de API, relay, key service y cliente.
- [x] Tests automatizados de Tor/DNS: DNS remoto verificado y ausencia de fallback clearnet; captura de red real (pcap) sin DNS, IPv6 ni conexiones fuera del proxy (job `leak-tests`). [x] WebRTC y previews remotas en la web (SEC-05). WebRTC en móvil: no aplica (sin app móvil propia).
- [x] Revocación en el policy-engine y rotación MLS con el worker del CLI (FR024-01/02/04). [ ] Revocación efectiva en la web managed y worker como servicio (FR024-03, FR024-05). [x] Rotación MLS (self-update) y expulsión con secreto post-expulsión (tests de conformidad + autoprueba en runtime).
- [x] Restore completo de identidad en dispositivo limpio (test). [x] Drill de restore del stack self-hosted, nocturno en CI (`restore-drill.yml`, NFR003-02). [ ] Simulacro de RPO/RTO en stage (NFR003-03).
- [x] Fuzz/property tests con fast-check de serialización, criptografía y parsers propios (`tests/fuzz`, SEC-03).
- [x] Dependency scanning (Dependabot, dependency review), CodeQL, SBOM, gitleaks. [ ] Firma de releases: `release.yml` firma con cosign keyless y provenance SLSA, pero aún no hay ningún release (NFR010-02).
- [ ] Threat models versionados (v0.1) pero en estado Propuesto: falta la aprobación de alguien distinto del autor y ligarlos a un release (DEC-10).

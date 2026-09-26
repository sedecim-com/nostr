# Threat model — v0.1 (versionado por release, spec §20)

## Activos
nsec / material de llave · contenido de mensajes · grafo social y vínculos entre personas · metadatos de
red (IP, horarios) · outbox local · backups · credenciales de servicio (KEK, tokens).

## Adversarios (§20.1) y mitigaciones implementadas

| Adversario | Mitigaciones en código | Riesgo residual |
|---|---|---|
| Relay curioso o comprometido | Gift wrap NIP-59 (remitente oculto, timestamps aleatorios), NIP-44, verificación de firmas en cliente, multi-relay con quorum, suscripciones `#p` acotadas | Ve destinatario (tag `p`), IP sin Tor, tamaños (padding NIP-44 parcial), canales NIP-29 en claro |
| Operador SaaS comprometido | Llaves locales/NIP-46 por defecto; backups NIP-49 con clave del usuario; mirror ciphertext-first y sellado opcional en reposo; indexer nunca descifra | En modo managed puede firmar (custodial, declarado); ve metadatos de canales |
| Atacante de red / ISP | TLS (wss), Tor-only con socks5h y fail-closed, allowlist de hosts por persona | Correlación temporal; fingerprint de tráfico |
| Malware en endpoint | Stores cifrados (XChaCha20-Poly1305 + scrypt), wipe de llaves en memoria best-effort | Un endpoint comprometido controla la sesión: fuera de alcance |
| Robo físico del dispositivo | Passphrase + scrypt en stores y NIP-49; revocación de dispositivo (policy-engine) | Passphrase débil |
| Compromiso de cuenta cloud | El backup cloud solo contiene ciphertext; NIP-98 en APIs (sin contraseñas de servidor) | Disponibilidad |
| Correlación entre identidades | Personas sin vínculo por defecto, compartimentos con store/relays/circuito Tor separados (IsolateSOCKSAuth), avisos de reutilización de contactos/archivos, banner "Enviando como…" | Estilo de escritura, horarios, errores humanos |
| Insider organizacional | RBAC/ABAC default-deny, auditoría sin plaintext, dispositivos registrados para recursos sensibles | Admins con privilegios amplios |
| Bug en biblioteca criptográfica | Autoprueba de secreto post-expulsión al abrir sesiones MLS (fail closed); override de ts-mls rc.11 tras hallar que rc.10 omitía UpdatePath en un Remove (RFC 9420 §12.4) | Otros fallos no cubiertos por la autoprueba; revisión independiente pendiente |
| Supply chain | Dependencias fijadas (versiones exactas + lockfile), noble/scure auditadas, keygen sin dependencias en runtime y bundle reproducible, SBOM, gitleaks, Dependabot, releases firmados con cosign keyless + provenance SLSA desde un entorno protegido (`release.yml`, docs/building.md) | Imágenes no reproducibles bit a bit (bases por tag); primer release firmado pendiente |
| Error humano | Advertencia antes de mostrar nsec, confirmación explícita para vínculos, no sobrescribir backups, disclosures por opción | — |

## Propiedades por modo (§20.2)

| Propiedad | Standard SaaS | Zero-knowledge | Tor high-risk |
|---|---|---|---|
| Servidor asocia cuenta↔npub | Sí (si el usuario registra la persona) | Opcional | No (no se registra) |
| Servidor obtiene nsec | Solo managed | No | No (validación rechaza managed) |
| Relay ve IP | Sí | Sí | Mitigado por Tor |
| Relay ve plaintext de canal | Canales NIP-29 sí | No si cifrado cliente | No si cifrado cliente |
| Forward secrecy | Solo Marmot/MLS | Solo Marmot/MLS | Solo Marmot/MLS (marmot-ts alpha, vía relay secundario) |
| Cloud recovery | Sí | Solo ciphertext | Off por defecto |

## Gates de seguridad (§20.3) — estado

- [ ] Revisión criptográfica independiente.
- [ ] Pentest de API, relay, key service y cliente.
- [x] Tests automatizados de Tor/DNS: DNS remoto verificado y ausencia de fallback clearnet. [ ] WebRTC (no aplica en CLI; pendiente en web/móvil).
- [x] Pérdida de dispositivo y revocación (policy-engine). [x] Rotación MLS (self-update) y expulsión con secreto post-expulsión (tests de conformidad + autoprueba en runtime).
- [x] Restore completo de identidad en dispositivo limpio (test). [ ] Drill de restore del stack (runbook).
- [ ] Fuzz/property tests de serialización (parcial: interop contra nostr-tools).
- [x] Dependency scanning (Dependabot), SBOM, gitleaks. [ ] Firma de releases.
- [x] Threat model versionado (este documento).

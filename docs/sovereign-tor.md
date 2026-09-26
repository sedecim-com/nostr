# Sovereign Tor Mode (spec §14)

```bash
docker compose --profile tor up -d           # Tor SOCKS en 127.0.0.1:9050 + onion service del relay
docker compose logs tor | grep "onion relay"   # dirección ws://<56 chars>.onion
export SOVEREIGN_PASSPHRASE='…'
npm run sovereign -- persona create --label Fuente --relay ws://<onion>.onion --high-risk
npm run sovereign -- channel send --persona <id> --group <h> "texto"
```

Garantías verificadas por tests (`packages/tor-network/test`, `apps/sovereign-client/test`):
- Con Tor caído, **no** se abre ninguna conexión: el mensaje queda en outbox con
  "No enviado: red de privacidad no disponible" y se reenvía (mismo event id) con `sovereign resume`.
- Resolución DNS dentro de Tor (`socks5h`): ningún `dns.lookup` local de destinos.
- Cada persona usa credenciales SOCKS distintas → circuitos separados (`IsolateSOCKSAuth`).
- Solo se permiten los hosts de relay configurados para la persona; `onionOnly` bloquea clearnet.
- Telemetría `none`: cero llamadas externas.

Limitaciones: el navegador estándar no puede garantizar Tor-only (el panel lo bloquea); WebRTC/previews
no aplican al CLI; no se ha realizado una auditoría independiente de fugas.

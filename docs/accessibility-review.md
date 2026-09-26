# Revisión de accesibilidad de la web (NFR009-02)

## Automatizado (en CI)
- La E2E de navegador (`tests/browser/web-saas.e2e.ts`) ejecuta axe-core en cada vista (bóveda,
  Personas, Canales, Mensajes, Entrega, Soberanía) y falla ante violaciones *serious* o *critical*.
- Corregido en S2 y S3:
  - Contraste del color primario (AA).
  - Etiquetas en todos los campos.
  - Enlace "Saltar al contenido".
  - Tabs según el patrón WAI-ARIA (el foco se queda en la pestaña; Tab entra al panel).
  - Diálogos con título asociado y foco inicial en "Cancelar".
  - Alertas y toasts con rol `alert`/`status`.

## Revisión manual con lector de pantalla (pendiente de una persona)
Hacerla con NVDA + Firefox en Windows y VoiceOver + Safari en macOS/iOS. Anotar hallazgos en la tabla.

| # | Flujo | Qué comprobar | NVDA | VoiceOver |
|---|---|---|---|---|
| 1 | Crear almacén | Se anuncian el radio de protección y el aviso de "sin contraseña" | | |
| 2 | Desbloquear | El error de contraseña se anuncia sin mover el foco | | |
| 3 | Crear persona | Los modos de llave se leen como un grupo; el éxito se anuncia | | |
| 4 | Signer remoto | La lista de permisos se lee antes de conectar; el código nostrconnect se puede copiar | | |
| 5 | Banner "Enviando como…" | Se anuncia al cambiar de persona (región `status`) | | |
| 6 | Canales | Lista navegable; los mensajes nuevos se anuncian (`aria-live`) sin robar el foco | | |
| 7 | Mensajes directos | La casilla de NIP-17 explica su estado; los adjuntos tienen nombre accesible | | |
| 8 | Vincular personas | El diálogo anuncia las consecuencias antes del botón de confirmar | | |
| 9 | Panel | Cada dimensión se expande con teclado y enlaza a su consecuencia | | |
| 10 | Aprobación del signer (`auth_url`) | La alerta se anuncia y el botón abre la página en una pestaña nueva | | |

**Resultado:** pendiente. Al completarla, marcar NFR009-02 como Hecho en el backlog con este documento como evidencia.

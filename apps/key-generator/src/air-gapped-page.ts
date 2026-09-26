/**
 * HTML shell of the air-gapped generator (FR003-05). build-html.mjs inlines the browser bundle and
 * pins both the script and the stylesheet by SHA-256 in a CSP that allows nothing else: no fetch, no
 * WebSocket, no images, fonts, frames or form submissions.
 */
import { BACKUP_SHEET_CSS } from './backup-sheet';

export const PAGE_CSS = `
:root{color-scheme:light}
body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:#f6f6f4;color:#111;line-height:1.5}
main{max-width:800px;margin:0 auto;padding:24px 16px}
h1{font-size:1.6rem;margin:0 0 8px}
.notice{background:#fff;border-left:4px solid #1b5e20;padding:8px 12px;margin:12px 0}
form{background:#fff;border:1px solid #ccc;padding:16px;display:grid;gap:12px}
label{display:grid;gap:4px;font-weight:600}
input,select{font:inherit;padding:8px;border:1px solid #888;border-radius:4px}
button{font:inherit;padding:8px 14px;border:1px solid #111;background:#111;color:#fff;border-radius:4px;cursor:pointer}
button.secondary{background:#fff;color:#111}
button:disabled{opacity:.6;cursor:progress}
button:focus-visible,input:focus-visible,select:focus-visible{outline:3px solid #1565c0;outline-offset:2px}
.error{color:#b71c1c;font-weight:600}
.actions{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}
code{font-family:ui-monospace,Menlo,Consolas,monospace;word-break:break-all}
#result{margin-top:20px}
#sheet{background:#fff;border:1px solid #ccc;margin-top:12px}
.hint{font-weight:400;color:#444;font-size:.9rem}
@media print{body{background:#fff}.no-print{display:none!important}main{padding:0;max-width:none}#sheet{border:0;margin:0}}
${BACKUP_SHEET_CSS}
`.trim();

/** Escapes a script so it cannot close its own <script> element. */
export function escapeInlineScript(js: string): string {
  return js.replace(/<\/(script)/gi, '<\\/$1').replace(/<!--/g, '<\\!--');
}

export function airGappedPage(script: string, sha256Base64: (text: string) => string): string {
  const js = escapeInlineScript(script);
  const csp = [
    "default-src 'none'",
    `script-src 'sha256-${sha256Base64(js)}'`,
    `style-src 'sha256-${sha256Base64(PAGE_CSS)}'`,
    "img-src 'none'",
    "connect-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
  ].join('; ');
  return `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Generador de llaves Nostr sin conexión</title>
<style>${PAGE_CSS}</style>
</head>
<body>
<main>
<div class="no-print">
<h1>Generador de llaves Nostr sin conexión</h1>
<p class="notice">Esta página es un único archivo local. Su política de seguridad (CSP) bloquea cualquier conexión de red: no envía datos a ningún servidor. Para reducir aún más el riesgo, ábrela en un equipo desconectado y cierra la pestaña al terminar.</p>
<p id="ready" role="status">Cargando…</p>
<form id="form" autocomplete="off">
<label for="pw">Contraseña del backup <span class="hint">(mínimo 12 caracteres; protege la clave privada cifrada)</span></label>
<input id="pw" type="password" required autocomplete="new-password">
<label for="pw2">Repite la contraseña</label>
<input id="pw2" type="password" required autocomplete="new-password">
<label for="logn">Coste de scrypt <span class="hint">(más alto = más lento de atacar y de abrir)</span></label>
<select id="logn">
<option value="16">2^16 (rápido)</option>
<option value="18" selected>2^18 (recomendado)</option>
<option value="20">2^20 (lento)</option>
</select>
<button id="generate" type="submit">Generar llave</button>
</form>
<p id="status" role="status" aria-live="polite"></p>
<p id="error" class="error" role="alert" hidden></p>
</div>
<section id="result" hidden aria-labelledby="result-title">
<div class="no-print">
<h2 id="result-title">Tu nueva identidad</h2>
<p>npub: <code id="npub"></code></p>
<p>ncryptsec: <code id="ncryptsec"></code></p>
<p id="selftest"></p>
<div class="actions">
<button id="print" type="button">Imprimir hoja de respaldo</button>
<button id="download" type="button" class="secondary">Descargar backup cifrado (.json)</button>
<button id="forget" type="button" class="secondary">Borrar de la página</button>
</div>
<p class="hint">La nsec nunca se muestra: solo sale de aquí cifrada con tu contraseña (NIP-49).</p>
</div>
<div id="sheet"></div>
</section>
</main>
<script>${js}</script>
</body>
</html>
`;
}

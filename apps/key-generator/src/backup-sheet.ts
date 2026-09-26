/**
 * Printable backup sheet (FR003-04): npub + ncryptsec as text and QR, creation date and recovery
 * instructions. Browser-safe (used by the CLI and by the air-gapped HTML generator); no remote
 * resources, no scripts, no inline style attributes (the pages that embed it run under a strict CSP).
 */
import { encodeQR, qrToSvg } from '@sedecim/qr';

export interface BackupSheetInput {
  npub: string;
  ncryptsec: string;
  /** ISO timestamp of key creation */
  createdAt: string;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

/** QR codes (ECC level M) of the npub and the ncryptsec as SVG. `inline` omits xmlns for HTML embedding. */
export function backupQrSvgs(k: Pick<BackupSheetInput, 'npub' | 'ncryptsec'>, opts: { inline?: boolean; moduleSize?: number } = {}): { npub: string; ncryptsec: string } {
  const common = { inline: opts.inline ?? false, moduleSize: opts.moduleSize ?? 4, margin: 4 };
  return {
    npub: qrToSvg(encodeQR(k.npub, { ecc: 'M' }), { ...common, title: 'Código QR del npub (clave pública)' }),
    ncryptsec: qrToSvg(encodeQR(k.ncryptsec, { ecc: 'M' }), { ...common, title: 'Código QR del ncryptsec (clave privada cifrada)' }),
  };
}

/** Human date in Spanish plus the ISO timestamp (both printed, so the sheet is unambiguous). */
export function formatSheetDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) throw new Error(`invalid createdAt: ${iso}`);
  const months = ['enero', 'febrero', 'marzo', 'abril', 'mayo', 'junio', 'julio', 'agosto', 'septiembre', 'octubre', 'noviembre', 'diciembre'];
  return `${d.getUTCDate()} de ${months[d.getUTCMonth()]} de ${d.getUTCFullYear()} (${d.toISOString()})`;
}

export const BACKUP_SHEET_CSS = `
.sheet{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:#111;background:#fff;max-width:760px;margin:0 auto;padding:24px;line-height:1.45}
.sheet h1{font-size:1.5rem;margin:0 0 4px}
.sheet h2{font-size:1.1rem;margin:20px 0 6px;border-bottom:1px solid #999}
.sheet .meta{color:#333;margin:0 0 12px}
.sheet .key{display:flex;gap:16px;align-items:flex-start;break-inside:avoid;page-break-inside:avoid}
.sheet .key svg{flex:none;width:180px;height:180px}
.sheet .key.secret svg{width:220px;height:220px}
.sheet code{font-family:ui-monospace,"SFMono-Regular",Menlo,Consolas,monospace;font-size:.85rem;word-break:break-all;overflow-wrap:anywhere;display:block;background:#f4f4f4;border:1px solid #ccc;padding:8px}
.sheet .warn{border:2px solid #111;padding:8px 12px;margin:12px 0}
.sheet ol{padding-left:20px}
.sheet .notes{border:1px solid #999;min-height:80px;margin-top:8px}
@media print{.sheet{padding:0;max-width:none}.sheet code{background:#fff}}
`.trim();

/** The sheet itself (an <article class="sheet">), to embed in a page that includes BACKUP_SHEET_CSS. */
export function backupSheetBody(k: BackupSheetInput): string {
  if (!/^npub1[02-9ac-hj-np-z]+$/.test(k.npub)) throw new Error('invalid npub');
  if (!/^ncryptsec1[02-9ac-hj-np-z]+$/.test(k.ncryptsec)) throw new Error('invalid ncryptsec');
  const qr = backupQrSvgs(k, { inline: true });
  const npub = escapeHtml(k.npub);
  const ncryptsec = escapeHtml(k.ncryptsec);
  return `<article class="sheet" aria-label="Hoja de respaldo">
<h1>Hoja de respaldo de identidad Nostr</h1>
<p class="meta">Creada el ${escapeHtml(formatSheetDate(k.createdAt))} con el generador offline de Acceso Nostr.</p>
<p class="warn"><strong>Guárdala como un documento sensible.</strong> Contiene tu clave privada cifrada. Sin la contraseña no sirve para firmar; con la contraseña, quien la tenga controla tu identidad.</p>
<h2>Clave pública (npub)</h2>
<div class="key public">${qr.npub}<div><p>Es tu identificador público: puedes compartirlo.</p><code id="sheet-npub">${npub}</code></div></div>
<h2>Clave privada cifrada (ncryptsec, NIP-49)</h2>
<div class="key secret">${qr.ncryptsec}<div><p>Cifrada con tu contraseña (scrypt + XChaCha20-Poly1305). No la compartas.</p><code id="sheet-ncryptsec">${ncryptsec}</code></div></div>
<h2>Cómo recuperar la identidad</h2>
<ol>
<li>Guarda esta hoja en un lugar seguro y <strong>separado de la contraseña</strong>. No la fotografíes ni la subas a la nube.</li>
<li>Para recuperar, escanea el QR del ncryptsec o copia el texto en un cliente compatible con NIP-49 (en Acceso Nostr: «Importar backup»; en la terminal: <code>sovereign persona import</code> o <code>keygen verify</code>) e introduce la contraseña.</li>
<li>Comprueba que el npub que muestra el cliente coincide exactamente con el de esta hoja. Si no coincide, no uses esa llave.</li>
<li>Si olvidas la contraseña, esta hoja no permite recuperar la identidad: nadie puede descifrarla por ti.</li>
<li>Si sospechas que alguien obtuvo esta hoja y la contraseña, crea una identidad nueva y avisa a tus contactos.</li>
</ol>
<h2>Notas</h2>
<div class="notes" aria-label="Espacio para notas a mano (nunca la contraseña)"></div>
<p class="meta">No escribas la contraseña en esta hoja.</p>
</article>`;
}

/**
 * Standalone printable page. `sha256Base64` hashes the inline <style> for the CSP (node:crypto in the
 * CLI, SubtleCrypto in a browser); the page has no scripts and loads nothing.
 */
export async function backupSheetHtml(k: BackupSheetInput, sha256Base64: (text: string) => string | Promise<string>): Promise<string> {
  const css = `body{margin:0;background:#fff}\n${BACKUP_SHEET_CSS}`;
  const csp = `default-src 'none'; style-src 'sha256-${await sha256Base64(css)}'; img-src 'none'; base-uri 'none'; form-action 'none'`;
  return `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Respaldo de identidad Nostr</title>
<style>${css}</style>
</head>
<body>
${backupSheetBody(k)}
</body>
</html>
`;
}

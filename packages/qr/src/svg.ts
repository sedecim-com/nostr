export interface QrSvgOptions {
  /** Size of one module in SVG user units / CSS pixels (default 4). */
  moduleSize?: number;
  /** Quiet zone in modules (default 4, the minimum required by ISO/IEC 18004). */
  margin?: number;
  /** Accessible title, rendered as <title> and aria-label. */
  title?: string;
  /**
   * Omit the xmlns declaration, for SVG embedded directly in HTML (the HTML parser assigns the SVG
   * namespace itself). Standalone .svg files need the default (false).
   */
  inline?: boolean;
  /** Colours (default black on white; keep high contrast for scanners). */
  dark?: string;
  light?: string;
}

function escapeXml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

const COLOR = /^(#[0-9a-fA-F]{3,8}|[a-zA-Z]+)$/;

/**
 * Renders a QR matrix as a self-contained SVG: one <path> for the dark modules over a light
 * background, no external references, scripts, styles or fonts.
 */
export function qrToSvg(matrix: boolean[][], opts: QrSvgOptions = {}): string {
  const moduleSize = opts.moduleSize ?? 4;
  const margin = opts.margin ?? 4;
  if (!(moduleSize > 0) || !Number.isFinite(moduleSize)) throw new Error('moduleSize must be a positive number');
  if (!Number.isInteger(margin) || margin < 0) throw new Error('margin must be a non-negative integer');
  const dark = opts.dark ?? '#000';
  const light = opts.light ?? '#fff';
  if (!COLOR.test(dark) || !COLOR.test(light)) throw new Error('colours must be #hex or a named colour');
  const n = matrix.length;
  if (matrix.some((row) => row.length !== n)) throw new Error('QR matrix must be square');
  const dim = n + margin * 2;
  const px = dim * moduleSize;
  let d = '';
  for (let y = 0; y < n; y++) {
    const row = matrix[y]!;
    for (let x = 0; x < n; ) {
      if (!row[x]) {
        x++;
        continue;
      }
      let w = 1;
      while (x + w < n && row[x + w]) w++;
      d += `M${x + margin} ${y + margin}h${w}v1h-${w}z`;
      x += w;
    }
  }
  const title = opts.title ? escapeXml(opts.title) : undefined;
  const ns = opts.inline ? '' : ' xmlns="http://www.w3.org/2000/svg"';
  const a11y = title ? ` role="img" aria-label="${title}"` : ' aria-hidden="true"';
  return (
    `<svg${ns} viewBox="0 0 ${dim} ${dim}" width="${px}" height="${px}" shape-rendering="crispEdges"${a11y}>` +
    (title ? `<title>${title}</title>` : '') +
    `<rect width="${dim}" height="${dim}" fill="${light}"/>` +
    `<path d="${d}" fill="${dark}"/>` +
    `</svg>`
  );
}

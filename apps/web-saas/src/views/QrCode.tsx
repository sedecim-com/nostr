import { useMemo } from 'react';
import { Box } from '@mui/material';
import { encodeQR } from '@sedecim/qr';

/**
 * QR drawn from the matrix as one SVG path (no innerHTML, no network): used for nostrconnect:// offers
 * and the npub (FR003-03). Always dark on white so any camera can read it, whatever the theme.
 */
export function QrCode({ text, label, size = 220 }: { text: string; label: string; size?: number }) {
  const { d, n } = useMemo(() => {
    const m = encodeQR(text, { ecc: 'M' });
    let path = '';
    m.forEach((row, y) => row.forEach((dark, x) => dark && (path += `M${x + 4} ${y + 4}h1v1h-1z`)));
    return { d: path, n: m.length + 8 };
  }, [text]);
  return (
    <Box component="svg" role="img" aria-label={label} viewBox={`0 0 ${n} ${n}`} sx={{ width: size, height: size, bgcolor: '#fff', borderRadius: 1 }} shapeRendering="crispEdges">
      <rect width={n} height={n} fill="#fff" />
      <path d={d} fill="#000" />
    </Box>
  );
}

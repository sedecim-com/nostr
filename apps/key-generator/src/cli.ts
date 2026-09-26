/**
 * Offline Nostr key generator (spec §8.2). Standalone: no analytics, no network, no remote fonts/CDN.
 * All network primitives are disabled before any key material is created.
 *
 *   keygen [--out backup.json] [--qr DIR] [--print backup.html] [--password-file f] [--logn 18] [--show-nsec --i-understand]
 *          --qr DIR            writes DIR/npub.svg and DIR/ncryptsec.svg (self-contained SVG QR codes)
 *          --print backup.html printable backup sheet: npub, ncryptsec, both QR, date and recovery steps
 *                              (single local HTML file, strict CSP, no remote resources)
 *   keygen verify backup.json [--password-file f]
 *   keygen service-key --i-understand   (hex secret for a service .env: relay key, mirror identity)
 */
import { enforceOffline } from './offline-guard';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { backupQrSvgs, backupSheetHtml } from './backup-sheet';
import { backupFile, generateKey, generateServiceKey, verifyBackup, type BackupFile } from './generate';

enforceOffline();

const args = process.argv.slice(2);
const flag = (n: string) => args.includes(n);
const opt = (n: string) => (args.includes(n) ? args[args.indexOf(n) + 1] : undefined);

async function askHidden(question: string): Promise<string> {
  if (!process.stdin.isTTY) {
    const rl = createInterface({ input: process.stdin });
    for await (const line of rl) return line;
    return '';
  }
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    const out = rl as unknown as { _writeToOutput: (s: string) => void; output: NodeJS.WriteStream };
    out._writeToOutput = (s: string) => {
      if (s.includes(question)) out.output.write(s);
    };
    rl.question(question, (answer) => {
      rl.close();
      process.stdout.write('\n');
      resolve(answer);
    });
  });
}

async function password(confirm: boolean): Promise<string> {
  const file = opt('--password-file');
  if (file) return readFileSync(file, 'utf8').replace(/\r?\n$/, '');
  const p1 = await askHidden('Contraseña del backup (mín. 12 caracteres): ');
  if (confirm) {
    const p2 = await askHidden('Repite la contraseña: ');
    if (p1 !== p2) throw new Error('las contraseñas no coinciden');
  }
  return p1;
}

async function main() {
  if (args[0] === 'verify') {
    const file = JSON.parse(readFileSync(args[1]!, 'utf8')) as BackupFile;
    const res = verifyBackup(file, await password(false));
    console.log(res.ok ? `OK: backup válido para ${res.npub}` : 'ERROR: el backup no corresponde al npub declarado');
    process.exit(res.ok ? 0 : 1);
  }
  if (args[0] === 'service-key') {
    // Machine-readable, meant to be piped into .env by scripts/init-env.sh; never for personal identities.
    if (!flag('--i-understand')) {
      console.error('ADVERTENCIA: imprime la llave secreta en claro (para el .env de un servicio). Añade --i-understand.');
      process.exit(2);
    }
    const k = generateServiceKey();
    console.log(`secret_hex=${k.secretHex}\npubkey_hex=${k.pubkeyHex}\nnpub=${k.npub}`);
    return;
  }
  const logN = Number(opt('--logn') ?? 18);
  const out = opt('--out');
  const qrDir = flag('--qr') ? opt('--qr') : undefined;
  const print = flag('--print') ? opt('--print') : undefined;
  if (flag('--qr') && (!qrDir || qrDir.startsWith('--'))) throw new Error('--qr requiere un directorio de salida');
  if (flag('--print') && (!print || print.startsWith('--'))) throw new Error('--print requiere un archivo de salida (.html)');
  const reveal = flag('--show-nsec');
  if (reveal && !flag('--i-understand')) {
    console.error('ADVERTENCIA: la nsec da control total de la identidad. Cualquiera que la vea puede suplantarte.\nAñade --i-understand para mostrarla en pantalla.');
    process.exit(2);
  }
  const qrFiles = qrDir ? [join(qrDir, 'npub.svg'), join(qrDir, 'ncryptsec.svg')] : [];
  const targets = [out, print, ...qrFiles].filter((f): f is string => !!f);
  let pw: string | undefined;
  if (targets.length) {
    // Every persistent output carries the ncryptsec, so it needs the backup password.
    pw = await password(true);
    if (pw.length < 12) throw new Error('la contraseña debe tener al menos 12 caracteres');
    for (const f of targets) if (existsSync(f)) throw new Error(`${f} ya existe: no se sobrescribe`);
  }
  const key = generateKey({ password: pw, logN, revealNsec: reveal });
  console.log(`npub:        ${key.npub}`);
  console.log(`pubkey hex:  ${key.pubkeyHex}`);
  console.log(`self-test:   derivación=${key.selfTest.checks.derivation} firma BIP-340=${key.selfTest.checks.signature} rechazo-manipulación=${key.selfTest.checks.tamperRejected}`);
  if (key.nsec) console.log(`\n!!! nsec (NO la compartas, NO la fotografíes): ${key.nsec}\n`);
  const write = (file: string, content: string) => writeFileSync(file, content, { mode: 0o600, flag: 'wx' });
  if (out) {
    write(out, JSON.stringify(backupFile(key, logN), null, 2) + '\n');
    console.log(`backup cifrado (NIP-49) escrito en ${out}`);
  }
  if (qrDir) {
    mkdirSync(qrDir, { recursive: true, mode: 0o700 });
    const svgs = backupQrSvgs({ npub: key.npub, ncryptsec: key.ncryptsec! });
    write(qrFiles[0]!, svgs.npub + '\n');
    write(qrFiles[1]!, svgs.ncryptsec + '\n');
    console.log(`QR (SVG) escritos en ${qrFiles.join(' y ')}`);
  }
  if (print) {
    const html = await backupSheetHtml({ npub: key.npub, ncryptsec: key.ncryptsec!, createdAt: key.createdAt }, (t) => createHash('sha256').update(t, 'utf8').digest('base64'));
    write(print, html);
    console.log(`hoja de respaldo imprimible escrita en ${print} (ábrela en el navegador e imprímela; no carga recursos remotos)`);
  }
  if (!targets.length && !reveal) console.log('\nNota: sin --out, --print, --qr ni --show-nsec la llave se descarta. Usa --out para guardar un backup cifrado.');
}


main().catch((err: Error) => {
  console.error(`error: ${err.message}`);
  process.exit(1);
});

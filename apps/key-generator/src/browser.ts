/**
 * Air-gapped HTML generator (FR003-05): runs from a single local file under a CSP that forbids every
 * network request. Keys come from crypto.getRandomValues (via @noble/curves), pass the BIP-340
 * self-test and are only output encrypted (NIP-49 ncryptsec) with the user's passphrase.
 */
import { backupSheetBody } from './backup-sheet';
import { backupFile, generateKeyAsync } from './generate';

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

function show(el: HTMLElement, visible: boolean) {
  el.hidden = !visible;
}

let lastBackup: string | undefined;
let downloadUrl: string | undefined;

function reset() {
  $<HTMLElement>('result').hidden = true;
  $<HTMLElement>('sheet').innerHTML = '';
  $<HTMLElement>('npub').textContent = '';
  $<HTMLElement>('ncryptsec').textContent = '';
  lastBackup = undefined;
  if (downloadUrl) URL.revokeObjectURL(downloadUrl);
  downloadUrl = undefined;
}

async function onGenerate(ev: Event) {
  ev.preventDefault();
  const error = $<HTMLElement>('error');
  const status = $<HTMLElement>('status');
  const button = $<HTMLButtonElement>('generate');
  const pwEl = $<HTMLInputElement>('pw');
  const pw2El = $<HTMLInputElement>('pw2');
  error.textContent = '';
  show(error, false);
  const pw = pwEl.value;
  if (pw.length < 12) return fail('La contraseña debe tener al menos 12 caracteres.');
  if (pw !== pw2El.value) return fail('Las contraseñas no coinciden.');
  const logN = Number($<HTMLSelectElement>('logn').value);
  if (![16, 18, 20].includes(logN)) return fail('Parámetro de coste no válido.');
  reset();
  button.disabled = true;
  status.textContent = 'Generando y cifrando la llave (scrypt): puede tardar unos segundos…';
  try {
    const key = await generateKeyAsync({ password: pw, logN });
    pwEl.value = '';
    pw2El.value = '';
    const t = key.selfTest.checks;
    $<HTMLElement>('npub').textContent = key.npub;
    $<HTMLElement>('ncryptsec').textContent = key.ncryptsec!;
    $<HTMLElement>('selftest').textContent = `Autoprueba: derivación ${t.derivation ? 'correcta' : 'FALLIDA'}, firma BIP-340 ${t.signature ? 'correcta' : 'FALLIDA'}, rechazo de manipulación ${t.tamperRejected ? 'correcto' : 'FALLIDO'}.`;
    // Values are bech32 (validated and escaped inside backupSheetBody).
    $<HTMLElement>('sheet').innerHTML = backupSheetBody({ npub: key.npub, ncryptsec: key.ncryptsec!, createdAt: key.createdAt });
    lastBackup = JSON.stringify(backupFile(key, logN), null, 2) + '\n';
    $<HTMLElement>('result').hidden = false;
    status.textContent = 'Listo. Imprime la hoja o descarga el backup cifrado; la contraseña no se guarda en ningún sitio.';
  } catch (err) {
    status.textContent = '';
    fail(`Error: ${(err as Error).message}`);
  } finally {
    button.disabled = false;
  }
}

function fail(msg: string) {
  const error = $<HTMLElement>('error');
  error.textContent = msg;
  show(error, true);
}

function onDownload() {
  if (!lastBackup) return;
  if (downloadUrl) URL.revokeObjectURL(downloadUrl);
  downloadUrl = URL.createObjectURL(new Blob([lastBackup], { type: 'application/json' }));
  const a = document.createElement('a');
  a.href = downloadUrl;
  a.download = `nostr-backup-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.append(a);
  a.click();
  a.remove();
}

function init() {
  $<HTMLFormElement>('form').addEventListener('submit', (e) => void onGenerate(e));
  $<HTMLButtonElement>('print').addEventListener('click', () => window.print());
  $<HTMLButtonElement>('download').addEventListener('click', onDownload);
  $<HTMLButtonElement>('forget').addEventListener('click', () => {
    reset();
    $<HTMLElement>('status').textContent = 'Datos borrados de la página. Cierra la pestaña para terminar.';
  });
  $<HTMLElement>('ready').textContent = 'Página cargada sin conexión: lista para generar.';
  document.documentElement.dataset.ready = '1';
}

init();

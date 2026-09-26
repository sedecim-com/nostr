import { normalizePubkey } from '@sedecim/nostr-core';
import { BUZZ_PINNED_ADAPTER, chatMessage, channelFilter, dmInboxFilter, DirectMessenger, FeatureDisabledError } from '@sedecim/messaging';
import { PRESETS, disclose, preset, summarize, validateConfig, type PresetName, type SovereigntyConfig } from '@sedecim/profiles';
import { custodyFacts, openSession, shortNpub, type CustodyChoice, type WebSession } from './session';

const $ = <T extends HTMLElement>(sel: string) => document.querySelector(sel) as T;
let session: WebSession | undefined;
let channelSub: { close(): void } | undefined;
let config: SovereigntyConfig = preset('convenience');

// --- tabs (keyboard accessible: buttons + arrow keys)
const tabs = [...document.querySelectorAll<HTMLButtonElement>('.tab')];
function show(tab: string) {
  for (const t of tabs) t.setAttribute('aria-selected', String(t.dataset.tab === tab));
  for (const v of document.querySelectorAll<HTMLElement>('.view')) v.hidden = v.id !== tab;
}
tabs.forEach((t, i) => {
  t.addEventListener('click', () => show(t.dataset.tab!));
  t.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
      const next = tabs[(i + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length]!;
      next.focus();
      show(next.dataset.tab!);
    }
  });
});

const text = (el: HTMLElement, s: string) => {
  el.textContent = s;
};
function li(s: string) {
  const el = document.createElement('li');
  el.textContent = s;
  return el;
}

function sendingAs(): string {
  if (!session) return 'Sin identidad activa';
  return `Enviando como ${shortNpub(session.pubkey)} · ${session.custodyLabel} · ${config.network === 'tor-only' ? 'Tor-only' : 'red directa'}`;
}
function refreshSendingAs() {
  text($('#sending-as'), sendingAs());
  document.querySelectorAll<HTMLElement>('[data-sending-as]').forEach((e) => text(e, sendingAs()));
}

// --- identity
$('#unlock-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const status = $('#identity-status');
  text(status, 'Activando…');
  try {
    session?.pool.close();
    session = await openSession({
      choice: (document.querySelector('input[name=custody]:checked') as HTMLInputElement).value as CustodyChoice,
      localPass: $<HTMLInputElement>('#local-pass').value,
      secret: $<HTMLInputElement>('#secret-input').value,
      ncryptsecPass: $<HTMLInputElement>('#ncryptsec-pass').value,
      relays: $<HTMLTextAreaElement>('#relays').value.split('\n').map((s) => s.trim()).filter(Boolean),
    });
    $<HTMLInputElement>('#secret-input').value = '';
    text(status, `Identidad activa: ${shortNpub(session.pubkey)}`);
    const facts = $('#custody-facts');
    facts.replaceChildren(...custodyFacts(session).map((f) => li(f)));
    $('#export-backup').hidden = session.signer.custody !== 'local';
    session.engine.onChange(() => void renderOutbox());
    refreshSendingAs();
    void renderOutbox();
  } catch (err) {
    status.className = 'error';
    text(status, `Error: ${(err as Error).message}`);
  }
});

$('#export-backup').addEventListener('click', async () => {
  const enc = await session?.keyStore.get('ncryptsec');
  if (!enc) return;
  const blob = new Blob([JSON.stringify({ format: 'sedecim-web-key-backup', version: 1, ncryptsec: enc }, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'nostr-backup-ncryptsec.json';
  a.click();
  URL.revokeObjectURL(a.href);
});

// --- channel (NIP-29)
let groupId = '';
$('#channel-join').addEventListener('submit', (e) => {
  e.preventDefault();
  if (!session) return alert('Activa una identidad primero');
  groupId = $<HTMLInputElement>('#group-id').value.trim();
  const log = $('#channel-log');
  log.replaceChildren();
  channelSub?.close();
  channelSub = session.pool.subscribe(session.relays, [{ ...channelFilter(groupId), limit: 100 }], {
    onevent: (evt) => {
      if (evt.kind !== 9) return;
      log.append(li(`[${new Date(evt.created_at * 1000).toLocaleString()}] ${shortNpub(evt.pubkey)}: ${evt.content}`));
    },
  });
});
$('#channel-send').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!session || !groupId) return alert('Abre un canal primero');
  const ta = $<HTMLTextAreaElement>('#channel-text');
  const rec = await session.engine.submit({ template: chatMessage(groupId, ta.value) }, { relays: session.relays, quorum: config.quorum });
  ta.value = '';
  text($('#outbox-h'), `Estado de entrega (último: ${rec.state})`);
});

// --- DMs (NIP-17 behind a flag)
// Explicit relay adapter from the interop gate (bounded gift-wrap jitter for the pinned Buzz build).
const messenger = () => new DirectMessenger(session!.signer, { nip17: $<HTMLInputElement>('#nip17-flag').checked, readReceipts: config.readReceipts }, BUZZ_PINNED_ADAPTER.wrap);
$('#dm-send').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!session) return alert('Activa una identidad primero');
  try {
    const msg = await messenger().compose({ recipients: [normalizePubkey($<HTMLInputElement>('#dm-to').value.trim())], content: $<HTMLTextAreaElement>('#dm-text').value });
    for (const w of msg.wraps) await session.engine.submit({ event: w.event }, { relays: session.relays, groupId: msg.rumor.id });
    $<HTMLTextAreaElement>('#dm-text').value = '';
  } catch (err) {
    alert(err instanceof FeatureDisabledError ? 'NIP-17 está deshabilitado (feature flag).' : (err as Error).message);
  }
});
$('#dm-refresh').addEventListener('click', async () => {
  if (!session) return;
  const log = $('#dm-log');
  log.replaceChildren();
  const wraps = await session.pool.query(session.relays, [dmInboxFilter(session.pubkey)], 8000);
  for (const w of wraps) {
    try {
      const m = await messenger().open(w);
      log.append(li(`[${new Date(m.rumor.created_at * 1000).toLocaleString()}] ${shortNpub(m.sender)}: ${m.rumor.content}`));
    } catch {
      /* ignore */
    }
  }
});

// --- outbox
async function renderOutbox() {
  if (!session) return;
  const rows = (await session.engine.list()).reverse().slice(0, 50).map((r) => {
    const tr = document.createElement('tr');
    const relays = Object.values(r.relayStatus).map((s) => `${new URL(s.relay).host}: ${s.acceptedAt ? 'OK' : s.permanent ? 'rechazado' : 'pendiente'} (${s.attemptCount})`).join('\n');
    for (const c of [r.opId.slice(0, 8), r.state, relays, r.blockedReason ?? r.failureReason ?? '']) {
      const td = document.createElement('td');
      td.textContent = c;
      td.style.whiteSpace = 'pre-line';
      tr.append(td);
    }
    return tr;
  });
  $('#outbox-rows').replaceChildren(...rows);
}
$('#outbox-resume').addEventListener('click', () => void session?.engine.resume().then(renderOutbox));

// --- sovereignty panel
const OPTIONS: Record<string, string[]> = {
  custody: ['local', 'offline', 'external', 'encrypted-backup', 'managed', 'managed-enclave'],
  network: ['direct', 'private-relay', 'multi-relay', 'tor-only'],
  identity: ['pseudonymous', 'linked', 'verified'],
  persistence: ['device', 'relay', 'replicated', 'encrypted-cloud'],
  messaging: ['nip17', 'marmot'],
  files: ['relay-plain', 'client-encrypted'],
  telemetry: ['standard', 'minimal', 'none'],
  notifications: ['push', 'privacy-push', 'none'],
  cloudBackup: ['off', 'ciphertext-user-key', 'operator-managed'],
  crashReports: ['off', 'manual-export', 'opt-in'],
};
const presetSel = $<HTMLSelectElement>('#preset');
for (const name of Object.keys(PRESETS)) presetSel.append(new Option(name, name));
presetSel.addEventListener('change', () => {
  config = preset(presetSel.value as PresetName);
  renderPanel();
});
function renderPanel() {
  const form = $('#panel-form');
  form.replaceChildren();
  for (const [key, opts] of Object.entries(OPTIONS)) {
    const label = document.createElement('label');
    label.textContent = key;
    const sel = document.createElement('select');
    sel.id = `cfg-${key}`;
    label.htmlFor = sel.id;
    for (const o of opts) sel.append(new Option(o, o, false, (config as unknown as Record<string, string>)[key] === o));
    sel.addEventListener('change', () => {
      config = { ...config, [key]: sel.value };
      renderPanel();
    });
    form.append(label, sel);
  }
  for (const key of ['remotePreviews', 'readReceipts', 'stripFileMetadata'] as const) {
    const label = document.createElement('label');
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.checked = config[key];
    cb.style.width = 'auto';
    cb.addEventListener('change', () => {
      config = { ...config, [key]: cb.checked };
      renderPanel();
    });
    label.append(cb, ` ${key}`);
    form.append(label);
  }
  const issues = validateConfig(config, 'web');
  $('#panel-issues').replaceChildren(...issues.map((i) => {
    const p = document.createElement('p');
    p.className = i.severity === 'error' ? 'error' : 'warn';
    p.textContent = `${i.severity === 'error' ? 'Bloqueante' : 'Aviso'}: ${i.message}`;
    return p;
  }));
  const dims = summarize(config);
  const names: Record<string, string> = { soberania: 'Soberanía', 'privacidad-operador': 'Privacidad frente al operador', recuperabilidad: 'Recuperabilidad', 'control-institucional': 'Control institucional' };
  $('#panel-dimensions').replaceChildren(...Object.entries(dims).map(([k, v]) => {
    const d = document.createElement('div');
    const h = document.createElement('h4');
    h.textContent = names[k]!;
    d.append(h, li(`Refuerzan: ${v.improvedBy.length}`), li(`Reducen: ${v.reducedBy.length}`));
    return d;
  }));
  $('#panel-disclosures').replaceChildren(...disclose(config).map((d) => li(`[${d.control}: ${d.option}] ${d.statement}${d.trustAssumptions.length ? ` — Confías en: ${d.trustAssumptions.join(' ')}` : ''}`)));
  refreshSendingAs();
}
renderPanel();

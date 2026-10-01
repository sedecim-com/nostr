import { useEffect, useState } from 'react';
import { Alert, Button, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, MenuItem, Stack, TextField, Typography } from '@mui/material';
import { BUZZ_PINNED_ADAPTER, NotYourMessageError, unwrappedExpiration, wrapOptionsFromFlags, type DirectMessage } from '@sedecim/messaging';
import { normalizePubkey } from '@sedecim/nostr-core';
import { MESSAGE_EXPIRATION_LABELS, MESSAGE_EXPIRATION_OPTIONS, MESSAGE_EXPIRATION_TEXTS, vaultExpirationNotice, type ExpirationSource, type MessageExpirationOption } from '@sedecim/profiles';
import { vaultUsage } from '../lib/continuity';
import { conversationExpiration, planDmDeletion, setConversationExpiration, type DmDeletionPlan } from '../lib/expiration';
import { useWorkspace } from '../lib/workspace';

const SOURCE: Record<ExpirationSource, string> = { conversation: 'elegida para esta conversación', persona: 'la de esta persona', profile: 'la de su perfil' };

/** When a message asks to expire, in the user's words (unix seconds). */
export const expiresText = (at: number) => `caduca el ${new Date(at * 1000).toLocaleString()}`;

/** The expiration a message carries, if any (PANEL-06). */
export function messageExpiresText(m: DirectMessage): string | undefined {
  const at = unwrappedExpiration(m);
  return at === undefined ? undefined : expiresText(at);
}

/** The contact a recipient field names, once it is a valid npub or hex key. */
function contactOf(to: string): string | undefined {
  try {
    return to.trim() ? normalizePubkey(to.trim()) : undefined;
  } catch {
    return undefined;
  }
}

/**
 * PANEL-06: the expiration of the conversation with `to` (a DM with one contact): its own choice or, without one, the
 * persona's. It applies to the messages written after it, and what it does and does not do is said next to it. When
 * the persona uses the Continuity Vault, changing it asks the vault its retention to say whether copies outlive it.
 */
export function ConversationExpiration({ to }: { to: string }) {
  const ws = useWorkspace();
  const s = ws.session!;
  const config = ws.config!;
  const contact = contactOf(to);
  const [state, setState] = useState<{ option: MessageExpirationOption; source: ExpirationSource; conversation?: MessageExpirationOption }>();
  const [retention, setRetention] = useState<number | null | undefined>();
  useEffect(() => {
    if (!contact) return setState(undefined);
    let live = true;
    void conversationExpiration(ws.book.store, s.persona, contact).then((r) => live && setState(r));
    return () => {
      live = false;
    };
  }, [contact, s.persona, ws.book]);
  if (!contact || !state) return null;
  const who = contact;

  const change = async (value: string) => {
    const option = value === 'persona' ? undefined : (value as MessageExpirationOption);
    await setConversationExpiration(ws.book.store, s.persona, who, option);
    const next = await conversationExpiration(ws.book.store, s.persona, who);
    setState(next);
    // Only on this explicit change, and only for a persona that uses the vault: the vault sees the request.
    if (next.option !== 'off' && ws.cfg.continuityVault && config.cloudBackup !== 'off') {
      const r = await vaultUsage(ws.cfg.continuityVault, s.persona).catch(() => undefined);
      setRetention(r?.retention ? r.retention.effective_days : undefined);
    }
    ws.notify(option === undefined ? 'Esta conversación sigue la caducidad de la persona.' : `Caducidad de esta conversación: ${MESSAGE_EXPIRATION_LABELS[option]}. Solo cambia los mensajes nuevos.`, 'success');
  };
  const notice = vaultExpirationNotice(state.option, { cloudBackup: config.cloudBackup, continuityVault: !!ws.cfg.continuityVault, retentionDays: retention });
  return (
    <Stack spacing={1} id="dm-expiration">
      <TextField select size="small" id="dm-expiration-select" label="Caducidad de esta conversación" value={state.conversation ?? 'persona'} onChange={(e) => void change(e.target.value)} sx={{ maxWidth: 360 }}>
        <MenuItem value="persona">Como la persona ({MESSAGE_EXPIRATION_LABELS[config.messageExpiration]})</MenuItem>
        {MESSAGE_EXPIRATION_OPTIONS.map((o) => (
          <MenuItem key={o} value={o}>
            {MESSAGE_EXPIRATION_LABELS[o]}
          </MenuItem>
        ))}
      </TextField>
      <Typography id="dm-expiration-now" variant="body2">
        {state.option === 'off' ? `Los mensajes nuevos a este contacto no piden caducar (${SOURCE[state.source]}).` : `Los mensajes nuevos a este contacto piden caducar a los ${MESSAGE_EXPIRATION_LABELS[state.option]} (${SOURCE[state.source]}, NIP-40).`}
      </Typography>
      {state.option !== 'off' && (
        <Alert severity="info" id="dm-expiration-facts">
          {[MESSAGE_EXPIRATION_TEXTS.request, MESSAGE_EXPIRATION_TEXTS.relay, MESSAGE_EXPIRATION_TEXTS.local, MESSAGE_EXPIRATION_TEXTS.past].join(' ')}
        </Alert>
      )}
      {notice && (
        <Alert severity="warning" id="dm-expiration-vault">
          {notice}
        </Alert>
      )}
    </Stack>
  );
}

/**
 * PANEL-06: «Borrar» on one of the persona's own messages. The dialog says what deleting does and what it cannot undo
 * (the copies already replicated) before anything is sent; only «Borrar» in it sends the deletion.
 */
export function DeleteOwnMessage({ message }: { message: DirectMessage }) {
  const ws = useWorkspace();
  const s = ws.session!;
  const [plan, setPlan] = useState<DmDeletionPlan>();
  const [busy, setBusy] = useState(false);
  if (message.sender !== s.pubkey) return null;
  const open = () => {
    try {
      setPlan(planDmDeletion(ws.book.store, s, message, { inbox: ws.dm.inbox, vaultUrl: ws.cfg.continuityVault, wrapOptions: wrapOptionsFromFlags(ws.flags, BUZZ_PINNED_ADAPTER.wrap) }));
    } catch (e) {
      ws.notify(e instanceof NotYourMessageError ? e.message : (e as Error).message, 'error');
    }
  };
  const confirm = async () => {
    if (!plan) return;
    setBusy(true);
    try {
      const r = await plan.confirm();
      ws.dm.refresh();
      const vault = r.vault ? ` Se borraron ${r.vault} copias del vault.` : r.vaultError ? ` El vault no respondió (${r.vaultError}): sus copias se intentarán borrar otra vez en la próxima purga.` : '';
      ws.notify(`Petición de borrado en la entrega, para ${r.deliveries.length > 1 ? 'sus destinatarios y ' : ''}tus otros dispositivos. Este navegador ya no lo guarda.${vault}`, r.vaultError ? 'warning' : 'success');
      setPlan(undefined);
    } catch (e) {
      ws.notify((e as Error).message, 'error');
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <Button size="small" color="error" onClick={open} aria-label="Borrar este mensaje">
        Borrar
      </Button>
      <Dialog open={!!plan} onClose={() => setPlan(undefined)} aria-labelledby="dm-delete-title">
        <DialogTitle id="dm-delete-title">¿Borrar este mensaje?</DialogTitle>
        <DialogContent id="dm-delete-notice">
          {plan?.notice.map((t) => (
            <DialogContentText key={t} sx={{ mb: 1 }}>
              {t}
            </DialogContentText>
          ))}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setPlan(undefined)}>Cancelar</Button>
          <Button id="dm-delete-confirm" color="error" onClick={() => void confirm()} disabled={busy}>
            Borrar
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
}

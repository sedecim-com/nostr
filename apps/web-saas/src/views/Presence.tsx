import { useEffect, useReducer, useState } from 'react';
import { Alert, Button, Card, CardContent, List, ListItem, ListItemText, MenuItem, Stack, TextField, Typography } from '@mui/material';
import { STATUS_MAX_CHARS, statusShownUntil, statusText, StatusTextError, type UserStatus } from '@sedecim/messaging';
import { PRESENCE_TEXTS, presenceOption, presencePolicy } from '@sedecim/profiles';
import { clearStatus, loadOwnStatus, publishStatus, STATUS_DURATIONS, STATUS_PROBLEM_TEXT } from '../lib/presence';
import { authorLabel } from '../lib/profiles';
import type { PersonaSession } from '../lib/session';
import { useWorkspace } from '../lib/workspace';
import { useProfiles } from './Profile';

/** FR015-05: re-renders the caller whenever the persona's status cache changes. */
function useStatuses(s: PersonaSession): void {
  const [, bump] = useReducer((n: number) => n + 1, 0);
  useEffect(() => s.statuses.onChange(bump), [s.statuses]);
}

const shownUntil = (st: UserStatus) => new Date(statusShownUntil(st) * 1000).toLocaleString();

/**
 * FR015-05: the persona's status (NIP-38). With presence off the card is not there and nothing is asked; where the
 * profile does not allow it (Tor-only, an organization), it only says why.
 */
export function PresenceCard() {
  const ws = useWorkspace();
  const config = ws.config!;
  if (presenceOption(config) === 'off') return null;
  const policy = presencePolicy(config);
  if (!policy.use)
    return (
      <Card id="presence">
        <CardContent>
          <Alert severity="info">{policy.statement}</Alert>
        </CardContent>
      </Card>
    );
  return <PresenceEditor />;
}

/** Only what the user writes and confirms is published: the preview shows the text exactly as it will go out. */
function PresenceEditor() {
  const ws = useWorkspace();
  const s = ws.session!;
  const config = ws.config!;
  useStatuses(s);
  useProfiles(s);
  const [text, setText] = useState('');
  const [ttl, setTtl] = useState(3600);
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  // The persona's own status, from its own relays (asking for its own npub tells them nothing about anyone else).
  useEffect(() => {
    let live = true;
    void loadOwnStatus(s, config)
      .catch(() => undefined)
      .finally(() => live && setLoaded(true));
    return () => {
      live = false;
    };
    // Once per open persona: a panel change that keeps presence on must not ask again.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [s.statuses, s.pubkey]);

  let preview = '';
  let problem = '';
  try {
    preview = statusText(text);
    if (!preview) problem = STATUS_PROBLEM_TEXT.empty;
  } catch (e) {
    problem = e instanceof StatusTextError ? STATUS_PROBLEM_TEXT[e.problem] : (e as Error).message;
  }
  const own = s.statuses.get(s.pubkey);
  const others = s.statuses
    .visible()
    .filter((st) => st.pubkey !== s.pubkey)
    .slice(0, 20);
  const duration = STATUS_DURATIONS.find((d) => d.seconds === ttl)?.label ?? '';

  const run = async (what: () => Promise<void>) => {
    setBusy(true);
    setError('');
    try {
      await what();
    } catch (e) {
      setError(e instanceof StatusTextError ? STATUS_PROBLEM_TEXT[e.problem] : (e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const publish = () =>
    void run(async () => {
      const rec = await publishStatus(s, config, text, ttl);
      setText('');
      ws.notify(rec.state === 'QUEUED' ? 'Estado en la cola de entrega hasta que un relay lo acepte.' : 'Estado publicado (kind 30315).', 'success');
    });
  const clear = () =>
    void run(async () => {
      const rec = await clearStatus(s, config);
      ws.notify(rec.state === 'QUEUED' ? 'Borrado en la cola de entrega hasta que un relay lo acepte.' : 'Estado borrado: se publicó uno vacío.', 'success');
    });

  return (
    <Card id="presence">
      <CardContent>
        <Stack spacing={2}>
          <Typography variant="h6" component="h2">
            Estado de presencia
          </Typography>
          <Typography variant="body2" sx={{ color: 'text.secondary' }}>
            {PRESENCE_TEXTS.what}
          </Typography>
          {config.identity === 'pseudonymous' && (
            <Alert severity="warning" id="presence-pseudonymous">
              {PRESENCE_TEXTS.pseudonymous}
            </Alert>
          )}
          <Typography variant="body2" id="presence-status" role="status">
            {!loaded ? 'Buscando tu estado en los relays de esta persona…' : own ? `Tu estado: «${own.text}». Caduca: ${shownUntil(own)}.` : 'Esta persona no tiene un estado publicado.'}
          </Typography>
          <TextField
            id="presence-text"
            label="Tu estado"
            value={text}
            onChange={(e) => setText(e.target.value)}
            disabled={!loaded}
            error={!!text && !!problem}
            helperText={text && problem ? problem : `${[...text].length}/${STATUS_MAX_CHARS}`}
            slotProps={{ htmlInput: { maxLength: STATUS_MAX_CHARS } }}
          />
          <TextField select id="presence-ttl" label="Caduca en" value={ttl} onChange={(e) => setTtl(Number(e.target.value))} disabled={!loaded}>
            {STATUS_DURATIONS.map((d) => (
              <MenuItem key={d.seconds} value={d.seconds}>
                {d.label}
              </MenuItem>
            ))}
          </TextField>
          {preview && !problem && (
            <Typography variant="body2" id="presence-preview">
              Se publicará «{preview}» durante {duration}.
            </Typography>
          )}
          <Typography variant="caption" sx={{ color: 'text.secondary' }}>
            {PRESENCE_TEXTS.limits}
          </Typography>
          <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap' }} useFlexGap>
            <Button id="presence-publish" variant="contained" disabled={busy || !loaded || !!problem} onClick={publish}>
              Publicar estado
            </Button>
            {own && (
              <Button id="presence-clear" color="warning" disabled={busy} onClick={clear}>
                Borrar estado
              </Button>
            )}
          </Stack>
          {own && (
            <Typography variant="caption" sx={{ color: 'text.secondary' }}>
              {PRESENCE_TEXTS.clear}
            </Typography>
          )}
          {error && <Alert severity="error">{error}</Alert>}
          <Typography variant="subtitle1" component="h3">
            Estados de otras personas
          </Typography>
          <Typography variant="caption" sx={{ color: 'text.secondary' }}>
            {PRESENCE_TEXTS.others}
          </Typography>
          {others.length === 0 ? (
            <Typography variant="body2">Todavía no hay estados de otras personas: llegan con sus perfiles, al abrir los canales y los mensajes directos.</Typography>
          ) : (
            <List id="presence-others" dense>
              {others.map((st) => (
                <ListItem key={st.pubkey}>
                  <ListItemText primary={st.text} secondary={`${authorLabel(s, st.pubkey)} · caduca: ${shownUntil(st)}`} />
                </ListItem>
              ))}
            </List>
          )}
        </Stack>
      </CardContent>
    </Card>
  );
}

import { useEffect, useMemo, useState } from 'react';
import { Alert, Card, CardContent, FormControlLabel, Stack, Switch, Typography } from '@mui/material';
import { browserPushEnv, disablePush, enablePush, pushAvailability, pushPreference, watchableRelays, type RelayWatch } from '../lib/push';
import { useWorkspace } from '../lib/workspace';
import { MaturityChip } from './MaturityChip';

/** OPS-06: what happens to activity on the persona's relays the gateway does not watch. */
function partialText(w: RelayWatch): string {
  const parts = [
    w.unobservable.length ? `en ${w.unobservable.join(', ')} no puede ver tu actividad sin acceso a tus DMs` : '',
    w.unserved.length ? `${w.unserved.join(', ')} no los vigila este gateway` : '',
    w.pending.length ? `${w.pending.join(', ')} aún lo está comprobando` : '',
  ].filter(Boolean);
  return `El gateway solo vigila ${w.watchable.join(', ')}: ${parts.join('; ')}. Lo que llegue allí no genera aviso.`;
}

const MODE_TEXT: Record<string, string> = {
  push: 'Push opaco: aviso agrupado con un retardo aleatorio de segundos.',
  'privacy-push': 'Solo aviso de actividad: agrupado con un retardo aleatorio de varios minutos.',
};

/**
 * Opt-in "Notificaciones" (ADR 0010). Only rendered when the deployment has a notification gateway;
 * sovereign and Tor personas see why it is off instead of a switch, and so do personas whose relays the
 * gateway cannot watch without reading access to their DMs (OPS-06).
 */
export function NotificationsControl() {
  const ws = useWorkspace();
  const gateway = ws.cfg.notificationGateway;
  const session = ws.session;
  const env = useMemo(() => browserPushEnv(), []);
  const availability = pushAvailability(gateway, ws.config, env);
  const personaId = session?.persona.id;
  const [on, setOn] = useState(false);
  const [busy, setBusy] = useState(false);
  // undefined: still asking the gateway; null: it did not answer (the switch stays, registering reports the error).
  const [watch, setWatch] = useState<RelayWatch | null | undefined>(undefined);

  // The gateway keeps registrations in memory only: refresh ours each time the persona is opened, where it can watch.
  useEffect(() => {
    setWatch(undefined);
    if (!personaId || !session || !gateway || availability.state !== 'available') return setOn(false);
    const wanted = pushPreference(personaId);
    setOn(wanted);
    let live = true;
    void watchableRelays(gateway, session.persona.relays).then(
      (w) => {
        if (!live) return;
        setWatch(w);
        if (!w.watchable.length) return setOn(false);
        if (wanted && typeof Notification !== 'undefined' && Notification.permission === 'granted') {
          void enablePush(gateway, { ...session.persona, config: ws.config! }, { env, signer: session.signer }).catch(() => live && setOn(false));
        }
      },
      () => live && setWatch(null),
    );
    return () => {
      live = false;
    };
  }, [personaId, gateway, availability.state]);

  if (availability.state === 'hidden' || !session) return null;

  const toggle = async (next: boolean) => {
    setBusy(true);
    try {
      if (next) {
        const r = await enablePush(gateway!, { ...session.persona, config: ws.config! }, { env, signer: session.signer });
        setOn(true);
        ws.notify(`Notificaciones activadas (${r.mode})`, 'success');
      } else {
        await disablePush(gateway!, session.persona, { env, signer: session.signer });
        setOn(false);
        ws.notify('Notificaciones desactivadas en este navegador', 'info');
      }
    } catch (e) {
      ws.notify((e as Error).message, 'error');
    } finally {
      setBusy(false);
    }
  };

  const body = () => {
    if (availability.state !== 'available') {
      return (
        <Alert id="notifications-off" severity="info">
          {availability.reason}
        </Alert>
      );
    }
    if (watch && !watch.watchable.length) {
      if (watch.pending.length) {
        return (
          <Alert id="notifications-checking" severity="info">
            El gateway de notificaciones todavía está comprobando si puede ver actividad en tus relays. Vuelve a abrir esta sección en unos minutos.
          </Alert>
        );
      }
      return watch.unobservable.length ? (
        <Alert id="notifications-unobservable" severity="info">
          Tus relays entregan los mensajes cifrados solo a su destinatario, así que el gateway de notificaciones no puede saber cuándo tienes actividad sin acceso a tus DMs, y no lo tiene. Por eso aquí no hay notificaciones push: la app consulta los relays solo mientras está abierta.
        </Alert>
      ) : (
        <Alert id="notifications-unserved" severity="info">
          El gateway de notificaciones de este despliegue no vigila ninguno de tus relays, así que no puede avisarte. La app consulta los relays solo mientras está abierta.
        </Alert>
      );
    }
    return (
      <>
        <FormControlLabel control={<Switch id="notifications-toggle" checked={on} disabled={busy || watch === undefined} onChange={(e) => void toggle(e.target.checked)} />} label="Avisarme de actividad nueva en este navegador" />
        <Typography variant="body2">
          {MODE_TEXT[availability.policy.mode]} El aviso dice solo «Tienes actividad nueva»: no incluye contenido, remitente ni número de mensajes. El servicio push del navegador ve cuándo llega un aviso y el gateway de notificaciones sabe qué npub vigila para este navegador.
        </Typography>
        {watch && watch.watchable.length < session.persona.relays.length && (
          <Typography id="notifications-partial" variant="body2" sx={{ color: 'text.secondary' }}>
            {partialText(watch)}
          </Typography>
        )}
      </>
    );
  };

  return (
    <Card id="notifications-control">
      <CardContent>
        <Stack spacing={1}>
          <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
            <Typography variant="h6" component="h2">
              Notificaciones
            </Typography>
            <MaturityChip id="push" />
          </Stack>
          {body()}
        </Stack>
      </CardContent>
    </Card>
  );
}

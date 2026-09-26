import { useEffect, useMemo, useState } from 'react';
import { Alert, Card, CardContent, FormControlLabel, Stack, Switch, Typography } from '@mui/material';
import { browserPushEnv, disablePush, enablePush, pushAvailability, pushPreference } from '../lib/push';
import { useWorkspace } from '../lib/workspace';

const MODE_TEXT: Record<string, string> = {
  push: 'Push opaco: aviso agrupado con un retardo aleatorio de segundos.',
  'privacy-push': 'Solo aviso de actividad: agrupado con un retardo aleatorio de varios minutos.',
};

/**
 * Opt-in "Notificaciones" (ADR 0010). Only rendered when the deployment has a notification gateway;
 * sovereign and Tor personas see why it is off instead of a switch.
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

  // The gateway keeps registrations in memory only: refresh ours each time the persona is opened.
  useEffect(() => {
    if (!personaId || !session || !gateway || availability.state !== 'available') return setOn(false);
    const wanted = pushPreference(personaId);
    setOn(wanted);
    if (wanted && typeof Notification !== 'undefined' && Notification.permission === 'granted') {
      void enablePush(gateway, { ...session.persona, config: ws.config! }, { env, signer: session.signer }).catch(() => setOn(false));
    }
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

  return (
    <Card id="notifications-control">
      <CardContent>
        <Stack spacing={1}>
          <Typography variant="h6" component="h2">
            Notificaciones
          </Typography>
          {availability.state === 'available' ? (
            <>
              <FormControlLabel control={<Switch id="notifications-toggle" checked={on} disabled={busy} onChange={(e) => void toggle(e.target.checked)} />} label="Avisarme de actividad nueva en este navegador" />
              <Typography variant="body2">
                {MODE_TEXT[availability.policy.mode]} El aviso dice solo «Tienes actividad nueva»: no incluye contenido, remitente ni número de mensajes. El servicio push del navegador ve cuándo llega un aviso y el gateway de notificaciones sabe qué npub vigila para este navegador.
              </Typography>
            </>
          ) : (
            <Alert id="notifications-off" severity="info">
              {availability.reason}
            </Alert>
          )}
        </Stack>
      </CardContent>
    </Card>
  );
}

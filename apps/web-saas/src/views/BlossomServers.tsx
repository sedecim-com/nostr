import { useEffect, useState } from 'react';
import { Alert, Button, Card, CardContent, Stack, TextField, Typography } from '@mui/material';
import { buildServerList, normalizeServerUrl } from '@sedecim/blossom-client';
import { blossomServersOf, uploadTargets } from '../lib/blossom';
import { useWorkspace } from '../lib/workspace';

/**
 * FR018-05: the persona's Blossom server list (BUD-03, kind 10063). Uploads go to the first server that
 * can take the file; downloads fall back to the sender's servers. Encrypted attachments never go to an
 * image-only media server.
 */
export function BlossomServers() {
  const ws = useWorkspace();
  const s = ws.session!;
  const [text, setText] = useState('');
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => {
    let live = true;
    void blossomServersOf(s).then((list) => {
      if (!live) return;
      setText(list.join('\n'));
      setLoaded(true);
    });
    return () => {
      live = false;
    };
  }, [s]);
  const servers = text.split('\n').map((l) => l.trim()).filter(Boolean);
  const encryptedTargets = (() => {
    try {
      return uploadTargets(ws.cfg, servers.map(normalizeServerUrl), true);
    } catch {
      return [];
    }
  })();

  const publish = async () => {
    setBusy(true);
    setError('');
    try {
      const tmpl = buildServerList(servers);
      const rec = await s.engine.submit({ template: tmpl }, { relays: s.persona.relays, quorum: 1, wait: true });
      if (rec.state === 'FAILED') throw new Error(rec.failureReason ?? 'el relay rechazó la lista');
      setText(tmpl.tags!.map((t) => t[1]).join('\n'));
      ws.notify(servers.length ? 'Lista de servidores Blossom publicada (kind 10063)' : 'Lista de servidores Blossom vaciada', 'success');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <CardContent>
        <Stack spacing={2}>
          <Typography variant="h6" component="h2" id="blossom-servers-h">
            Servidores de archivos (Blossom)
          </Typography>
          <Typography variant="body2" sx={{ color: 'text.secondary' }}>
            Tu lista pública de servidores (kind 10063): los adjuntos se suben al primero que los acepte y otros clientes buscan ahí tus archivos si el enlace falla. Cada servidor ve tu IP, el tamaño y la hora de cada archivo; los adjuntos de mensajes directos se cifran antes de subirlos.
          </Typography>
          <TextField id="blossom-servers" label="Servidores (uno por línea, el primero es el principal)" multiline minRows={2} value={text} onChange={(e) => setText(e.target.value)} disabled={!loaded} placeholder="https://blossom.example" />
          <Typography variant="body2" id="blossom-encrypted-route">
            {encryptedTargets.length ? `Adjuntos cifrados: ${encryptedTargets.map((u) => new URL(u).host).join(' → ')}` : 'Adjuntos cifrados: no hay servidor disponible.'}
          </Typography>
          <Stack direction="row" spacing={1}>
            <Button id="blossom-publish" variant="outlined" onClick={() => void publish()} disabled={busy || !loaded}>
              Publicar lista de servidores
            </Button>
          </Stack>
          {error && <Alert severity="error">{error}</Alert>}
        </Stack>
      </CardContent>
    </Card>
  );
}

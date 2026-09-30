import { useState } from 'react';
import { Alert, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Typography } from '@mui/material';
import type { PolicyAdminApi, Resource, Sensitivity } from '../api';
import { parseMembers, parseRules, SENSITIVITIES } from '../forms';
import { shortNpub } from '../signers';
import { errorText, useLoad } from '../ui';

const KINDS: Resource['kind'][] = ['workspace', 'channel', 'group'];
const KIND_LABEL: Record<Resource['kind'], string> = { workspace: 'Espacio de trabajo', channel: 'Canal', group: 'Grupo MLS' };
const SENS_LABEL: Record<Sensitivity, string> = { public: 'Pública', internal: 'Interna', confidential: 'Confidencial', secret: 'Secreta' };
const RULE_EXAMPLE = '[{ "actions": ["read", "publish"], "anyRole": ["staff"], "minDeviceTrust": "registered" }]';

type Editing = { isNew: boolean; id: string; kind: Resource['kind']; sensitivity: Sensitivity; rules: string; members: string };

export function ResourcesView({ api }: { api: PolicyAdminApi }) {
  const { data, error, reload } = useLoad(api.listResources, [api]);
  const [editing, setEditing] = useState<Editing | undefined>();
  const [formError, setFormError] = useState<string | undefined>();
  const [busy, setBusy] = useState(false);

  const open = (r?: Resource) => {
    setFormError(undefined);
    setEditing(
      r
        ? { isNew: false, id: r.id, kind: r.kind, sensitivity: r.sensitivity, rules: JSON.stringify(r.rules, null, 2), members: (r.members ?? []).join('\n') }
        : { isNew: true, id: '', kind: 'channel', sensitivity: 'internal', rules: '[]', members: '' },
    );
  };

  const save = async () => {
    if (!editing) return;
    setBusy(true);
    setFormError(undefined);
    try {
      const id = editing.id.trim();
      if (!/^[A-Za-z0-9._:-]{1,128}$/.test(id)) throw new Error('ID inválido: letras, números y . _ : - (máx. 128)');
      const members = parseMembers(editing.members);
      await api.putResource(id, { kind: editing.kind, sensitivity: editing.sensitivity, rules: parseRules(editing.rules), ...(members ? { members } : {}) });
      setEditing(undefined);
      await reload();
    } catch (e) {
      setFormError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const set = (patch: Partial<Editing>) => setEditing((x) => x && { ...x, ...patch });

  return (
    <Stack spacing={2}>
      <Stack direction="row" sx={{ alignItems: 'center', justifyContent: 'space-between' }}>
        <Typography variant="h5" component="h2">
          Recursos y políticas
        </Typography>
        <Button variant="contained" onClick={() => open()}>
          Nuevo recurso
        </Button>
      </Stack>
      <Typography variant="body2" sx={{ color: 'text.secondary' }}>
        Denegar por defecto: una acción solo se permite si alguna regla la concede. Desde «confidencial», además, hace falta clearance suficiente y un dispositivo registrado.
      </Typography>
      {error && <Alert severity="error">{error}</Alert>}
      <TableContainer>
        <Table size="small" aria-label="Recursos">
          <TableHead>
            <TableRow>
              <TableCell>ID</TableCell>
              <TableCell>Tipo</TableCell>
              <TableCell>Sensibilidad</TableCell>
              <TableCell>Reglas</TableCell>
              <TableCell>Miembros</TableCell>
              <TableCell>Acciones</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {data?.map((r) => (
              <TableRow key={r.id} data-resource={r.id}>
                <TableCell>{r.id}</TableCell>
                <TableCell>{KIND_LABEL[r.kind]}</TableCell>
                <TableCell>
                  <Chip size="small" label={SENS_LABEL[r.sensitivity]} color={r.sensitivity === 'secret' ? 'error' : r.sensitivity === 'confidential' ? 'warning' : 'default'} />
                </TableCell>
                <TableCell>{r.rules.length}</TableCell>
                <TableCell title={(r.members ?? []).join('\n')}>{r.members ? r.members.map(shortNpub).join(', ') || 'ninguno' : 'sin lista'}</TableCell>
                <TableCell>
                  <Button size="small" onClick={() => open(r)}>
                    Editar
                  </Button>
                </TableCell>
              </TableRow>
            ))}
            {data?.length === 0 && (
              <TableRow>
                <TableCell colSpan={6}>No hay recursos.</TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>

      <Dialog open={!!editing} onClose={() => setEditing(undefined)} aria-labelledby="resource-dialog-title" fullWidth maxWidth="md">
        <DialogTitle id="resource-dialog-title">{editing?.isNew ? 'Nuevo recurso' : `Editar ${editing?.id}`}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            {formError && <Alert severity="error">{formError}</Alert>}
            <TextField id="resource-id" label="ID" value={editing?.id ?? ''} disabled={!editing?.isNew} onChange={(e) => set({ id: e.target.value })} />
            <TextField id="resource-kind" select label="Tipo" value={editing?.kind ?? 'channel'} onChange={(e) => set({ kind: e.target.value as Resource['kind'] })} slotProps={{ select: { native: true } }}>
              {KINDS.map((k) => (
                <option key={k} value={k}>
                  {KIND_LABEL[k]}
                </option>
              ))}
            </TextField>
            <TextField id="resource-sensitivity" select label="Sensibilidad" value={editing?.sensitivity ?? 'internal'} onChange={(e) => set({ sensitivity: e.target.value as Sensitivity })} slotProps={{ select: { native: true } }}>
              {SENSITIVITIES.map((s) => (
                <option key={s} value={s}>
                  {SENS_LABEL[s]}
                </option>
              ))}
            </TextField>
            <TextField id="resource-rules" label="Reglas (JSON)" multiline minRows={4} value={editing?.rules ?? ''} onChange={(e) => set({ rules: e.target.value })} helperText={`Ejemplo: ${RULE_EXAMPLE}`} slotProps={{ htmlInput: { spellCheck: false } }} sx={{ '& textarea': { fontFamily: 'monospace' } }} />
            <TextField id="resource-members" label="Miembros explícitos" multiline minRows={2} value={editing?.members ?? ''} onChange={(e) => set({ members: e.target.value })} helperText="Un npub o clave hex por línea. Vacío: sin lista de miembros." />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditing(undefined)}>Cancelar</Button>
          <Button variant="contained" disabled={busy} onClick={() => void save()}>
            Guardar
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
}

import { useEffect, useState } from 'react';
import { Accordion, AccordionDetails, AccordionSummary, Alert, Box, Button, Card, CardContent, Checkbox, Chip, FormControlLabel, Link, List, ListItem, ListItemText, MenuItem, Stack, TextField, Typography } from '@mui/material';
import { PRESETS, configMaturity, disclose, preset, summarize, validateConfig, type PresetName, type SovereigntyConfig } from '@sedecim/profiles';
import { useWorkspace } from '../lib/workspace';
import { NotificationsControl } from './NotificationsControl';
import { MaturityChip } from './MaturityChip';

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
  continuity: ['off', 'best-effort', 'required-for-resilient'],
  crashReports: ['off', 'manual-export', 'opt-in'],
  localProtection: ['passphrase', 'device'],
};
const FLAGS = ['remotePreviews', 'deliveryReceipts', 'readReceipts', 'stripFileMetadata'] as const;
const DIMENSIONS: Record<string, string> = { soberania: 'Soberanía', 'privacidad-operador': 'Privacidad frente al operador', recuperabilidad: 'Recuperabilidad', 'control-institucional': 'Control institucional' };

/**
 * Sovereignty panel (spec §9) for the active persona. Saving applies the configuration to the client
 * (PANEL-02: quorum, receipts, previews, attachments, Tor-only blocking) and persists it encrypted in the
 * persona's vault record (PANEL-03). Blocking issues cannot be saved.
 */
export function PanelView() {
  const ws = useWorkspace();
  const [draft, setDraft] = useState<SovereigntyConfig>(ws.config!);
  useEffect(() => setDraft(ws.config!), [ws.config]);
  // FR010-04: the quorum is checked against this persona's relays, so it is refused rather than capped in silence.
  // VAULT-04: and the Continuity Vault policy against the deployment (without a vault, `required` would hold every send).
  const issues = validateConfig(draft, 'web', { relays: ws.session?.persona.relays.length, continuityVault: !!ws.cfg.continuityVault });
  const blocking = issues.some((i) => i.severity === 'error');
  // PANEL-07: the least mature of what this configuration uses (and private-resilient is never above Beta without a vault).
  const maturityNow = configMaturity(draft, { continuityVault: !!ws.cfg.continuityVault });
  const dirty = JSON.stringify(draft) !== JSON.stringify(ws.config);
  const set = (patch: Partial<SovereigntyConfig>) => setDraft((d) => ({ ...d, ...patch }));

  return (
    <Stack spacing={2}>
      <Card>
        <CardContent>
          <Stack spacing={2}>
            <TextField select id="preset" label="Partir de un perfil" value="" onChange={(e) => setDraft({ ...preset(e.target.value as PresetName), custody: ws.config!.custody })}>
              {Object.keys(PRESETS).map((n) => (
                <MenuItem key={n} value={n}>
                  {n}
                </MenuItem>
              ))}
            </TextField>
            <Stack direction="row" spacing={1} sx={{ alignItems: 'center', flexWrap: 'wrap' }} useFlexGap id="panel-maturity">
              <Typography variant="body2">Madurez de esta configuración:</Typography>
              <MaturityChip level={maturityNow.level} why={maturityNow.parts[0]!.why} />
              <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                {maturityNow.parts
                  .filter((p) => p.level === maturityNow.level)
                  .map((p) => `${p.name}: ${p.why}`)
                  .join(' ')}
              </Typography>
            </Stack>
            <Box id="panel-form" sx={{ display: 'grid', gridTemplateColumns: { sm: '1fr 1fr', md: '1fr 1fr 1fr' }, gap: 2 }}>
              {/* PANEL-05: custody is a fact of the persona (its key or signer), not a setting: shown, not chosen. */}
              {Object.entries(OPTIONS).map(([key, opts]) => (
                <TextField key={key} select id={`cfg-${key}`} label={key} value={(draft as unknown as Record<string, string>)[key]} disabled={key === 'custody'} helperText={key === 'custody' ? 'La de esta persona: no se cambia desde el panel' : undefined} slotProps={{ formHelperText: { sx: { '&.Mui-disabled': { color: 'text.secondary' } } } }} onChange={(e) => set({ [key]: e.target.value } as Partial<SovereigntyConfig>)}>
                  {opts.map((o) => (
                    <MenuItem key={o} value={o}>
                      {o}
                    </MenuItem>
                  ))}
                </TextField>
              ))}
              <TextField id="cfg-quorum" label="quorum" type="number" value={draft.quorum} onChange={(e) => set({ quorum: Number(e.target.value) })} slotProps={{ htmlInput: { min: 1, max: 5 } }} />
              {FLAGS.map((k) => (
                <FormControlLabel key={k} control={<Checkbox id={`cfg-${k}`} checked={draft[k]} onChange={(e) => set({ [k]: e.target.checked } as Partial<SovereigntyConfig>)} />} label={k} />
              ))}
            </Box>
            <Box id="panel-issues">
              {issues.map((i) => (
                <Alert key={i.code} severity={i.severity === 'error' ? 'error' : 'warning'} sx={{ mb: 1 }}>
                  {i.severity === 'error' ? 'Bloqueante' : 'Aviso'}: {i.message}
                </Alert>
              ))}
            </Box>
            <Stack direction="row" spacing={1}>
              <Button id="panel-save" variant="contained" disabled={!dirty || blocking} onClick={() => void ws.saveConfig(draft).then(() => ws.notify('Configuración aplicada a esta persona', 'success'))}>
                Aplicar a esta persona
              </Button>
              <Button disabled={!dirty} onClick={() => setDraft(ws.config!)}>
                Descartar cambios
              </Button>
            </Stack>
            {draft.localProtection !== ws.config!.localProtection && <Alert severity="info">El cambio de contraseña del almacén se aplica desde Personas → Protección de este navegador.</Alert>}
          </Stack>
        </CardContent>
      </Card>
      {/* PANEL-04: one indicator per dimension, each backed by the statements that move it; never a single score. */}
      <Box id="panel-dimensions" sx={{ display: 'grid', gridTemplateColumns: { sm: '1fr 1fr', md: 'repeat(4, 1fr)' }, gap: 2, alignItems: 'start' }}>
        {Object.entries(summarize(draft)).map(([k, v]) => (
          <Accordion key={k} disableGutters>
            <AccordionSummary aria-controls={`dim-${k}`} id={`dim-${k}-h`}>
              <Stack spacing={1}>
                <Typography variant="subtitle1" component="h3">
                  {DIMENSIONS[k]}
                </Typography>
                <Stack direction="row" spacing={1}>
                  <Chip size="small" variant="outlined" label={`Refuerzan: ${v.improvedBy.length}`} />
                  <Chip size="small" variant="outlined" label={`Reducen: ${v.reducedBy.length}`} />
                </Stack>
              </Stack>
            </AccordionSummary>
            <AccordionDetails>
              {[...v.improvedBy.map((st) => ['Refuerza', st] as const), ...v.reducedBy.map((st) => ['Reduce', st] as const)].map(([kind, st]) => {
                const d = disclose(draft).find((x) => x.statement === st);
                return (
                  <Typography key={`${kind}:${st}`} variant="body2" sx={{ mb: 1 }}>
                    <strong>{kind}:</strong> {st} {d && <Link href={`#disc-${d.control}`}>ver consecuencia</Link>}
                  </Typography>
                );
              })}
              {v.improvedBy.length + v.reducedBy.length === 0 && <Typography variant="body2">Ningún ajuste afecta a esta dimensión.</Typography>}
            </AccordionDetails>
          </Accordion>
        ))}
      </Box>
      <NotificationsControl />
      <Card>
        <CardContent>
          <Typography variant="h6" component="h2">
            Consecuencias de esta configuración
          </Typography>
          <List id="panel-disclosures" dense>
            {disclose(draft).map((d) => (
              <ListItem key={`${d.control}:${d.option}`} id={`disc-${d.control}`}>
                <ListItemText primary={`[${d.control}: ${d.option}] ${d.statement}`} secondary={d.trustAssumptions.length ? `Confías en: ${d.trustAssumptions.join(' ')}` : undefined} />
              </ListItem>
            ))}
          </List>
        </CardContent>
      </Card>
    </Stack>
  );
}

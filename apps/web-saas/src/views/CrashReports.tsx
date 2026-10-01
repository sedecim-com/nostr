import { Component, useEffect, useMemo, useState, useSyncExternalStore, type ErrorInfo, type ReactNode } from 'react';
import { Alert, Box, Button, Card, CardContent, List, ListItem, ListItemText, Stack, Typography } from '@mui/material';
import { disclose } from '@sedecim/profiles';
import { crashReportJson, crashSummary, type CrashReport, type StoredCrashReport } from '@sedecim/telemetry-policy/crash-report';
import { crashStore, downloadCrashReport, webCrashReports } from '../lib/crash';
import { useWorkspace } from '../lib/workspace';

/**
 * NFR007-03: a view that throws while rendering stops alone, the rest of the app goes on, and its failure is captured
 * as the active persona's profile says (nothing in 'off').
 */
export class CrashBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  override state = { failed: false };

  static getDerivedStateFromError(): { failed: boolean } {
    return { failed: true };
  }

  override componentDidCatch(error: unknown, info: ErrorInfo): void {
    webCrashReports().componentError(error, info.componentStack);
  }

  override render(): ReactNode {
    if (!this.state.failed) return this.props.children;
    const captured = webCrashReports().capture.currentMode !== 'off';
    return (
      <Alert
        severity="error"
        id="crash-boundary"
        action={
          <Button color="inherit" onClick={() => this.setState({ failed: false })}>
            Reintentar
          </Button>
        }
      >
        Esta sección ha fallado y se ha detenido; el resto de la app sigue funcionando.
        {captured ? ' El informe del fallo está en Soberanía y privacidad, en «Informes de fallo».' : ''}
      </Alert>
    );
  }
}

/**
 * NFR007-03: the reports of this browser. What the profile does is the reviewed statement of its option; the last
 * failure is in memory only, and a report is saved in a file only after showing exactly what the file holds.
 */
export function CrashReportsCard() {
  const ws = useWorkspace();
  const crash = webCrashReports();
  const revision = useSyncExternalStore(crash.capture.subscribe, crash.capture.revision);
  const config = ws.config!;
  const mode = config.crashReports;
  const statement = disclose(config).find((d) => d.control === 'crashReports')?.statement;
  const last = crash.capture.lastReport();
  const store = useMemo(() => crashStore(ws.book.store), [ws.book]);
  const [saved, setSaved] = useState<StoredCrashReport[]>([]);
  const [preview, setPreview] = useState<{ id: string; report: CrashReport }>();
  const [error, setError] = useState('');

  // Reading the list also applies the retention: what is past it is deleted from the vault.
  useEffect(() => {
    let live = true;
    store.list().then(
      (list) => live && setSaved(list),
      () => live && setSaved([]),
    );
    return () => {
      live = false;
    };
  }, [store, revision]);

  const run = (fn: () => Promise<void>) => {
    setError('');
    fn().catch((e: unknown) => setError(e instanceof Error ? e.message : 'No se pudo completar'));
  };
  const remove = (id: string) =>
    run(async () => {
      await store.remove(id);
      if (preview?.id === id) setPreview(undefined);
      crash.capture.changed();
    });
  const clear = () =>
    run(async () => {
      await store.clear();
      setPreview(undefined);
      crash.capture.changed();
    });

  return (
    <Card id="crash-reports">
      <CardContent>
        <Stack spacing={2}>
          <Typography variant="h6" component="h2">
            Informes de fallo
          </Typography>
          {statement && (
            <Typography variant="body2" id="crash-mode">
              {statement}
            </Typography>
          )}
          {mode !== 'off' &&
            (last ? (
              <Stack direction="row" spacing={1} sx={{ alignItems: 'center', flexWrap: 'wrap' }} useFlexGap>
                <Typography variant="body2" id="crash-last">
                  Último fallo en esta pestaña: {crashSummary(last)}
                </Typography>
                <Button id="crash-last-view" onClick={() => setPreview({ id: 'last', report: last })}>
                  Ver el informe
                </Button>
                <Button
                  id="crash-last-forget"
                  onClick={() => {
                    crash.capture.forgetLast();
                    if (preview?.id === 'last') setPreview(undefined);
                  }}
                >
                  Olvidar este informe
                </Button>
              </Stack>
            ) : (
              <Typography variant="body2" id="crash-last" sx={{ color: 'text.secondary' }}>
                No hay ningún fallo capturado desde que abriste esta persona en esta pestaña.
              </Typography>
            ))}
          {saved.length > 0 && (
            <Box>
              <Typography variant="subtitle2" component="h3">
                Guardados cifrados en este navegador ({saved.length})
              </Typography>
              {mode !== 'opt-in' && (
                <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                  Esta persona no guarda informes nuevos: estos se guardaron cuando una persona de este navegador lo tenía activado.
                </Typography>
              )}
              <List dense id="crash-saved">
                {saved.map((r) => (
                  <ListItem key={r.id} disableGutters>
                    <ListItemText primary={crashSummary(r.report)} secondary={`${new Date(r.savedAt).toLocaleString()}${r.count > 1 ? ` · ${r.count} veces` : ''}`} />
                    <Button size="small" onClick={() => setPreview({ id: r.id, report: r.report })}>
                      Ver
                    </Button>
                    <Button size="small" color="error" onClick={() => remove(r.id)}>
                      Borrar
                    </Button>
                  </ListItem>
                ))}
              </List>
              <Button id="crash-clear" color="error" onClick={clear}>
                Borrar todos los informes guardados
              </Button>
            </Box>
          )}
          {preview && (
            <Box>
              <Typography variant="body2">Esto es exactamente lo que guarda el archivo. No se envía a ningún sitio: si quieres compartirlo, lo envías tú.</Typography>
              <Box component="pre" id="crash-preview" sx={{ maxHeight: 320, overflow: 'auto', fontSize: 12, whiteSpace: 'pre-wrap', wordBreak: 'break-word', bgcolor: 'action.hover', p: 1, borderRadius: 1 }}>
                {crashReportJson(preview.report)}
              </Box>
              <Stack direction="row" spacing={1}>
                <Button id="crash-save-file" variant="contained" onClick={() => downloadCrashReport(preview.report)}>
                  Guardar en un archivo
                </Button>
                <Button onClick={() => setPreview(undefined)}>Cerrar la vista previa</Button>
              </Stack>
            </Box>
          )}
          {error && <Alert severity="error">{error}</Alert>}
        </Stack>
      </CardContent>
    </Card>
  );
}

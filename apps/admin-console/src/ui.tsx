import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { Alert, Button, Dialog, DialogActions, DialogContent, DialogTitle, List, ListItem, ListItemText } from '@mui/material';
import { ApiError, type RotationRequired } from './api';
import { shortNpub } from './signers';

export function errorText(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.status === 401) return `Autenticación NIP-98 rechazada: ${e.message}`;
    if (e.status === 403) return 'Esta llave no es administradora del policy-engine (POLICY_ADMIN_PUBKEYS).';
    return e.status ? `Error ${e.status}: ${e.message}` : e.message;
  }
  return (e as Error)?.message ?? String(e);
}

/** Loads data on mount and on reload(); keeps the last error visible. */
export function useLoad<T>(fn: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | undefined>();
  const [error, setError] = useState<string | undefined>();
  const [loading, setLoading] = useState(true);
  const load = useCallback(fn, deps);
  const reload = useCallback(async () => {
    setLoading(true);
    try {
      setData(await load());
      setError(undefined);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setLoading(false);
    }
  }, [load]);
  useEffect(() => {
    void reload();
  }, [reload]);
  return { data, error, loading, reload, setError };
}

export const fmtDate = (ms: number) => new Date(ms).toLocaleString('es');

export function ConfirmDialog(props: { open: boolean; title: string; children: ReactNode; confirm: string; danger?: boolean; busy?: boolean; onConfirm(): void; onClose(): void; id: string }) {
  return (
    <Dialog open={props.open} onClose={props.onClose} aria-labelledby={`${props.id}-title`}>
      <DialogTitle id={`${props.id}-title`}>{props.title}</DialogTitle>
      <DialogContent>{props.children}</DialogContent>
      <DialogActions>
        <Button onClick={props.onClose}>Cancelar</Button>
        <Button onClick={props.onConfirm} disabled={props.busy} color={props.danger ? 'error' : 'primary'} variant="contained">
          {props.confirm}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/** Rotations returned by a revocation: every listed MLS group needs a commit removing the member. */
export function RotationsResult({ rotations, id }: { rotations: RotationRequired[]; id: string }) {
  if (rotations.length === 0)
    return (
      <Alert severity="info" id={id}>
        Revocación aplicada. No hay grupos MLS que rotar.
      </Alert>
    );
  return (
    <Alert severity="warning" id={id}>
      Revocación aplicada. Rotaciones de clave MLS requeridas ({rotations.length}):
      <List dense>
        {rotations.map((r, i) => (
          <ListItem key={r.id ?? `${r.resourceId}-${i}`} disableGutters>
            <ListItemText primary={`Grupo ${r.resourceId}`} secondary={`${r.reason} · quitar ${shortNpub(r.removedPubkey)}`} />
          </ListItem>
        ))}
      </List>
    </Alert>
  );
}

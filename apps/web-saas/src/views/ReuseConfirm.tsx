import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Button, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, List, ListItem, ListItemText } from '@mui/material';
import type { PersonaUse, ReuseWarning } from '@sedecim/identity/usage';
import { recordUse, reuseWarnings } from '../lib/compartment';
import { useWorkspace } from '../lib/workspace';

export interface ReuseConfirm {
  /** Resolves true when nothing is crossed or the user confirms; false when they cancel (then nothing may go out). */
  confirm(uses: PersonaUse[]): Promise<boolean>;
  /** Notes the uses once they go ahead, right before the first request. */
  record(uses: PersonaUse[]): Promise<void>;
  /** The dialog, to render in the view. */
  dialog: ReactNode;
}

/**
 * FR006-07 (spec §14.1): before the active persona uses a contact or a file that another persona of this browser
 * already used, a dialog says which persona and who could relate the two, and nothing goes out without an explicit
 * confirmation. Cancelling, leaving the view or switching persona counts as «Cancelar».
 */
export function useReuseConfirm(): ReuseConfirm {
  const ws = useWorkspace();
  const persona = ws.session!.persona;
  const [warnings, setWarnings] = useState<ReuseWarning[]>([]);
  const answer = useRef<((ok: boolean) => void) | undefined>(undefined);

  const settle = (ok: boolean) => {
    answer.current?.(ok);
    answer.current = undefined;
    setWarnings([]);
  };
  useEffect(() => () => settle(false), [persona.id]);

  return {
    confirm: async (uses) => {
      const found = await reuseWarnings(ws.book, persona, uses);
      if (!found.length) return true;
      answer.current?.(false);
      setWarnings(found);
      return new Promise<boolean>((resolve) => (answer.current = resolve));
    },
    record: (uses) => recordUse(ws.book, persona, uses),
    dialog: (
      <Dialog open={warnings.length > 0} onClose={() => settle(false)} aria-labelledby="reuse-title" aria-describedby="reuse-consequence">
        <DialogTitle id="reuse-title">Esto ya lo usaste con otra de tus personas</DialogTitle>
        <DialogContent>
          <List id="reuse-warnings" dense disablePadding>
            {warnings.map((w, i) => (
              <ListItem key={`${w.kind}-${w.personaId}-${i}`} disableGutters>
                <ListItemText primary={w.message} />
              </ListItem>
            ))}
          </List>
          <DialogContentText id="reuse-consequence" sx={{ mt: 1 }}>
            No se ha enviado nada. Si sigues, lo que envíes no se puede retirar: quien lo reciba puede relacionar a «{persona.label}» con esa otra persona.
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button id="reuse-cancel" onClick={() => settle(false)} autoFocus>
            Cancelar
          </Button>
          <Button id="reuse-confirm" color="warning" onClick={() => settle(true)}>
            Entiendo el riesgo, seguir con {persona.label}
          </Button>
        </DialogActions>
      </Dialog>
    ),
  };
}

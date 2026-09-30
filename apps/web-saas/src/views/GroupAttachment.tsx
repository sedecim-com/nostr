import { useState } from 'react';
import { Box, Button, Typography } from '@mui/material';
import type { GroupMediaAttachment, GroupSession } from '@sedecim/marmot-adapter';
import { fetchGroupFile, fileSizeLabel, groupErrorMessage, groupMediaDownloader } from '../lib/groups';
import type { PersonaSession } from '../lib/session';

/**
 * FR025-14: a MIP-04 file of a group message, sent or received. Downloading fetches the ciphertext by its hash (checked
 * before it is used), decrypts it with the key of the epoch it was sent in (checked again) and offers it as a local file;
 * nothing is fetched until the user asks.
 */
export function GroupAttachment({ s, gs, groupId, attachment }: { s: PersonaSession; gs: GroupSession; groupId: string; attachment: GroupMediaAttachment }) {
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const size = fileSizeLabel(attachment.size);
  const save = async () => {
    setBusy(true);
    setError('');
    try {
      const { data, attachment: a } = await fetchGroupFile(gs, groupId, attachment.sha256, groupMediaDownloader(s));
      const link = document.createElement('a');
      link.href = URL.createObjectURL(new Blob([data.slice().buffer], { type: a.type }));
      link.download = a.filename;
      link.click();
      URL.revokeObjectURL(link.href);
    } catch (e) {
      setError(groupErrorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Box component="span" sx={{ display: 'block' }} data-sha256={attachment.sha256}>
      Archivo cifrado: {attachment.filename} ({attachment.type}
      {size ? ` · ${size}` : ''}){' '}
      <Button size="small" disabled={busy} onClick={() => void save()}>
        Descargar y verificar
      </Button>
      {error && (
        <Typography component="span" color="error" sx={{ display: 'block' }}>
          {error}
        </Typography>
      )}
    </Box>
  );
}

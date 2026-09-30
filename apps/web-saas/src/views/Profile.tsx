import { useEffect, useReducer, useState } from 'react';
import { Alert, Avatar, Box, Button, Card, CardContent, Checkbox, FormControlLabel, Stack, TextField, Typography } from '@mui/material';
import { UnsanitizableFileError } from '@sedecim/blossom-client';
import { PROFILE_LIMITS } from '@sedecim/messaging';
import { PUBLIC_PROFILE_TEXTS } from '@sedecim/profiles';
import { unsanitizableMessage } from '../lib/blossom';
import { avatarOf, publishProfile, uploadAvatar } from '../lib/profiles';
import type { PersonaSession } from '../lib/session';
import { sendBlockedReason, useWorkspace } from '../lib/workspace';

/** FR006-04: re-renders the caller whenever the persona's profile cache learns a profile. */
export function useProfiles(s: PersonaSession): void {
  const [, bump] = useReducer((n: number) => n + 1, 0);
  useEffect(() => s.profiles.onChange(bump), [s.profiles]);
}

/**
 * FR006-04: the avatar of a key whose profile this persona knows, downloaded only when `show` (the panel's remote
 * previews, or the user's «Mostrar avatares»). Decorative: the name and npub are next to it. Nothing when unknown.
 */
export function AuthorAvatar({ pubkey, show }: { pubkey: string; show: boolean }) {
  const ws = useWorkspace();
  const s = ws.session!;
  const url = s.profiles.get(pubkey)?.picture;
  const [src, setSrc] = useState<string | undefined>();
  useEffect(() => {
    setSrc(undefined);
    if (!show || !url) return;
    let live = true;
    let objectUrl: string | undefined;
    avatarOf(s, ws.cfg, url)
      .then((blob) => {
        if (!live) return;
        objectUrl = URL.createObjectURL(blob);
        setSrc(objectUrl);
      })
      .catch(() => undefined);
    return () => {
      live = false;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [show, url, s.profiles, ws.cfg]);
  return src ? <Avatar src={src} alt="" sx={{ width: 28, height: 28, mr: 1, mt: 0.5 }} /> : null;
}

/** FR006-04: «Mostrar avatares», while the panel keeps remote previews off and some author shown has an avatar. */
export function AvatarsToggle({ pubkeys, shown, onShow }: { pubkeys: string[]; shown: boolean; onShow(): void }) {
  const ws = useWorkspace();
  const s = ws.session!;
  if (shown || !pubkeys.some((pk) => s.profiles.get(pk)?.picture)) return null;
  return (
    <Stack spacing={0.5} sx={{ alignItems: 'flex-start' }}>
      <Button id="avatars-show" size="small" onClick={onShow}>
        Mostrar avatares
      </Button>
      <Typography variant="caption" sx={{ color: 'text.secondary' }}>
        {PUBLIC_PROFILE_TEXTS.others}
      </Typography>
    </Stack>
  );
}

/**
 * FR006-04: the persona's public profile (kind 0): name, description and avatar, published by its own signer only
 * when the user asks. A pseudonymous persona also needs the explicit acknowledgement of what it reveals.
 */
export function PublicProfileCard() {
  const ws = useWorkspace();
  const s = ws.session!;
  const config = ws.config!;
  useProfiles(s);
  const published = s.profiles.get(s.pubkey);
  const pseudonymous = config.identity === 'pseudonymous';
  const blocked = sendBlockedReason(config);
  const [name, setName] = useState('');
  const [about, setAbout] = useState('');
  const [picture, setPicture] = useState('');
  const [loaded, setLoaded] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);
  const [showAvatar, setShowAvatar] = useState(config.remotePreviews);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  // The persona's own profile, from its own relays (asking for its own npub tells them nothing).
  useEffect(() => {
    let live = true;
    void s.profiles
      .lookup(s.persona.relays, [s.pubkey])
      .then(() => {
        const p = s.profiles.get(s.pubkey);
        if (!live) return;
        setName(p?.name ?? '');
        setAbout(p?.about ?? '');
        setPicture(p?.picture ?? '');
      })
      .finally(() => live && setLoaded(true));
    return () => {
      live = false;
    };
    // Once per open persona: a later change of its record (links, archive key) must not wipe what is being edited.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [s.profiles, s.pubkey]);

  const run = async (what: () => Promise<void>) => {
    setBusy(true);
    setError('');
    try {
      await what();
    } catch (e) {
      setError(e instanceof UnsanitizableFileError ? unsanitizableMessage(e) : (e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  // Withdrawing is its own explicit choice: it only ever replaces a published profile with an empty one.
  const publish = (fields: { name?: string; about?: string; picture?: string }, done: string, withdraw = false) =>
    void run(async () => {
      const rec = await publishProfile(s, config, fields, { acknowledged: withdraw || acknowledged });
      setAcknowledged(false);
      ws.notify(rec.state === 'QUEUED' ? `${done} Queda en la cola de entrega hasta que un relay lo acepte.` : done, 'success');
    });
  const upload = (file: File) =>
    void run(async () => {
      setPicture(await uploadAvatar(s, ws.cfg, new Uint8Array(await file.arrayBuffer()), config));
    });

  const hasProfile = !!(published?.name || published?.about || published?.picture);
  const filled = !!(name.trim() || about.trim() || picture.trim());

  return (
    <Card id="public-profile">
      <CardContent>
        <Stack spacing={2}>
          <Typography variant="h6" component="h2">
            Perfil público
          </Typography>
          <Typography variant="body2" sx={{ color: 'text.secondary' }}>
            {PUBLIC_PROFILE_TEXTS.what}
          </Typography>
          {pseudonymous && (
            <Alert severity="warning" id="profile-pseudonymous">
              {PUBLIC_PROFILE_TEXTS.pseudonymous}
            </Alert>
          )}
          {blocked && <Alert severity="error">{blocked}</Alert>}
          <Typography variant="body2" id="profile-status" role="status">
            {!loaded ? 'Buscando el perfil de esta persona en sus relays…' : hasProfile ? `Publicado: ${published!.name ?? 'sin nombre'}.` : 'No hay perfil público de esta persona en sus relays.'}
          </Typography>
          <TextField id="profile-name" label="Nombre público" value={name} onChange={(e) => setName(e.target.value)} disabled={!loaded} slotProps={{ htmlInput: { maxLength: PROFILE_LIMITS.name } }} />
          <TextField id="profile-about" label="Descripción (opcional)" value={about} onChange={(e) => setAbout(e.target.value)} disabled={!loaded} multiline minRows={1} slotProps={{ htmlInput: { maxLength: PROFILE_LIMITS.about } }} />
          <TextField id="profile-picture" label="Dirección del avatar (opcional)" value={picture} onChange={(e) => setPicture(e.target.value)} disabled={!loaded} placeholder="https://…" />
          <Stack direction="row" spacing={1} sx={{ alignItems: 'center', flexWrap: 'wrap' }} useFlexGap>
            <Button component="label" variant="outlined" disabled={busy || !loaded || !!blocked}>
              Subir imagen de avatar
              <input id="profile-avatar-file" hidden type="file" accept="image/jpeg,image/png,image/webp" onChange={(e) => e.target.files?.[0] && upload(e.target.files[0])} />
            </Button>
            {picture && (showAvatar ? <ProfileAvatarPreview url={picture} /> : <Button onClick={() => setShowAvatar(true)}>Mostrar avatar</Button>)}
          </Stack>
          <Typography variant="caption" sx={{ color: 'text.secondary' }}>
            {PUBLIC_PROFILE_TEXTS.avatar}
          </Typography>
          {pseudonymous && <FormControlLabel control={<Checkbox id="profile-ack" checked={acknowledged} onChange={(e) => setAcknowledged(e.target.checked)} />} label={PUBLIC_PROFILE_TEXTS.acknowledge} />}
          <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap' }} useFlexGap>
            <Button id="profile-publish" variant="contained" disabled={busy || !loaded || !!blocked || !filled || (pseudonymous && !acknowledged)} onClick={() => publish({ name, about, picture }, 'Perfil público publicado (kind 0).')}>
              Publicar perfil
            </Button>
            {hasProfile && (
              <Button id="profile-withdraw" color="warning" disabled={busy || !!blocked} onClick={() => publish({}, 'Perfil público retirado: se publicó uno vacío.', true)}>
                Retirar perfil
              </Button>
            )}
          </Stack>
          {hasProfile && (
            <Typography variant="caption" sx={{ color: 'text.secondary' }}>
              {PUBLIC_PROFILE_TEXTS.withdraw}
            </Typography>
          )}
          {error && <Alert severity="error">{error}</Alert>}
        </Stack>
      </CardContent>
    </Card>
  );
}

/** The avatar the user is about to publish, shown as the others will see it. */
function ProfileAvatarPreview({ url }: { url: string }) {
  const ws = useWorkspace();
  const s = ws.session!;
  const [src, setSrc] = useState<string | undefined>();
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    let live = true;
    let objectUrl: string | undefined;
    setSrc(undefined);
    setFailed(false);
    avatarOf(s, ws.cfg, url)
      .then((blob) => {
        if (!live) return;
        objectUrl = URL.createObjectURL(blob);
        setSrc(objectUrl);
      })
      .catch(() => live && setFailed(true));
    return () => {
      live = false;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [url, s.profiles, ws.cfg]);
  if (failed) return <Typography variant="body2">No se pudo cargar el avatar (JPEG, PNG o WebP de hasta 1 MB).</Typography>;
  return src ? <Box component="img" id="profile-avatar-preview" src={src} alt="Tu avatar" sx={{ width: 48, height: 48, borderRadius: '50%' }} /> : null;
}

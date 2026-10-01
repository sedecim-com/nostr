import { BlossomClient, checkAttachmentSize, MAX_ATTACHMENT_BYTES, prepareBlob, sanitizeMetadata, uploadToServers } from '@sedecim/blossom-client';
import type { OutboxRecord } from '@sedecim/delivery-engine';
import { buildProfile, type ProfileCache, type ProfileFields } from '@sedecim/messaging';
import { bytesToHex, type Signer } from '@sedecim/nostr-core';
import type { SovereigntyConfig } from '@sedecim/profiles';
import { blossomServersOf, uploadTargets } from './blossom';
import type { DeploymentConfig } from './config';
import { shortNpub, type PersonaSession } from './session';
import { sendBlockedReason } from './workspace';

/**
 * FR006-04: how the web shows a key: "name · npub1…" once this persona knows its public profile, else the short npub.
 * The npub always stays: anyone can claim any name.
 */
export function authorLabel(s: PersonaSession, pubkey: string): string {
  const name = s.profiles.get(pubkey)?.name;
  return name ? `${name} · ${shortNpub(pubkey)}` : shortNpub(pubkey);
}

/*
 * FR006-04: which profiles are looked up, always on the persona's own relays. Only lookups that tell those relays
 * nothing new happen on their own:
 * - channels: the authors of the messages those same relays served to this persona;
 * - direct messages: this persona and its contacts (keys it wrote to), whose DM relays it already asked for.
 * Someone who wrote without being a contact, and the members of a secure group, are shown from the cache: asking for
 * their profile would tell the relays who writes to this persona (the gift wrap hides it) or who is in the group. The
 * groups view looks its members up only when the user asks (PUBLIC_PROFILE_TEXTS.groups).
 */
export function lookupChannelAuthors(s: PersonaSession, pubkeys: Iterable<string>): Promise<void> {
  return s.profiles.lookup(s.persona.relays, pubkeys);
}

export async function lookupDmCorrespondents(s: PersonaSession, pubkeys: Iterable<string>): Promise<void> {
  const wanted = [s.pubkey];
  for (const pk of new Set(pubkeys)) if (pk !== s.pubkey && (await s.isContact(pk).catch(() => false))) wanted.push(pk);
  await s.profiles.lookup(s.persona.relays, wanted);
}

export function lookupGroupMembers(s: PersonaSession, members: Iterable<string>): Promise<void> {
  return s.profiles.lookup(s.persona.relays, members);
}

/** A pseudonymous persona publishes no profile without the user's explicit choice. */
export class ProfileConsentError extends Error {
  constructor() {
    super('Esta persona es seudónima: su perfil público solo se publica si marcas que entiendes lo que supone.');
  }
}

/**
 * FR006-04: publishes the persona's public profile (kind 0), signed by its own signer (local key, NIP-07, NIP-46 or
 * managed) through its outbox, on its relays. Nothing is published for a configuration the browser cannot honour
 * (Tor-only), nor for a pseudonymous persona without `acknowledged` (its explicit choice). An empty profile withdraws
 * the previous one (it replaces it).
 */
export async function publishProfile(s: PersonaSession, config: SovereigntyConfig, fields: ProfileFields, opts: { acknowledged?: boolean } = {}): Promise<OutboxRecord> {
  const blocked = sendBlockedReason(config);
  if (blocked) throw new Error(blocked);
  if (config.identity === 'pseudonymous' && !opts.acknowledged) throw new ProfileConsentError();
  // NIP-01: of two versions with the same created_at the lowest id wins, so a change made in the same second as the
  // previous one (withdrawing right after publishing) could be dropped by the relays: it is dated one second later.
  const created_at = Math.max(Math.floor(Date.now() / 1000), (s.profiles.get(s.pubkey)?.createdAt ?? 0) + 1);
  const rec = await s.engine.submit({ template: { ...buildProfile(fields), created_at } }, { relays: s.persona.relays, quorum: 1, wait: true });
  if (rec.state === 'FAILED' || !rec.event) throw new Error(`Los relays rechazaron el perfil${rec.failureReason ? `: ${rec.failureReason}` : ''}.`);
  s.profiles.put(rec.event);
  return rec;
}

/** Image formats an avatar may have: the ones whose metadata the sanitizer removes (FR019). */
const AVATAR_TYPES: Record<string, string> = { jpeg: 'image/jpeg', png: 'image/png', webp: 'image/webp' };
export const AVATAR_MAX_BYTES = MAX_ATTACHMENT_BYTES.avatar;

/** The image type of an avatar by its bytes (never by what a server or a file name says), or undefined. */
function avatarType(bytes: Uint8Array): string | undefined {
  try {
    return AVATAR_TYPES[sanitizeMetadata(bytes).format];
  } catch {
    return undefined; // malformed
  }
}

/**
 * FR006-04: uploads an avatar for the persona's profile, public and unencrypted, always without its metadata (EXIF,
 * whatever the panel says): JPEG, PNG or WebP only, at most AVATAR_MAX_BYTES, to the persona's Blossom servers (kind
 * 10063) or the deployment's media server. Returns its address.
 */
export async function uploadAvatar(s: PersonaSession, cfg: DeploymentConfig, bytes: Uint8Array, config: SovereigntyConfig): Promise<string> {
  const blocked = sendBlockedReason(config);
  if (blocked) throw new Error(blocked);
  checkAttachmentSize('avatar', bytes.length);
  const type = avatarType(bytes);
  if (!type) throw new Error('El avatar debe ser una imagen JPEG, PNG o WebP.');
  const prepared = prepareBlob(bytes, { sanitize: true, requireSanitizable: true, mimeType: type, flow: 'avatar' });
  const targets = uploadTargets(cfg, await blossomServersOf(s), false);
  if (targets.length === 0) throw new Error('No hay servidor de archivos para el avatar: publica tu lista de servidores Blossom o configura el de media.');
  const { descriptor, server } = await uploadToServers(prepared, targets, s.signer);
  return descriptor.url || `${server.replace(/\/$/, '')}/${prepared.sha256}`;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes.slice())));
}

/**
 * FR006-04: downloads an avatar someone chose, as bytes the page shows from a blob: URL (the CSP allows no remote
 * images). No cookies, no referrer, no redirects to other hosts, at most AVATAR_MAX_BYTES, JPEG, PNG or WebP only, and
 * checked against the hash when the address is a Blossom one (…/<sha256>). Only the deployment's own media server
 * (`operator`: the same operator as the relays the persona authenticates to) may get a BUD-01 token; no other server
 * ever learns who asks.
 */
export async function loadAvatar(url: string, opts: { fetch?: typeof fetch; operator?: { mediaServer: string; signer: Signer } } = {}): Promise<Blob> {
  const u = new URL(url);
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error('avatar address must be http(s)');
  const sha = /(?:^|\/)([0-9a-f]{64})(?:\.[a-z0-9]{1,8})?$/i.exec(u.pathname)?.[1]?.toLowerCase();
  let bytes: Uint8Array;
  if (opts.operator && sha && u.origin === new URL(opts.operator.mediaServer).origin) {
    bytes = await new BlossomClient(opts.operator.mediaServer, opts.operator.signer).download(sha, { url });
  } else {
    const res = await (opts.fetch ?? fetch)(url, { credentials: 'omit', referrerPolicy: 'no-referrer', redirect: 'error', cache: 'force-cache' });
    if (!res.ok) throw new Error(`avatar: ${res.status}`);
    if (Number(res.headers.get('content-length') ?? 0) > AVATAR_MAX_BYTES) throw new Error('avatar too large');
    bytes = new Uint8Array(await res.arrayBuffer());
    if (sha && (await sha256Hex(bytes)) !== sha) throw new Error('avatar hash mismatch');
  }
  if (bytes.length > AVATAR_MAX_BYTES) throw new Error('avatar too large');
  const type = avatarType(bytes);
  if (!type) throw new Error('avatar is not a JPEG, PNG or WebP image');
  return new Blob([bytes.slice().buffer], { type });
}

/** Avatars already downloaded, per persona (its profile cache) and address, while the persona is open. */
const avatars = new WeakMap<ProfileCache, Map<string, Promise<Blob>>>();

export function avatarOf(s: PersonaSession, cfg: DeploymentConfig, url: string): Promise<Blob> {
  let byUrl = avatars.get(s.profiles);
  if (!byUrl) avatars.set(s.profiles, (byUrl = new Map()));
  let blob = byUrl.get(url);
  if (!blob) {
    blob = loadAvatar(url, cfg.buzzMedia ? { operator: { mediaServer: cfg.buzzMedia, signer: s.signer } } : {});
    blob.catch(() => byUrl.delete(url));
    byUrl.set(url, blob);
  }
  return blob;
}

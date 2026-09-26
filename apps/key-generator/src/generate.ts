import { bytesToHex, generateSecretKey, nip19, nip49, selfTestKey, wipe, type KeySelfTest } from '@sedecim/nostr-core';

export interface GeneratedKey {
  npub: string;
  pubkeyHex: string;
  /** Only present when explicitly requested. */
  nsec?: string;
  ncryptsec?: string;
  selfTest: KeySelfTest;
  createdAt: string;
}

export interface BackupFile {
  format: 'sedecim-offline-key';
  version: 1;
  npub: string;
  ncryptsec: string;
  kdf: { name: 'scrypt'; logN: number; r: 8; p: 1 };
  createdAt: string;
  note: string;
}

export interface GenerateOptions {
  password?: string;
  logN?: number;
  revealNsec?: boolean;
}

/** Generates a key with the OS CSPRNG, verifies derivation + BIP-340 signature, then wipes memory. */
export function generateKey(opts: GenerateOptions = {}): GeneratedKey {
  const sk = generateSecretKey();
  try {
    const selfTest = selfTestKey(sk);
    if (!selfTest.ok) throw new Error('self-test failed: refusing to output this key');
    return {
      npub: nip19.npubEncode(selfTest.pubkey),
      pubkeyHex: selfTest.pubkey,
      ...(opts.revealNsec ? { nsec: nip19.nsecEncode(sk) } : {}),
      ...(opts.password ? { ncryptsec: nip49.encryptKey(sk, opts.password, opts.logN ?? 18, 0x01) } : {}),
      selfTest,
      createdAt: new Date().toISOString(),
    };
  } finally {
    wipe(sk);
  }
}

/**
 * Key for a service identity that lives in the stack's .env (relay signing key, mirror NIP-42 identity):
 * same CSPRNG and self-test as a user key, returned as hex because that is what the services read.
 */
export function generateServiceKey(): { secretHex: string; pubkeyHex: string; npub: string } {
  const sk = generateSecretKey();
  try {
    const selfTest = selfTestKey(sk);
    if (!selfTest.ok) throw new Error('self-test failed: refusing to output this key');
    return { secretHex: bytesToHex(sk), pubkeyHex: selfTest.pubkey, npub: nip19.npubEncode(selfTest.pubkey) };
  } finally {
    wipe(sk);
  }
}

export function backupFile(k: GeneratedKey, logN: number): BackupFile {
  if (!k.ncryptsec) throw new Error('a password is required to create an encrypted backup');
  return {
    format: 'sedecim-offline-key',
    version: 1,
    npub: k.npub,
    ncryptsec: k.ncryptsec,
    kdf: { name: 'scrypt', logN, r: 8, p: 1 },
    createdAt: k.createdAt,
    note: 'NIP-49 ncryptsec. Guarda este archivo y la contraseña por separado. Sin la contraseña no hay recuperación.',
  };
}

/** Verifies a backup offline: decrypts, re-derives the npub and signs a test message. */
export function verifyBackup(file: BackupFile, password: string): { ok: boolean; npub: string } {
  const { secretKey } = nip49.decryptKey(file.ncryptsec, password);
  try {
    const t = selfTestKey(secretKey);
    const npub = nip19.npubEncode(t.pubkey);
    return { ok: t.ok && npub === file.npub, npub };
  } finally {
    wipe(secretKey);
  }
}

import { bytesToHex } from '@sedecim/nostr-core';
import type { EncryptedStore } from '@sedecim/encrypted-store/browser';
import { ManagedSignerClient, type AccessTokenProvider, type ManagedSignerConnection } from '@sedecim/signer';

/** How long a device session of this browser lasts before the Acceso login opens another one. */
const SESSION_TTL_SECONDS = 12 * 3600;
/** A session this close to its end is replaced before use rather than failing mid-request. */
const MARGIN_MS = 60_000;

interface Stored {
  /** This browser as the managed-signer knows it: a random id, the same for every persona of this vault. */
  deviceId: string;
  token?: string;
  expiresAt?: number;
}

/**
 * FR005-11 (and FR024-03): the web signs for a managed persona through a device session of this browser, opened with
 * the Acceso login, never with the login token itself. The owner sees that session in their list and can close it
 * from any browser; the organisation can revoke the device. Its token stays in the encrypted vault; one that expired
 * or was closed is replaced with the login the next time the managed-signer refuses it.
 */
export class BrowserManagedSession {
  private opening?: Promise<string>;

  constructor(
    private readonly store: EncryptedStore,
    readonly baseUrl: string,
    private readonly acceso: AccessTokenProvider,
    private readonly now: () => number = Date.now,
  ) {}

  private col() {
    return this.store.collection<Stored>('managed-device');
  }

  private async stored(): Promise<Stored> {
    const s = await this.col().get('this');
    if (s) return s;
    const fresh = { deviceId: `web-${bytesToHex(crypto.getRandomValues(new Uint8Array(12)))}` };
    await this.col().put('this', fresh);
    return fresh;
  }

  /** This browser's device id at the managed-signer. */
  async deviceId(): Promise<string> {
    return (await this.stored()).deviceId;
  }

  private async token(): Promise<string> {
    const s = await this.stored();
    if (s.token && (s.expiresAt ?? 0) - MARGIN_MS > this.now()) return s.token;
    return this.open();
  }

  /** Opens a new session with the login (one at a time, however many requests ask for it). */
  private open(): Promise<string> {
    this.opening ??= (async () => {
      try {
        const s = await this.stored();
        const opened = await ManagedSignerClient.openDeviceSession(this.login(), s.deviceId, { ttlSeconds: SESSION_TTL_SECONDS });
        await this.col().put('this', { deviceId: s.deviceId, token: opened.token, expiresAt: Date.parse(opened.expiresAt) });
        return opened.token;
      } finally {
        this.opening = undefined;
      }
    })();
    return this.opening;
  }

  /** What a managed persona signs with in this browser: its device session, replaced when refused. */
  connection(): ManagedSignerConnection {
    return {
      baseUrl: this.baseUrl,
      token: () => this.token(),
      renew: async () => {
        const s = await this.stored();
        await this.col().put('this', { deviceId: s.deviceId });
      },
    };
  }

  /** The Acceso login itself: what may close sessions other than this browser's. */
  login(): ManagedSignerConnection {
    return { baseUrl: this.baseUrl, token: this.acceso };
  }

  /** FR005-11: forgets this browser's session locally (after closing it at the managed-signer). */
  async forget(): Promise<void> {
    const s = await this.stored();
    await this.col().put('this', { deviceId: s.deviceId });
  }
}

import { bytesToHex } from '@sedecim/nostr-core';
import type { EncryptedStore } from '@sedecim/encrypted-store/browser';
import { ManagedSignerClient, ManagedSignerHttpError, ManagedSignerReauthError, type AccessTokenProvider, type ManagedSignerConnection } from '@sedecim/signer';

/** How long a device session of this browser lasts before the Acceso login opens another one. */
const SESSION_TTL_SECONDS = 12 * 3600;
/** A session this close to its end is replaced before use rather than failing mid-request. */
const MARGIN_MS = 60_000;

/** Device ids the organisation's policy-engine hands out (and the random `web-…` ones). */
const DEVICE_ID = /^[A-Za-z0-9._:-]{1,128}$/;

/** FR024-03: the organisation revoked the device this browser is bound to; the login cannot open another session. */
export class DeviceRevokedError extends Error {
  constructor(readonly deviceId: string) {
    super(`Tu organización revocó este dispositivo (${deviceId}): este navegador ya no puede firmar con tu llave gestionada. Pide a tu organización que registre un dispositivo nuevo.`);
  }
}

/**
 * IR-2026-10-11: the owner closed their other sessions from another browser after this one signed in: this login no
 * longer opens sessions until its password is typed again. Still a ManagedSignerReauthError, so the views offer that.
 */
export class SessionsClosedError extends ManagedSignerReauthError {
  constructor() {
    super('Se cerraron las sesiones de tu llave gestionada desde otro navegador: escribe otra vez tu contraseña de Acceso en «Actividad de tu llave gestionada» para volver a firmar aquí.');
  }
}

interface Stored {
  /**
   * This browser as the managed-signer knows it: a random id, the same for every persona of this vault, or the device
   * its organisation registered for it in the policy-engine (FR024-03), so that revoking that device reaches it.
   */
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

  /**
   * FR024-03: binds this browser to the device its organisation registered for it in the policy-engine. Its sessions
   * then carry that id, so revoking the device (propagated by the rotation worker) turns this browser away, also when it
   * tries to open another session with the login. The current session is closed first.
   */
  async bindDevice(deviceId: string): Promise<void> {
    const id = deviceId.trim();
    if (!DEVICE_ID.test(id)) throw new Error('id de dispositivo no válido: usa el que te dio tu organización');
    const s = await this.stored();
    if (s.deviceId === id) return;
    if (s.token && (s.expiresAt ?? 0) > this.now()) {
      const current: ManagedSignerConnection = { baseUrl: this.baseUrl, token: async () => s.token! };
      const own = (await ManagedSignerClient.listDeviceSessions(current).catch(() => [])).find((x) => x.current);
      if (own) await ManagedSignerClient.closeDeviceSession(current, own.id).catch(() => undefined);
    }
    await this.col().put('this', { deviceId: id });
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
        const opened = await ManagedSignerClient.openDeviceSession(this.login(), s.deviceId, { ttlSeconds: SESSION_TTL_SECONDS }).catch((e: unknown) => {
          if (e instanceof ManagedSignerHttpError && e.status === 403 && /device revoked/.test(e.message)) throw new DeviceRevokedError(s.deviceId);
          if (e instanceof ManagedSignerReauthError) throw new SessionsClosedError();
          throw e;
        });
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

import { readFileSync } from 'node:fs';
import type { EventsConfig } from './engine';
import { parseSigningKey, parseWebhookSecretsKey } from './events';
import { systemResolver, type Resolver } from './webhooks';

/** OPS-16: how the webhook dispatcher runs. */
export interface WebhookDispatchSettings {
  /** POLICY_WEBHOOK_MAX_ATTEMPTS: attempts per delivery. */
  maxAttempts: number;
  /** POLICY_WEBHOOK_DISABLE_AFTER: consecutive failed attempts that disable a subscription. */
  disableAfter: number;
  /** POLICY_WEBHOOK_TIMEOUT_MS: limit of each request. */
  timeoutMs: number;
  /** POLICY_WEBHOOK_INTERVAL_MS: how often each replica looks for due deliveries. */
  intervalMs: number;
  /** POLICY_WEBHOOK_DELIVERY_RETENTION_DAYS: days finished deliveries stay in the log. */
  deliveryRetentionDays: number;
}

const list = (v?: string) => (v ?? '').split(',').map((s) => s.trim()).filter(Boolean);

function positive(env: NodeJS.ProcessEnv, name: string, fallback: number): number {
  const raw = env[name]?.trim();
  if (!raw) return fallback;
  const n = Number(raw);
  if (!Number.isSafeInteger(n) || n < 1) throw new Error(`${name} must be a positive whole number`);
  return n;
}

/** The contents of a secret file named by a `*_FILE` variable. Errors name the variable and the path, never the contents. */
function readSecret(name: string, path: string, read: (path: string) => string): string {
  let text: string;
  try {
    text = read(path);
  } catch (e) {
    throw new Error(`${name}: cannot read ${path} (${(e as NodeJS.ErrnoException).code ?? 'error'})`);
  }
  if (!text.trim()) throw new Error(`${name}: ${path} is empty`);
  return text;
}

/**
 * OPS-16: events and webhooks from the environment. Without POLICY_EVENTS_SIGNING_KEY_FILE both are off, explicitly
 * (`warnings` says so, and their routes answer 404). With it, a file that cannot be read or holds no Ed25519 key stops the
 * service before it serves anything (fail closed): the engine never signs with a default key nor emits unsigned events.
 * Webhooks also need POLICY_WEBHOOK_SECRETS_KEY_FILE.
 */
export function eventsConfigFromEnv(
  env: NodeJS.ProcessEnv,
  opts: { readFile?: (path: string) => string; resolve?: Resolver } = {},
): { events?: EventsConfig; dispatch: WebhookDispatchSettings; warnings: string[] } {
  const read = opts.readFile ?? ((path: string) => readFileSync(path, 'utf8'));
  const dispatch: WebhookDispatchSettings = {
    maxAttempts: positive(env, 'POLICY_WEBHOOK_MAX_ATTEMPTS', 10),
    disableAfter: positive(env, 'POLICY_WEBHOOK_DISABLE_AFTER', 15),
    timeoutMs: positive(env, 'POLICY_WEBHOOK_TIMEOUT_MS', 10_000),
    intervalMs: positive(env, 'POLICY_WEBHOOK_INTERVAL_MS', 2_000),
    deliveryRetentionDays: positive(env, 'POLICY_WEBHOOK_DELIVERY_RETENTION_DAYS', 30),
  };
  const allowPrivateRaw = env.POLICY_WEBHOOKS_ALLOW_PRIVATE?.trim() ?? '';
  if (!['', 'true', 'false'].includes(allowPrivateRaw)) throw new Error('POLICY_WEBHOOKS_ALLOW_PRIVATE must be true or false');
  const allowPrivate = allowPrivateRaw === 'true';
  const keyFile = env.POLICY_EVENTS_SIGNING_KEY_FILE?.trim();
  const secretsFile = env.POLICY_WEBHOOK_SECRETS_KEY_FILE?.trim();
  if (!keyFile) {
    if (secretsFile) throw new Error('POLICY_WEBHOOK_SECRETS_KEY_FILE needs POLICY_EVENTS_SIGNING_KEY_FILE: webhooks deliver signed events');
    return { dispatch, warnings: ['POLICY_EVENTS_SIGNING_KEY_FILE not set: signed events and webhooks are off'] };
  }
  let key;
  try {
    key = parseSigningKey(readSecret('POLICY_EVENTS_SIGNING_KEY_FILE', keyFile, read));
  } catch (e) {
    throw new Error(`POLICY_EVENTS_SIGNING_KEY_FILE: ${(e as Error).message.replace(/^POLICY_EVENTS_SIGNING_KEY_FILE: /, '')}`);
  }
  const issuer = env.POLICY_EVENTS_ISSUER?.trim() || env.PUBLIC_BASE_URL?.trim();
  if (!issuer) throw new Error('POLICY_EVENTS_ISSUER (or PUBLIC_BASE_URL) is required with POLICY_EVENTS_SIGNING_KEY_FILE: every event names its issuer');
  const warnings: string[] = [];
  const events: EventsConfig = { issuer, key, revokedKids: list(env.POLICY_EVENTS_REVOKED_KIDS) };
  if (secretsFile) {
    let secretsKey: Buffer;
    try {
      secretsKey = parseWebhookSecretsKey(readSecret('POLICY_WEBHOOK_SECRETS_KEY_FILE', secretsFile, read));
    } catch (e) {
      throw new Error(`POLICY_WEBHOOK_SECRETS_KEY_FILE: ${(e as Error).message.replace(/^POLICY_WEBHOOK_SECRETS_KEY_FILE: /, '')}`);
    }
    events.webhooks = { secretsKey, policy: { allowPrivate, resolve: opts.resolve ?? systemResolver }, max: positive(env, 'POLICY_WEBHOOKS_MAX', 10) };
    if (allowPrivate) warnings.push('POLICY_WEBHOOKS_ALLOW_PRIVATE=true: webhooks may reach loopback, private and cloud-metadata addresses, over http too (tests and development only)');
  } else warnings.push('POLICY_WEBHOOK_SECRETS_KEY_FILE not set: webhooks are off (the signed event stream is on)');
  return { events, dispatch, warnings };
}

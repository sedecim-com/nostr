import { hexToBytes } from '@sedecim/nostr-core';
import { createManagedSignerApi, LocalEnvelopeVault, ManagedSigner } from './index';

const env = process.env;
if (!env.MANAGED_SIGNER_KEK || !/^[0-9a-f]{64}$/.test(env.MANAGED_SIGNER_KEK)) throw new Error('MANAGED_SIGNER_KEK (64 hex chars) is required');
if (!env.MANAGED_SIGNER_TOKENS) throw new Error('MANAGED_SIGNER_TOKENS is required (token:principal,...)');
const tokens = Object.fromEntries(env.MANAGED_SIGNER_TOKENS.split(',').map((p) => p.split(':') as [string, string]));
const vault = new LocalEnvelopeVault(env.MANAGED_SIGNER_VAULT_DIR ?? '/data/vault', hexToBytes(env.MANAGED_SIGNER_KEK));
const core = new ManagedSigner(vault, { retentionDays: Number(env.MANAGED_SIGNER_RETENTION_DAYS ?? 30) });
const api = createManagedSignerApi(core, { name: 'managed-signer', bearerTokens: tokens });
await api.listen(Number(env.PORT ?? 8084), env.HOST ?? '0.0.0.0');

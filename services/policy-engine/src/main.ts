import { createPolicyApi, PolicyEngine } from './index';

const env = process.env;
const admins = (env.POLICY_ADMIN_PUBKEYS ?? '').split(',').filter(Boolean);
const tokens = Object.fromEntries((env.POLICY_SERVICE_TOKENS ?? '').split(',').filter(Boolean).map((p) => p.split(':') as [string, string]));
if (admins.length === 0) console.warn('POLICY_ADMIN_PUBKEYS empty: admin routes will reject every request');
const api = createPolicyApi(new PolicyEngine(), { name: 'policy-engine', publicBaseUrl: env.PUBLIC_BASE_URL, bearerTokens: tokens, adminPubkeys: admins });
await api.listen(Number(env.PORT ?? 8083), env.HOST ?? '0.0.0.0');

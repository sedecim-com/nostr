/** Development relay: `npm run dev:relay -- --port 7777 [--auth] [--negentropy]`. In-memory, for local testing only. */
import { TestRelay } from './relay';

const args = process.argv.slice(2);
const port = Number(args[args.indexOf('--port') + 1] || 7777);
const relay = new TestRelay({ port, host: '0.0.0.0', requireAuth: args.includes('--auth'), pGatedKinds: [1059], supportsNegentropy: args.includes('--negentropy') });
const url = await relay.start();
console.log(`dev relay listening on ${url} (in-memory, NOT for production)`);

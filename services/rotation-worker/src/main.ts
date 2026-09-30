// FR024-05: rotation worker service (compose service `rotation-worker`, profile `institutional`; k8s
// components/institutional). Configuration: docs/institutional.md («Worker de rotaciones»).
import { npubEncode } from '@sedecim/nostr-core';
import { createLogger } from '@sedecim/telemetry-policy';
import { parseConfig, startRotationWorker } from './index';

const logger = createLogger({ base: { service: 'rotation-worker' }, minimizeIp: true });
const cfg = parseConfig(process.env);
const running = await startRotationWorker(cfg, { logger });
// Groups must list this identity as an admin (and invite it) for the worker to rotate them.
logger.info('rotation worker running', { npub: npubEncode(running.pubkey), relays: cfg.relays.map((r) => r.public).join(','), managed_signer: !!cfg.managedSigner });

for (const sig of ['SIGTERM', 'SIGINT'] as const) {
  process.once(sig, () => {
    void running.stop().finally(() => process.exit(0));
  });
}

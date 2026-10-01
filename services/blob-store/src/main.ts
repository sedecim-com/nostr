import { rateLimitFromEnv, serveMetrics, tracingFromEnv } from '@sedecim/service-kit';
import { BlobStore } from './index';

const env = process.env;
// BUD-02 upload/delete tokens (kind 24242) are reusable until their `expiration`, as the spec allows:
// there is no replay cache here. The limits below (RATE_LIMIT_* env, per replica) bound their abuse.
const store = new BlobStore({
  dir: env.BLOB_DIR ?? '/data/blobs',
  publicUrl: env.PUBLIC_BASE_URL,
  allowedPubkeys: (env.BLOB_ALLOWED_PUBKEYS ?? '').split(',').filter(Boolean),
  maxBytes: Number(env.BLOB_MAX_BYTES ?? 50 * 1024 * 1024),
  rateLimit: rateLimitFromEnv(env),
  maxConcurrentUploadsPerIp: Number(env.BLOB_MAX_CONCURRENT_UPLOADS_PER_IP ?? 4),
  // NFR007-02: TELEMETRY_LEVEL / TRACE_SAMPLE_RATE / TRACE_EXPORT_URL; off by default.
  tracing: tracingFromEnv(env),
});
if (env.METRICS_PORT && store.rateLimiter) await serveMetrics(() => store.rateLimiter!.render(), { port: Number(env.METRICS_PORT), host: env.METRICS_HOST ?? '0.0.0.0' });
await store.listen(Number(env.PORT ?? 8085), env.HOST ?? '0.0.0.0');

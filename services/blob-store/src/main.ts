import { BlobStore } from './index';

const env = process.env;
const store = new BlobStore({
  dir: env.BLOB_DIR ?? '/data/blobs',
  publicUrl: env.PUBLIC_BASE_URL,
  allowedPubkeys: (env.BLOB_ALLOWED_PUBKEYS ?? '').split(',').filter(Boolean),
  maxBytes: Number(env.BLOB_MAX_BYTES ?? 50 * 1024 * 1024),
});
await store.listen(Number(env.PORT ?? 8085), env.HOST ?? '0.0.0.0');

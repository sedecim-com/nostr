import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { NetworkGuard, ResponseTooLargeError } from '../src/index';

/** FR018-06: a response body over `maxBytes` is cut off while it arrives instead of being buffered whole. */

const MiB = 1024 * 1024;

describe('NetworkGuard.fetch with a size limit (FR018-06)', () => {
  let server: Server;
  let base = '';
  const streamed = { chunks: 0 };
  beforeAll(async () => {
    server = createServer((req, res) => {
      if (req.url === '/declared') {
        res.writeHead(200, { 'content-length': String(3 * MiB) });
        res.end(Buffer.alloc(3 * MiB));
      } else if (req.url === '/streamed') {
        // No declared length: 4 MiB in 64 KiB chunks.
        res.writeHead(200);
        const chunk = Buffer.alloc(64 * 1024);
        let n = 0;
        const push = () => {
          while (n < 64) {
            n += 1;
            streamed.chunks = n;
            if (!res.write(chunk)) return void res.once('drain', push);
          }
          res.end();
        };
        push();
      } else {
        res.writeHead(200, { 'content-length': '5' });
        res.end('hello');
      }
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });

  const guard = () => new NetworkGuard({ mode: 'direct' });

  it('FR018-06: refuses from the declared length, before any of the body is read', async () => {
    const err = await guard()
      .fetch(`${base}/declared`, { maxBytes: MiB })
      .catch((e: Error) => e);
    expect(err).toBeInstanceOf(ResponseTooLargeError);
    expect(err).toMatchObject({ size: 3 * MiB, limit: MiB });
  });

  it('FR018-06: with no declared length, it hangs up once the body passes the limit', async () => {
    const err = await guard()
      .fetch(`${base}/streamed`, { maxBytes: MiB })
      .catch((e: Error) => e);
    expect(err).toBeInstanceOf(ResponseTooLargeError);
    expect(err).toMatchObject({ size: undefined, limit: MiB });
    expect(streamed.chunks).toBeLessThan(64);
  });

  it('FR018-06: a body that fits, or no limit at all, comes whole', async () => {
    expect(new TextDecoder().decode((await guard().fetch(`${base}/small`, { maxBytes: 5 })).body)).toBe('hello');
    expect(new TextDecoder().decode((await guard().fetch(`${base}/small`)).body)).toBe('hello');
    await expect(guard().fetch(`${base}/small`, { maxBytes: 4 })).rejects.toBeInstanceOf(ResponseTooLargeError);
    expect((await guard().fetch(`${base}/streamed`)).body.length).toBe(4 * MiB);
  });
});

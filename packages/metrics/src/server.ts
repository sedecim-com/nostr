import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { NostrMetricsExporter } from './exporter';
import { PROMETHEUS_CONTENT_TYPE } from './registry';

export interface MetricsServer {
  url: string;
  close(): Promise<void>;
}

/**
 * Serves `GET /metrics` on its own (internal) port, separate from any public API, so Prometheus can
 * scrape it without exposing it through the edge. Pass the exporter only when the profile allows
 * telemetry (NostrMetricsExporter cannot be built at level 'none').
 */
export async function startMetricsServer(exporter: NostrMetricsExporter, opts: { port?: number; host?: string } = {}): Promise<MetricsServer> {
  const server: Server = createServer((req, res) => {
    const path = (req.url ?? '/').split('?')[0];
    if (req.method !== 'GET' || path !== '/metrics') {
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end('not found');
      return;
    }
    exporter.render().then(
      (body) => {
        res.writeHead(200, { 'content-type': PROMETHEUS_CONTENT_TYPE, 'cache-control': 'no-store' });
        res.end(body);
      },
      () => {
        res.writeHead(500, { 'content-type': 'text/plain' });
        res.end('metrics unavailable');
      },
    );
  });
  const host = opts.host ?? '127.0.0.1';
  await new Promise<void>((r) => server.listen(opts.port ?? 0, host, () => r()));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://${host === '0.0.0.0' ? '127.0.0.1' : host}:${port}/metrics`,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

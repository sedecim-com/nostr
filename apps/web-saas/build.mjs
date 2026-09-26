import { build } from 'esbuild';
import { copyFileSync } from 'node:fs';

// Node built-ins are only used by server-side backends (FileBackend); stub them for the browser bundle.
const stubNode = {
  name: 'stub-node',
  setup(b) {
    b.onResolve({ filter: /^node:/ }, (a) => ({ path: a.path, namespace: 'stub' }));
    b.onLoad({ filter: /.*/, namespace: 'stub' }, () => ({ contents: 'export default {}; export const mkdir=()=>{throw new Error("unavailable in browser")}, readdir=mkdir, readFile=mkdir, rename=mkdir, rm=mkdir, writeFile=mkdir, open=mkdir, join=(...p)=>p.join("/");', loader: 'js' }));
  },
};

await build({
  entryPoints: [new URL('./src/main.ts', import.meta.url).pathname],
  bundle: true,
  format: 'esm',
  platform: 'browser',
  target: 'es2022',
  sourcemap: true,
  outfile: new URL('./public/app.js', import.meta.url).pathname,
  plugins: [stubNode],
  legalComments: 'none',
});
// Deployment flags generated from the interop gate (compose also mounts the live file over it).
copyFileSync(new URL('../../infra/web/flags.json', import.meta.url), new URL('./public/flags.json', import.meta.url));
console.log('built apps/web-saas/public/app.js (+ flags.json)');

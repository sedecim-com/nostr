import { copyFileSync } from 'node:fs';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react-swc';

// Deployment flags come from the interop gate (compose also mounts the live file over it).
const flags = () => ({
  name: 'interop-flags',
  writeBundle(opts: { dir?: string }) {
    copyFileSync(new URL('../../infra/web/flags.json', import.meta.url), `${opts.dir}/flags.json`);
  },
});

export default defineConfig({
  root: new URL('.', import.meta.url).pathname,
  base: './',
  publicDir: 'static',
  plugins: [react(), flags()],
  build: { outDir: 'dist', emptyOutDir: true, sourcemap: false, target: 'es2022', chunkSizeWarningLimit: 800 },
  server: { port: 5173 },
});

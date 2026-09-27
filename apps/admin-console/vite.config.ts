import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react-swc';

// Served by the web nginx image under /admin/ (relative base, like apps/web-saas).
export default defineConfig({
  root: new URL('.', import.meta.url).pathname,
  base: './',
  publicDir: 'static',
  plugins: [react()],
  build: { outDir: 'dist', emptyOutDir: true, sourcemap: false, target: 'es2022', chunkSizeWarningLimit: 800 },
  server: { port: 5174 },
});

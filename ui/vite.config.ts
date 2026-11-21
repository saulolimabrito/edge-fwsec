import { defineConfig } from 'vitest/config';
import { svelte } from '@sveltejs/vite-plugin-svelte';

export default defineConfig({
  plugins: [svelte()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // Appliance UI is served offline; keep output deterministic.
    sourcemap: false,
    modulePreload: { polyfill: false },
  },
  server: {
    // Dev only: forward to the local HTTPS stack (scripts/dev.sh). The
    // backend's same-origin check expects its own origin, so the proxy
    // presents requests as coming from it.
    proxy: {
      '/api': {
        target: 'https://127.0.0.1:8443',
        secure: false,
        changeOrigin: true,
        headers: { Origin: 'https://127.0.0.1:8443' },
      },
    },
  },
  test: { include: ['src/**/*.test.ts'] },
});

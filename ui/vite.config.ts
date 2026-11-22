import { loadEnv } from 'vite';
import { defineConfig } from 'vitest/config';
import { svelte } from '@sveltejs/vite-plugin-svelte';

export default defineConfig(({ mode }) => {
  // Dev only: the HTTPS backend to proxy to (local stack by default; set
  // EFW_DEV_BACKEND to review an installed appliance through a port forward).
  const backend = loadEnv(mode, '.', 'EFW_').EFW_DEV_BACKEND || 'https://127.0.0.1:8443';
  return {
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
          target: backend,
          secure: false,
          changeOrigin: true,
          headers: { Origin: backend },
        },
      },
    },
    test: { include: ['src/**/*.test.ts'] },
  };
});

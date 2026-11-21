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
    proxy: {
      '/api': { target: 'https://127.0.0.1:8443', secure: false },
      '/healthz': { target: 'https://127.0.0.1:8443', secure: false },
    },
  },
  test: { include: ['src/**/*.test.ts'] },
});

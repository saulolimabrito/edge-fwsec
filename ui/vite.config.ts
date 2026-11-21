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
    proxy: { '/api': 'http://127.0.0.1:8080', '/healthz': 'http://127.0.0.1:8080' },
  },
  test: { include: ['src/**/*.test.ts'] },
});

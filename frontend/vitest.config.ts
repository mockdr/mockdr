import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath, URL } from 'node:url'

import pkg from './package.json' with { type: 'json' }

export default defineConfig({
  plugins: [vue()],
  // Must mirror vite.config.ts — components referencing __APP_VERSION__ fail
  // to render under test without it.
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
  },
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    env: {
      VITE_ADMIN_TOKEN: 'admin-token-0000-0000-000000000001',
      VITE_VIEWER_TOKEN: 'viewer-token-0000-0000-000000000002',
      VITE_ANALYST_TOKEN: 'soc-analyst-token-000-000000000003',
    },
    // Exclude Playwright E2E specs from vitest — they use @playwright/test not vitest
    exclude: ['node_modules/**', 'e2e/**'],
    // A timeout should measure the test, not the machine. The default five
    // seconds is generous for a mounted component and not for one mounted
    // while `pytest -n auto` has every core: `ci.sh` runs the two quality
    // gates concurrently, where CI gives them a runner each, and a Graph
    // view that mounts in milliseconds alone timed out at 19s under that
    // load. Fifteen still fails a component that genuinely hangs.
    testTimeout: 15_000,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      // Stores (80% floor) + Components (60% floor per TESTING.md §2).
      // AppLayout has no testable JS (pure template import-only script),
      // so it is excluded to avoid a misleading 0% statements entry.
      include: ['src/stores/**', 'src/components/**', 'src/views/**', 'src/api/**'],
      exclude: ['src/**/__tests__/**', 'node_modules/**', '**/AppLayout.vue'],
      thresholds: {
        lines: 75,
        functions: 70,
        branches: 65,
        statements: 75,
      },
    },
  },
})

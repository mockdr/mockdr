import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath, URL } from 'node:url'

export default defineConfig({
  plugins: [vue()],
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

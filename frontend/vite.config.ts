import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath, URL } from 'node:url'

import pkg from './package.json' with { type: 'json' }

export default defineConfig({
  plugins: [vue()],
  // Surfaced in the sidebar footer. Injected from package.json so the version
  // lives in one place per workspace instead of being retyped in a template.
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
  },
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    port: 3000,
    proxy: {
      '/web/api': {
        target: 'http://localhost:8001',
        changeOrigin: true,
      },
      '/_dev': {
        target: 'http://localhost:8001',
        changeOrigin: true,
        rewrite: (path) => `/web/api/v2.1${path}`,
      },
    },
  },
})

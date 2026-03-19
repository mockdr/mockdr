import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath, URL } from 'node:url'

export default defineConfig({
  plugins: [vue()],
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

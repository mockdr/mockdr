import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
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

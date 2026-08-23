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
      // Every API root the backend serves. A root missing here falls through
      // to the SPA and answers index.html with a 200 — HTML parsed as JSON.
      // Console routes share some prefixes (/splunk/search is a page, /splunk/
      // services/... is the API): a browser navigation asks for text/html and
      // stays with the SPA; an XHR does not and is proxied.
      ...Object.fromEntries(
        ['/web/api', '/cs', '/mde', '/graph', '/sentinel', '/xdr', '/splunk', '/elastic', '/kibana'].map(
          (root) => [
            root,
            {
              target: 'http://localhost:8001',
              changeOrigin: true,
              bypass: (req: { headers: { accept?: string } }) =>
                req.headers.accept?.includes('text/html') ? '/index.html' : undefined,
            },
          ],
        ),
      ),
      '/_dev': {
        target: 'http://localhost:8001',
        changeOrigin: true,
        rewrite: (path) => `/web/api/v2.1${path}`,
      },
    },
  },
})

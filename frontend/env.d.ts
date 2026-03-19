/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_XDR_KEY_ID: string
  readonly VITE_XDR_KEY_SECRET: string
  readonly VITE_CS_CLIENT_ID: string
  readonly VITE_CS_CLIENT_SECRET: string
  readonly VITE_MDE_CLIENT_ID: string
  readonly VITE_MDE_CLIENT_SECRET: string
  readonly VITE_ES_USERNAME: string
  readonly VITE_ES_PASSWORD: string
  readonly VITE_SPLUNK_USERNAME: string
  readonly VITE_SPLUNK_PASSWORD: string
  readonly VITE_ADMIN_TOKEN: string
  readonly VITE_VIEWER_TOKEN: string
  readonly VITE_ANALYST_TOKEN: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}

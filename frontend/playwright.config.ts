import { defineConfig, devices } from '@playwright/test'

/**
 * Playwright E2E configuration for the mockdr frontend.
 *
 * Tests run against the Vite dev server (port 3000) which proxies
 * /web/api calls to the FastAPI mock backend (port 8001).
 *
 * The `webServer` entries start both servers automatically so that
 * `npx playwright test` works in CI and locally without manual setup.
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  retries: process.env['CI'] ? 1 : 0,
  reporter: [['html'], ['github']],
  use: {
    baseURL: process.env['E2E_BASE_URL'] ?? 'http://localhost:3000',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
  webServer: [
    {
      command: 'cd ../backend && uvicorn main:app --host 0.0.0.0 --port 8001 --no-access-log',
      port: 8001,
      reuseExistingServer: !process.env['CI'],
      timeout: 60_000,
    },
    {
      command: 'npm run dev',
      port: 3000,
      reuseExistingServer: !process.env['CI'],
      timeout: 30_000,
    },
  ],
})

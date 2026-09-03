import { defineConfig, devices } from '@playwright/test'

/**
 * Playwright E2E configuration for the mockdr frontend.
 *
 * Tests run against the Vite dev server, which proxies /web/api calls to
 * the FastAPI mock backend on 8001.
 *
 * The `webServer` entries start both automatically so that `npx playwright
 * test` works in CI and locally without manual setup.
 *
 * The front end listens on 3101 rather than 3000, and that is not
 * cosmetic. `reuseExistingServer` cannot tell *what* is already on a port,
 * only that something answers: with Grafana on 3000 — where it, Rails,
 * Next.js and most of the ecosystem default — every test loaded Grafana and
 * failed on a missing login form. Seventy-five red tests that say nothing
 * about this application. 3101 collides with nothing here.
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  retries: process.env['CI'] ? 1 : 0,
  reporter: [['html'], ['github']],
  use: {
    baseURL: process.env['E2E_BASE_URL'] ?? 'http://localhost:3101',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
  webServer: [
    {
      // The venv's own interpreter: there is no `uvicorn` on PATH locally,
      // and a webServer that cannot start is only visible as failing tests.
      command:
        'cd ../backend && .venv/bin/python -m uvicorn main:app'
        + ' --host 0.0.0.0 --port 8001 --no-access-log',
      port: 8001,
      reuseExistingServer: !process.env['CI'],
      timeout: 60_000,
    },
    {
      command: 'npm run dev -- --port 3101 --strictPort',
      port: 3101,
      reuseExistingServer: !process.env['CI'],
      timeout: 30_000,
    },
  ],
})

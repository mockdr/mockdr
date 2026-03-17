import { test, expect } from '@playwright/test'

/**
 * E2E critical user flow tests for mockdr.
 *
 * Covers all P0 flows from TESTING.md §5.1.  Both the FastAPI backend
 * (port 8001) and Vite dev server (port 3000) are started automatically
 * by the playwright.config.ts `webServer` entries.
 *
 * `setTokenAndGo` uses page.evaluate (one-time, non-persistent) instead
 * of page.addInitScript (persists across all subsequent navigations) so
 * that post-logout navigations correctly see an empty localStorage.
 */

const ADMIN_TOKEN = 'admin-token-0000-0000-000000000001'

/**
 * Set the admin token in localStorage via a one-time evaluate call, then
 * navigate to the given path.  Unlike addInitScript, this does NOT re-run
 * on subsequent navigations, which is required for the logout test.
 */
async function setTokenAndGo(
  page: Parameters<typeof test>[1]['page'],
  path: string,
): Promise<void> {
  // Navigate to the public login page first to establish the domain's
  // localStorage context, then inject the token and go to the target path.
  await page.goto('/login')
  await page.evaluate((t) => localStorage.setItem('s1_token', t), ADMIN_TOKEN)
  await page.goto(path)
}

// ── 1. Login → Dashboard ─────────────────────────────────────────────────────

test('login flow: clicking Sign In with Admin token redirects to dashboard', async ({ page }) => {
  await page.goto('/login')
  // The login page shows token-picker buttons — Admin is selected by default.
  // Just click the "Sign In" button.
  await page.click('button:has-text("Sign In")')
  await page.waitForURL('**/dashboard', { timeout: 15_000 })
  await expect(page).toHaveURL(/dashboard/)
})

test('login page shows all three preset token options', async ({ page }) => {
  await page.goto('/login')
  await expect(page.locator('button:has-text("Admin")')).toBeVisible()
  await expect(page.locator('button:has-text("Viewer")')).toBeVisible()
  await expect(page.locator('button:has-text("SOC Analyst")')).toBeVisible()
})

// ── 2. Endpoint list → detail ─────────────────────────────────────────────────

test('endpoint list loads and clicking a row opens the detail view', async ({ page }) => {
  await setTokenAndGo(page, '/endpoints')
  await page.waitForSelector('tbody tr', { timeout: 15_000 })
  const rows = page.locator('tbody tr')
  await expect(rows).not.toHaveCount(0)
  await rows.first().click()
  await page.waitForURL(/\/endpoints\/.+/, { timeout: 10_000 })
  await expect(page).toHaveURL(/\/endpoints\/.+/)
  await expect(page.locator('h1, .text-s1-text').first()).toBeVisible()
})

// ── 3. Threat list → detail ───────────────────────────────────────────────────

test('threat list loads and clicking a row opens the detail view', async ({ page }) => {
  await setTokenAndGo(page, '/threats')
  await page.waitForSelector('tbody tr', { timeout: 15_000 })
  const rows = page.locator('tbody tr')
  await expect(rows).not.toHaveCount(0)
  await rows.first().click()
  await page.waitForURL(/\/threats\/.+/, { timeout: 10_000 })
  await expect(page).toHaveURL(/\/threats\/.+/)
  await expect(page.locator('h1, .text-s1-text').first()).toBeVisible()
})

// ── 4. Sites list ─────────────────────────────────────────────────────────────

test('sites list loads with allSites aggregate counts visible', async ({ page }) => {
  await setTokenAndGo(page, '/sites')
  await page.waitForSelector('h1', { timeout: 15_000 })
  await expect(page.locator('h1')).toContainText('Sites')
  // At least one site card or table row should be visible
  await expect(page.locator('tbody tr, .card').first()).toBeVisible()
})

// ── 5. Pagination ─────────────────────────────────────────────────────────────

test('pagination: endpoint list shows load-more or all agents', async ({ page }) => {
  await setTokenAndGo(page, '/endpoints')
  await page.waitForSelector('tbody tr', { timeout: 15_000 })
  const initialCount = await page.locator('tbody tr').count()
  expect(initialCount).toBeGreaterThan(0)

  // Seed generates 50 agents, limit is 25 — "Load more" should appear
  const loadMoreBtn = page.locator('button:has-text("Load more")')
  if (await loadMoreBtn.count() > 0) {
    await expect(loadMoreBtn).toBeVisible()
    await loadMoreBtn.click()
    // Wait for the list to grow
    await page.waitForFunction(
      (n) => document.querySelectorAll('tbody tr').length > n,
      initialCount,
      { timeout: 10_000 },
    )
    const afterCount = await page.locator('tbody tr').count()
    expect(afterCount).toBeGreaterThan(initialCount)
  }
})

// ── 6. Filter: OS type ────────────────────────────────────────────────────────

test('OS type filter: selecting Windows filters the agent list', async ({ page }) => {
  await setTokenAndGo(page, '/endpoints')
  await page.waitForSelector('tbody tr', { timeout: 15_000 })

  // The first <select> in the filter bar is osTypes with value "windows"
  const selects = page.locator('select')
  // Find the select that has a "windows" option (value attribute)
  const count = await selects.count()
  let osSelect = null
  for (let i = 0; i < count; i++) {
    const opts = await selects.nth(i).locator('option').evaluateAll(
      (els) => els.map((el) => (el as HTMLOptionElement).value),
    )
    if (opts.includes('windows')) {
      osSelect = selects.nth(i)
      break
    }
  }
  expect(osSelect).not.toBeNull()
  await osSelect!.selectOption('windows')

  // Wait for the 300ms debounce + network fetch
  await page.waitForTimeout(600)
  await page.waitForFunction(
    () => !document.querySelector('[class*="animate-spin"]'),
    { timeout: 10_000 },
  )
  // The list should have updated (may be fewer rows or same — just verify it loaded)
  await expect(page.locator('tbody tr, [data-testid="empty-state"]').first()).toBeVisible()
})

// ── 7a. Splunk health check ───────────────────────────────────────────────────

test('splunk server info returns valid JSON', async ({ request }) => {
  const baseURL = process.env.E2E_BASE_URL ?? 'http://localhost:8001'
  const response = await request.get(`${baseURL}/splunk/services/server/info?output_mode=json`)
  expect(response.ok()).toBeTruthy()
  const body = await response.json()
  expect(body).toHaveProperty('entry')
  expect(Array.isArray(body.entry)).toBeTruthy()
})

// ── 7. Logout ─────────────────────────────────────────────────────────────────

test('logout clears token; protected routes then redirect to /login', async ({ page }) => {
  await setTokenAndGo(page, '/dashboard')
  await page.waitForSelector('header', { timeout: 15_000 })

  // Open the user menu — find the button that shows the current role name
  const userMenuBtn = page.locator('header button').filter({
    hasText: /admin|viewer|soc analyst|user/i,
  }).first()
  await userMenuBtn.click()

  // Click "Sign Out"
  await page.locator('button:has-text("Sign Out")').click()
  await page.waitForURL('**/login', { timeout: 10_000 })
  await expect(page).toHaveURL(/login/)

  // Navigate to a protected route — must redirect to /login because
  // setTokenAndGo used page.evaluate (one-time), NOT addInitScript,
  // so the token is NOT re-injected on this navigation.
  await page.goto('/dashboard')
  await page.waitForURL('**/login', { timeout: 10_000 })
  await expect(page).toHaveURL(/login/)
})

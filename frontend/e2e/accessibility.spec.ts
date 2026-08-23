import { test, expect } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

/**
 * WCAG 2.2 AA smoke test (axe-core) on every console page the router lists.
 *
 * Routes are read from src/router/index.ts so a new view is covered the day
 * it is added. Detail routes (with `:id`) are visited through the first row
 * of their list where the list exists; the rest are static pages.
 *
 * Fails on any serious or critical violation. Everything below that is
 * printed so it can be worked down without blocking.
 */

const ADMIN_TOKEN = 'admin-token-0000-0000-000000000001'
const here = dirname(fileURLToPath(import.meta.url))
const router = readFileSync(join(here, '..', 'src', 'router', 'index.ts'), 'utf8')
const STATIC = [...router.matchAll(/path: '([^':]+)'/g)]
  .map((m) => m[1])
  .filter((p) => !p.includes('pathMatch'))
  .map((p) => (p.startsWith('/') ? p : `/${p}`))
const PAGES = Array.from(new Set(STATIC))

test.describe.configure({ mode: 'parallel' })

async function audit(page: import('@playwright/test').Page, path: string): Promise<void> {
  await page.goto(path)
  await page.waitForLoadState('networkidle')
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
    .analyze()
  const blocking = results.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')
  const minor = results.violations.filter((v) => !blocking.includes(v))
  if (minor.length) {
    console.log(`${path}: ${minor.length} non-blocking axe finding(s): ${minor.map((v) => v.id).join(', ')}`)
  }
  expect(
    blocking.map((v) => `${v.id} (${v.impact}) ×${v.nodes.length}: ${v.help} — ${v.nodes[0]?.target.join(' ')}`),
  ).toEqual([])
}

test.beforeEach(async ({ page }) => {
  await page.goto('/login')
  await page.evaluate((t) => localStorage.setItem('s1_token', t), ADMIN_TOKEN)
})

for (const path of PAGES) {
  test(`no serious accessibility violations on ${path}`, async ({ page }) => {
    await audit(page, path)
  })
}

// Detail pages: open the first navigable row of their list.
const DETAIL_LISTS = ['/endpoints', '/threats', '/crowdstrike/hosts', '/defender/machines', '/cortex-xdr/incidents']

for (const list of DETAIL_LISTS) {
  test(`no serious accessibility violations on the first detail page under ${list}`, async ({ page }) => {
    await page.goto(list)
    await page.waitForLoadState('networkidle')
    const row = page.locator('tr[role="link"]').first()
    if ((await row.count()) === 0) test.skip(true, `${list} has no navigable rows`)
    await row.click()
    await page.waitForLoadState('networkidle')
    expect(page.url()).not.toContain(list + '?')
    await audit(page, page.url().replace(/^https?:\/\/[^/]+/, ''))
  })
}

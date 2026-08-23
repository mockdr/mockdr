import { test, expect } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'

/**
 * WCAG 2.2 AA smoke test (axe-core) on the pages a SOC analyst lives in.
 *
 * Fails on any serious or critical violation. Everything below that is
 * reported in the test output so it can be worked down without blocking.
 */

const ADMIN_TOKEN = 'admin-token-0000-0000-000000000001'

const PAGES = ['/login', '/dashboard', '/endpoints', '/threats', '/splunk/search']

for (const path of PAGES) {
  test(`no serious accessibility violations on ${path}`, async ({ page }) => {
    await page.goto('/login')
    await page.evaluate((t) => localStorage.setItem('s1_token', t), ADMIN_TOKEN)
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
      blocking.map((v) => `${v.id} (${v.impact}) ×${v.nodes.length}: ${v.help}`),
    ).toEqual([])
  })
}

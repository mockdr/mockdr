import { expect, test } from '@playwright/test'

/**
 * The two things the chunking commit bought, guarded rather than logged.
 *
 * `_perf.spec.ts` was committed by accident out of that round: four tests
 * that measured and asserted nothing, running in the suite and inflating
 * its count. What it measured is worth keeping, so it says it now.
 *
 * Both bounds sit between two *measured* states rather than being chosen:
 *
 *  - Rollup gave every lucide icon its own ~200-byte chunk, so a navigation
 *    fetched 42-46 JavaScript files. Grouped, it is 15-19. Thirty is
 *    comfortably between the two regimes: it cannot be reached by ordinary
 *    growth and cannot be missed if the grouping is lost.
 *  - Chart.js is 250 kB and belongs on the dashboard, not on the login
 *    screen. Naming a chunk pins it into the static graph, which is why it
 *    is not grouped; the guard is simply that it stays away from login.
 */

const ADMIN_TOKEN = 'admin-token-0000-0000-000000000001'

/** Every resource this page fetched, by kind. */
async function loaded(page: import('@playwright/test').Page) {
  return page.evaluate(() => {
    const entries = performance.getEntriesByType(
      'resource',
    ) as PerformanceResourceTiming[]
    return {
      js: entries.filter((r) => /\.js(\?|$)/.test(r.name)).length,
      all: entries.length,
      kb: Math.round(entries.reduce((sum, r) => sum + (r.transferSize || 0), 0) / 1024),
      chartjs: entries.some((r) => /chart/i.test(r.name)),
    }
  })
}

test('the login screen does not carry the dashboard on its back', async ({ page }) => {
  await page.goto('/login')
  await page.waitForLoadState('networkidle')

  const first = await loaded(page)

  expect(first.chartjs, 'Chart.js is 250 kB and nothing on login draws a chart').toBe(false)
  expect(first.js).toBeLessThanOrEqual(30)
})

for (const path of ['/dashboard', '/endpoints', '/graph/users']) {
  test(`${path} fetches grouped chunks, not one per icon`, async ({ page }) => {
    await page.goto('/login')
    await page.evaluate((t) => localStorage.setItem('s1_token', t), ADMIN_TOKEN)
    await page.goto(path)
    await page.waitForLoadState('networkidle')

    const view = await loaded(page)

    // 15-19 grouped, 42-46 one-per-icon: the bound tells the two apart.
    expect(view.js, `${path} fetched ${view.js} JS files`).toBeLessThanOrEqual(30)
  })
}

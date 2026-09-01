import { test, expect } from '@playwright/test'

/**
 * A table that renders is not a table that says anything.
 *
 * Three views drew rows whose every text cell was empty, and every check
 * this repo had passed over them: the page loaded, the request succeeded,
 * the type check was satisfied because the API layer *declared* the flat
 * shape the table wanted, and the unit tests fed hand-written fixtures in
 * that same wrong shape.
 *
 *   - `/elastic/alerts`      25 rows, every cell blank
 *   - `/elastic/endpoints`   25 rows, every cell blank
 *   - `/elastic` dashboard   the endpoint chart one grey "Unknown" wedge
 *                            and the recent-alerts list nameless
 *   - `/graph/apps`          the publishing state empty, and two columns
 *                            for a field the reference does not list
 *
 * The check counts only cells that ought to carry text — one holding a
 * checkbox, a button or an icon is not blank, it is a control — and allows
 * a generous share of genuinely empty ones, because a column that is often
 * unset is ordinary. What is not ordinary is most of a table being nothing.
 */

const ADMIN_TOKEN = 'admin-token-0000-0000-000000000001'

const VIEWS = [
  '/endpoints', '/threats', '/alerts', '/sites', '/users', '/groups',
  '/exclusions', '/blocklist', '/ioc', '/tags',
  '/crowdstrike/hosts', '/crowdstrike/detections',
  '/defender/machines', '/defender/alerts', '/defender/indicators',
  '/defender/vulnerabilities',
  '/elastic/endpoints', '/elastic/rules', '/elastic/alerts', '/elastic/cases',
  '/cortex-xdr/incidents', '/cortex-xdr/alerts', '/cortex-xdr/endpoints',
  '/splunk/notables', '/splunk/indexes',
  '/sentinel/incidents', '/sentinel/analytics',
  '/graph/users', '/graph/groups', '/graph/devices', '/graph/apps',
  '/graph/security/alerts', '/graph/sign-in-logs',
]

for (const view of VIEWS) {
  test(`${view} fills the rows it draws`, async ({ page }) => {
    await page.goto('/login')
    await page.evaluate((t) => localStorage.setItem('s1_token', t), ADMIN_TOKEN)
    await page.goto(view)
    await page.waitForSelector('tbody tr', { timeout: 15_000 })

    const seen = await page.locator('tbody tr').evaluateAll((rows) => {
      let cells = 0
      let blank = 0
      for (const row of rows.slice(0, 5)) {
        for (const cell of row.querySelectorAll('td')) {
          if (cell.querySelector('input, button, svg, img')) continue
          cells += 1
          const text = (cell.textContent ?? '').trim()
          if (!text || text === '—' || text === '-') blank += 1
        }
      }
      return { rows: rows.length, cells, blank }
    })

    expect(seen.rows, `${view} drew no rows`).toBeGreaterThan(0)
    expect(seen.cells, `${view} has no text cells to check`).toBeGreaterThan(0)
    const share = seen.blank / seen.cells
    expect(share, `${view}: ${Math.round(share * 100)}% of its text cells are `
      + `empty across ${Math.min(seen.rows, 5)} rows`).toBeLessThan(0.4)
  })
}

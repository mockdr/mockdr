import { test, expect } from '@playwright/test'

/**
 * The buttons on a detail page that *act* — isolate, wipe, resolve, close.
 *
 * Nearly thirty of them across seven pages, and none had ever been pressed.
 * Two were broken, both on the Elastic case:
 *
 *   - It sent `updated_at` where Kibana wants the saved object's opaque
 *     `version` — a base64 string like `WzIwNCwxXQ==` on the live 8.15 —
 *     and got 409 "This case has been updated. Please refresh before saving
 *     additional updates." on the first press, every time. `EsCase` did not
 *     declare a `version` at all, so there was nothing right to send.
 *   - Having sent the right one, it kept it. Kibana answers a list of the
 *     cases it updated, each carrying the version the *next* update must
 *     send, so the second press was a 409 too.
 *
 * The pages are visited in one test each rather than all at once, so a
 * failure names the page it happened on.
 */

const ADMIN_TOKEN = 'admin-token-0000-0000-000000000001'

/** (the list to open, the buttons its detail page offers). */
const PAGES: [string, string[]][] = [
  ['/threats', ['Suspicious', 'True Positive', 'Quarantine', 'Kill', 'Remediate']],
  ['/defender/machines', ['Isolate', 'Release', 'Quick Scan', 'Full Scan']],
  ['/cortex-xdr/endpoints', ['Isolate', 'Unisolate', 'Scan']],
  ['/graph/devices', ['Wipe', 'Retire', 'Sync', 'Scan']],
  ['/sentinel/incidents', ['Set Active', 'Reopen', 'Close']],
  // Which of these is on the page depends on the state the incident is in,
  // and other tests move it. Any one of them is enough.
  ['/cortex-xdr/incidents', ['Investigate', 'Resolve (TP)', 'Resolve (FP)', 'Reopen']],
  ['/elastic/cases', ['Close', 'Reopen', 'Mark In Progress']],
]

for (const [list, buttons] of PAGES) {
  test(`the actions on ${list}'s detail page are accepted`, async ({ page }) => {
    const refused: string[] = []
    page.on('response', async (response) => {
      if (response.request().method() === 'GET') return
      if (response.status() < 400 || response.url().includes('/token')) return
      refused.push(`${response.status()} ${response.request().method()} `
        + `${new URL(response.url()).pathname} :: ${(await response.text()).slice(0, 140)}`)
    })

    await page.goto('/login')
    await page.evaluate((t) => localStorage.setItem('s1_token', t), ADMIN_TOKEN)
    await page.goto(list)
    await page.waitForSelector('tbody tr', { timeout: 15_000 })

    const row = page.locator('tbody tr').first()
    const link = row.locator('a').first()
    if (await link.isVisible().catch(() => false)) await link.click()
    else await row.click()
    await page.waitForTimeout(800)

    let pressed = 0
    for (const label of buttons) {
      const button = page.getByRole('button', { name: label, exact: true }).first()
      // A button may be absent because the record is already in that state —
      // "Reopen" on an open case — which is the page being sensible.
      if (!(await button.isVisible().catch(() => false))) continue
      await button.click()
      await page.waitForTimeout(700)
      pressed += 1
    }

    expect(pressed, `${list}: none of ${buttons.join(', ')} was on the page`)
      .toBeGreaterThan(0)
    expect(refused).toEqual([])
  })
}

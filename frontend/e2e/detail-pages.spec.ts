import { test, expect } from '@playwright/test'

/**
 * Every detail page, opened the way a person opens it.
 *
 * The list pages were swept for blank cells; this walks one step further,
 * because a detail page is where an analyst actually works. Two were broken
 * and three were unreachable:
 *
 *   - A Defender machine row pushed `/defender/machines/undefined`. The
 *     `machine` entity names its key `id` — `machineId` is what an *alert*
 *     calls the machine it happened on — and the type declared the wrong
 *     one, so the type check was satisfied and the page answered 404.
 *   - The Cortex endpoint detail filtered on `endpoint_id`. Cortex names
 *     that filter after the list it takes, `endpoint_id_list`, and refuses
 *     the singular outright, naming its fourteen supported fields.
 *   - `/graph/users/:id`, `/graph/devices/:id` and `/graph/groups/:id`
 *     existed, worked, and nothing in the console linked to them.
 */

const ADMIN_TOKEN = 'admin-token-0000-0000-000000000001'

/** (the list, the prefix its detail pages live under). */
const PAIRS: [string, string][] = [
  ['/endpoints', '/endpoints/'],
  ['/threats', '/threats/'],
  ['/crowdstrike/hosts', '/crowdstrike/hosts/'],
  ['/crowdstrike/detections', '/crowdstrike/detections/'],
  ['/defender/machines', '/defender/machines/'],
  ['/elastic/cases', '/elastic/cases/'],
  ['/cortex-xdr/incidents', '/cortex-xdr/incidents/'],
  ['/cortex-xdr/endpoints', '/cortex-xdr/endpoints/'],
  ['/sentinel/incidents', '/sentinel/incidents/'],
  ['/graph/users', '/graph/users/'],
  ['/graph/devices', '/graph/devices/'],
  ['/graph/groups', '/graph/groups/'],
]

for (const [list, prefix] of PAIRS) {
  test(`${list} opens a detail page that says something`, async ({ page }) => {
    const refused: string[] = []
    page.on('response', (response) => {
      if (response.status() >= 400 && !response.url().includes('/token')) {
        refused.push(`${response.status()} ${new URL(response.url()).pathname}`)
      }
    })

    await page.goto('/login')
    await page.evaluate((t) => localStorage.setItem('s1_token', t), ADMIN_TOKEN)
    await page.goto(list)
    await page.waitForSelector('tbody tr', { timeout: 15_000 })

    // A link in the first row if there is one, the row itself otherwise:
    // the console uses both idioms.
    const row = page.locator('tbody tr').first()
    const link = row.locator('a').first()
    if (await link.isVisible().catch(() => false)) await link.click()
    else await row.click()
    await page.waitForTimeout(900)

    const url = new URL(page.url()).pathname
    expect(url, `${list} did not open a detail page`).toContain(prefix)
    expect(url.slice(prefix.length),
      `${list} opened ${url} — no identifier`).not.toBe('')
    expect(url, `${list} opened a page for "undefined"`).not.toContain('undefined')

    const text = (await page.locator('main').innerText()).replace(/\s+/g, ' ')
    expect(text.length,
      `${url} rendered ${text.length} characters`).toBeGreaterThan(150)
    expect(refused, `${url} was refused`).toEqual([])
  })
}

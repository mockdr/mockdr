import { test, expect } from '@playwright/test'

/**
 * Every filter dropdown the console offers, option by option.
 *
 * A filter that changes nothing is invisible from the outside: the page
 * renders, the request succeeds, and the table is simply wrong. Two of them
 * were worse than that — every option emptied the table, because the query
 * named fields the documents do not have:
 *
 *   - The Elastic alerts view asked for `severity` and `status` where a
 *     signal carries `signal.rule.severity` and `signal.status`, and read
 *     the same flat names in its table, so it drew twenty-five rows with
 *     every cell blank.
 *   - The rules view sent Kibana's own saved-object filter, which the *mock*
 *     turned into a substring search over rule names.
 *
 * The check is deliberately weak per option — a value that legitimately has
 * no rows is fine — and strong across them: if every option in a dropdown
 * yields the same count as no filter at all, the dropdown does nothing.
 */

const ADMIN_TOKEN = 'admin-token-0000-0000-000000000001'

const VIEWS = [
  '/threats', '/endpoints', '/alerts',
  '/crowdstrike/hosts', '/crowdstrike/detections',
  '/defender/machines', '/defender/alerts',
  '/cortex-xdr/incidents', '/elastic/alerts', '/elastic/rules',
]

for (const view of VIEWS) {
  test(`the filters on ${view} narrow something`, async ({ page }) => {
    const refused: string[] = []
    page.on('response', (r) => {
      if (r.status() >= 400 && !r.url().includes('/token')) {
        refused.push(`${r.status()} ${new URL(r.url()).pathname}`)
      }
    })
    await page.goto('/login')
    await page.evaluate((t) => localStorage.setItem('s1_token', t), ADMIN_TOKEN)
    await page.goto(view)
    await page.waitForSelector('tbody tr', { timeout: 15_000 })

    const selects = page.locator('select:visible')
    const howMany = await selects.count()
    expect(howMany, `${view} shows no filters`).toBeGreaterThan(0)

    for (let index = 0; index < howMany; index++) {
      const box = selects.nth(index)
      const label = (await box.getAttribute('aria-label')) ?? `select ${index}`
      const values = (await box.locator('option').evaluateAll(
        (options) => options.map((o) => (o as HTMLOptionElement).value),
      )).filter(Boolean)
      if (values.length < 2) continue

      await box.selectOption('')
      await page.waitForTimeout(350)
      const unfiltered = await page.locator('tbody tr').count()

      const counts: number[] = []
      for (const value of values) {
        await box.selectOption(value)
        await page.waitForTimeout(350)
        counts.push(await page.locator('tbody tr').count())
      }
      await box.selectOption('')
      await page.waitForTimeout(300)

      expect(counts.some((n) => n !== unfiltered),
        `${view} — "${label}" gives ${unfiltered} rows for every option, `
        + `which is what no filter gives`).toBe(true)
      expect(counts.some((n) => n > 0),
        `${view} — "${label}" empties the table for every option`).toBe(true)
    }
    expect(refused).toEqual([])
  })
}

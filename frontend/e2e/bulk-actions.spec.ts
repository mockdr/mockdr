import { test, expect } from '@playwright/test'

/**
 * The console's bulk actions, pressed in a browser.
 *
 * The four buttons on the threats view posted to `/threats/actions/<name>`,
 * a path family SentinelOne does not have — every click was a 404. Nothing
 * saw it: the unit tests mock the API client, and the e2e suite walked the
 * pages without pressing anything. So this presses them, and checks the
 * record afterwards rather than the request.
 *
 * `mark-as-threat` and `mark-as-benign` are one route with two verdicts,
 * `resolve` is a different route with a status, and `add-to-blocklist` is a
 * third with a scope — which is why one generic dispatcher could never have
 * served them.
 */

const ADMIN_TOKEN = 'admin-token-0000-0000-000000000001'
const API = process.env['E2E_API_URL'] ?? 'http://localhost:8001'

async function signIn(page: Parameters<typeof test>[1]['page'], path: string): Promise<void> {
  await page.goto('/login')
  await page.evaluate((t) => localStorage.setItem('s1_token', t), ADMIN_TOKEN)
  await page.goto(path)
}

/** One threat's verdict and incident status, read straight from the API. */
async function threat(request: Parameters<typeof test>[1]['request'], id: string) {
  const response = await request.get(`${API}/web/api/v2.1/threats`, {
    params: { ids: id },
    headers: { Authorization: `ApiToken ${ADMIN_TOKEN}` },
  })
  expect(response.ok()).toBeTruthy()
  const body = await response.json()
  return body.data[0].threatInfo as Record<string, string>
}

/** Tick the first row's checkbox and wait for the toolbar to appear. */
async function selectFirstRow(page: Parameters<typeof test>[1]['page']): Promise<void> {
  await page.waitForSelector('tbody tr', { timeout: 15_000 })
  const rows = page.locator('tbody tr')
  await expect(rows.first()).toBeVisible()
  await rows.first().locator('input[type="checkbox"]').check()
  await expect(page.getByText('1 selected')).toBeVisible()
}

// Serial: these press buttons that change the same first row, against one
// shared backend. Run in parallel they overwrite each other's verdict and
// fail for a reason that has nothing to do with the console.
test.describe.serial('bulk actions on the threats view', () => {
  test('the toolbar appears only once something is selected', async ({ page }) => {
    await signIn(page, '/threats')
    await page.waitForSelector('tbody tr', { timeout: 15_000 })
    await expect(page.getByRole('button', { name: /Mark as Benign/i })).toHaveCount(0)

    await page.locator('tbody tr').first().locator('input[type="checkbox"]').check()
    await expect(page.getByRole('button', { name: /Mark as Benign/i })).toBeVisible()
  })

  test('Mark as Benign sets the analyst verdict on the record', async ({ page, request }) => {
    await signIn(page, '/threats')
    await selectFirstRow(page)

    const responded = page.waitForResponse(
      (r) => r.url().includes('/threats/analyst-verdict') && r.request().method() === 'POST',
    )
    await page.getByRole('button', { name: /Mark as Benign/i }).click()
    const call = await responded
    expect(call.status()).toBe(200)

    const sent = JSON.parse(call.request().postData() ?? '{}')
    expect(sent.data).toEqual({ analystVerdict: 'false_positive' })
    // The record, not the request: a 200 proves the route exists and
    // nothing more. Both of those were true before, and the verdict still
    // did not move.
    for (const id of sent.filter.ids as string[]) {
      expect((await threat(request, id))['analystVerdict']).toBe('false_positive')
    }
  })

  test('Resolve sets the incident status on the record', async ({ page, request }) => {
    await signIn(page, '/threats')
    await selectFirstRow(page)

    const responded = page.waitForResponse(
      (r) => r.url().includes('/threats/incident') && r.request().method() === 'POST',
    )
    await page.getByRole('button', { name: /^Resolve$/i }).click()
    const call = await responded
    expect(call.status()).toBe(200)

    const sent = JSON.parse(call.request().postData() ?? '{}')
    expect(sent.data).toEqual({ incidentStatus: 'resolved' })
    for (const id of sent.filter.ids as string[]) {
      expect((await threat(request, id))['incidentStatus']).toBe('resolved')
    }
  })

  test('Add to Blocklist reaches the route the vendor spells "blacklist"', async ({ page }) => {
    await signIn(page, '/threats')
    await selectFirstRow(page)

    const responded = page.waitForResponse(
      (r) => r.url().includes('/threats/add-to-blacklist') && r.request().method() === 'POST',
    )
    await page.getByRole('button', { name: /Add to Blocklist/i }).click()
    expect((await responded).status()).toBe(200)
  })

  test('no bulk action answers 4xx or 5xx', async ({ page }) => {
    const refused: string[] = []
    page.on('response', (r) => {
      if (r.status() >= 400 && r.url().includes('/web/api/')) {
        refused.push(`${r.status()} ${r.request().method()} ${new URL(r.url()).pathname}`)
      }
    })
    await signIn(page, '/threats')
    await selectFirstRow(page)

    for (const name of [/Mark as Threat/i, /Mark as Benign/i, /^Resolve$/i, /Add to Blocklist/i]) {
      await page.locator('tbody tr').first().locator('input[type="checkbox"]').check()
      await page.getByRole('button', { name }).click()
      await page.waitForTimeout(250)
    }
    expect(refused).toEqual([])
  })
})

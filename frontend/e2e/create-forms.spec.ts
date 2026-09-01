import { test, expect } from '@playwright/test'

/**
 * Every create form the console offers, filled in and submitted.
 *
 * Walking the pages is not using them. The e2e suite visited all 75 routes
 * without pressing anything, so two of these had been answering 400 since
 * they were written:
 *
 *   - Create Case sent no `owner`, and Kibana refuses a case without the
 *     solution it belongs to — `Invalid value "undefined" supplied to
 *     "owner"`. Measured on 8.15: securitySolution, observability and cases
 *     are accepted, anything else is 403.
 *   - Create Rule sent no `query`, and the *mock* refused it. 8.15 accepts a
 *     query rule with no query and stores `query: ""`, so the console was
 *     right and the mock was not.
 *
 * The submit button is found inside the dialog rather than by name: on the
 * Defender page the opener is also called "Create", and picking the first
 * match just reopens the form — which is how that one looked broken for
 * twenty minutes while it was fine.
 */

const ADMIN_TOKEN = 'admin-token-0000-0000-000000000001'

/** (route, the button that opens the form, what to type where). */
const FORMS: [string, string, Record<string, string>][] = [
  ['/sites', 'New Site', { }],
  ['/users', 'Create User', { }],
  ['/exclusions', 'Add Exclusion', { }],
  ['/blocklist', 'Add Hash', { }],
  ['/groups', 'New Group', { }],
  ['/tags', 'Create Tag', { }],
  ['/elastic/cases', 'Create Case',
   { 'Case title': 'Probe case', 'Case description': 'Raised by the suite.' }],
  ['/elastic/rules', 'Create Rule',
   { 'Rule name': 'Probe rule', 'Rule description': 'Raised by the suite.' }],
  ['/defender/indicators', 'Create',
   { 'e.g. 192.168.1.1': '198.51.100.9', 'Indicator title': 'Probe indicator' }],
]

test.describe.serial('the console can fill in its own forms', () => {
  for (const [route, opener, fields] of FORMS) {
    test(`${route}: ${opener} is accepted`, async ({ page }) => {
      const refused: string[] = []
      page.on('response', async (response) => {
        const method = response.request().method()
        if (method === 'GET' || response.status() < 400) return
        if (response.url().includes('/token')) return
        refused.push(`${response.status()} ${method} ${new URL(response.url()).pathname}`
          + ` :: ${(await response.text()).slice(0, 160)}`)
      })

      await page.goto('/login')
      await page.evaluate((t) => localStorage.setItem('s1_token', t), ADMIN_TOKEN)
      await page.goto(route)
      await page.getByRole('button', { name: new RegExp(`^${opener}$`, 'i') })
        .first().click()

      for (const [placeholder, value] of Object.entries(fields)) {
        await page.getByPlaceholder(placeholder).fill(value)
      }
      // Anything the form left blank: enough to satisfy a required field
      // without pretending to know what each one means. Typed inputs count
      // too — the user form's submit stays disabled until the e-mail box
      // has something in it, and a filler that only knew about text boxes
      // waited thirty seconds for a button that was never going to enable.
      const blanks = page.locator(
        'input[type="text"]:visible, input[type="email"]:visible, '
        + 'input[type="url"]:visible, input:not([type]):visible, textarea:visible')
      for (let i = 0; i < await blanks.count(); i++) {
        const box = blanks.nth(i)
        if (await box.inputValue()) continue
        const kind = await box.getAttribute('type')
        await box.fill(kind === 'email' ? 'probe@acmecorp.internal' : `probe-${i}`)
          .catch(() => {})
      }

      // The dialog's own submit — the last one, since the page's opener may
      // carry the same word.
      const submit = page.getByRole('button', { name: /^(Create|Save|Add)$/i })
      await submit.last().click()
      await page.waitForTimeout(600)

      expect(refused).toEqual([])
    })
  }
})

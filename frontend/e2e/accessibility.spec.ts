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

/**
 * Visit a page and hold it to three things.
 *
 * axe on its own was not enough: it reports what is wrong with the markup a
 * page rendered, and finds nothing wrong with markup a page never rendered.
 * A blank shell, a view whose data call was refused, a permanent loading
 * skeleton — every one of those passed a sweep of 75 routes that only asked
 * whether the accessibility tree had serious violations.
 *
 * So the page must also show its own header (or, on a detail page, some
 * content: those eight views carry no `h1`), and nothing it asked the
 * backend for may have been refused.
 */
async function audit(
  page: import('@playwright/test').Page,
  path: string,
  options: { heading?: boolean } = {},
): Promise<void> {
  const { heading = true } = options
  const refused: string[] = []
  const onResponse = (response: import('@playwright/test').Response): void => {
    const url = new URL(response.url())
    if (response.status() >= 400 && !url.pathname.includes('favicon')) {
      refused.push(`${response.status()} ${response.request().method()} ${url.pathname}`)
    }
  }
  page.on('response', onResponse)
  await page.goto(path)
  await page.waitForLoadState('networkidle')
  page.off('response', onResponse)

  if (heading) {
    const title = page.locator('h1').first()
    await expect(title, `${path} rendered no heading`).toBeVisible()
    expect((await title.innerText()).trim(), `${path} has an empty heading`).not.toBe('')
  } else {
    const body = (await page.locator('main').first().innerText()).trim()
    expect(body.length, `${path} rendered ${body.length} characters of content`)
      .toBeGreaterThan(40)
  }
  expect(refused, `${path} asked for something it was refused`).toEqual([])

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
    // A detail view carries no `h1` — none of the eight do — so it is held
    // to having rendered content instead.
    await audit(page, page.url().replace(/^https?:\/\/[^/]+/, ''), { heading: false })
  })
}

import { test, expect } from '@playwright/test'

/**
 * The number on a dashboard card, against the collection it summarises.
 *
 * A card is what somebody reads instead of opening the list, so a wrong one
 * is believed. Three were:
 *
 *   - "Active Threats" counted `threatInfo.resolved`, a field the 2.1 schema
 *     does not declare and the answer does not carry, so all thirty threats
 *     counted as active while six were resolved. (`?resolved=` is a *filter*
 *     the vendor keeps for 2.0 compatibility, not a property of the record —
 *     and the mock read it off the same missing field, so it answered
 *     `resolved=true` with nothing.)
 *   - "Endpoints Offline" counted only `disconnected`, and `networkStatus`
 *     has four values; the agents mid-transition were in neither bar of the
 *     chart either.
 *   - Sentinel's cards were drawn from the first page of incidents — 50 of
 *     165 — while the answer's own `nextLink` said there were more.
 *
 * Each expectation below is the API's own count, fetched in the test rather
 * than written down, so the seed can change without this going stale.
 *
 * The counts are read on both sides of the page load and the card must
 * match one of them. Other files in this suite resolve threats and create
 * users against the same backend, so a count taken once can be stale by the
 * time the page renders — which is a race in the test, not a wrong card,
 * and it cost one confusing red run to see that.
 */

/** Read a count twice, around whatever happens in between. */
async function around<T>(read: () => Promise<T>, act: () => Promise<void>): Promise<[T, T]> {
  const before = await read()
  await act()
  return [before, await read()]
}

const ADMIN_TOKEN = 'admin-token-0000-0000-000000000001'
const API = process.env['E2E_API_URL'] ?? 'http://localhost:8001'
const S1 = { Authorization: `ApiToken ${ADMIN_TOKEN}` }


/** The number on the card whose label matches. */
async function card(page: Parameters<typeof test>[1]['page'], label: string): Promise<number> {
  const text = await page.locator('.card').filter({ hasText: label }).first().innerText()
  const digits = text.replace(/\s+/g, ' ').match(/(\d[\d,]*)/)
  expect(digits, `no number on the "${label}" card: ${text}`).toBeTruthy()
  return Number((digits as RegExpMatchArray)[1].replace(/,/g, ''))
}

async function signIn(page: Parameters<typeof test>[1]['page'], route: string): Promise<void> {
  await page.goto('/login')
  await page.evaluate((t) => localStorage.setItem('s1_token', t), ADMIN_TOKEN)
  await page.goto(route)
  // A fixed wait read a card mid-render often enough to cost a red run;
  // the cards fill from several calls, so wait for the last one to land.
  await page.waitForLoadState('networkidle')
  await page.waitForTimeout(300)
}

test.describe('a dashboard card counts what it says it counts', () => {
  test('the SentinelOne dashboard', async ({ page, request }) => {
    const read = async () => {
      const agents = await (await request.get(`${API}/web/api/v2.1/agents`,
        { params: { limit: 200 }, headers: S1 })).json()
      const threats = await (await request.get(`${API}/web/api/v2.1/threats`,
        { params: { limit: 200 }, headers: S1 })).json()
      const unresolved = await (await request.get(`${API}/web/api/v2.1/cloud-detection/alerts`,
        { params: { incidentStatuses: 'unresolved', limit: 1 }, headers: S1 })).json()
      return {
        endpoints: agents.pagination.totalItems as number,
        offline: agents.data.filter(
          (a: { networkStatus: string }) => a.networkStatus !== 'connected').length,
        active: threats.data.filter(
          (t: { threatInfo: { incidentStatus: string } }) =>
            t.threatInfo.incidentStatus !== 'resolved').length,
        threats: threats.pagination.totalItems as number,
        unresolved: unresolved.pagination.totalItems as number,
      }
    }
    const [before, after] = await around(read, () => signIn(page, '/dashboard'))

    expect([before.endpoints, after.endpoints]).toContain(await card(page, 'Total Endpoints'))
    expect([before.active, after.active]).toContain(await card(page, 'Active Threats'))
    expect([before.unresolved, after.unresolved]).toContain(await card(page, 'Unresolved Alerts'))
    expect([before.offline, after.offline]).toContain(await card(page, 'Endpoints Offline'))
    // The one that hid the bug: every threat counted as active.
    expect(after.active).toBeLessThan(after.threats)
  })

  test('the Sentinel dashboard reads the estate, not the first page', async ({ page, request }) => {
    const token = await (await request.post(`${API}/sentinel/oauth2/v2.0/token`, {
      form: {
        grant_type: 'client_credentials', client_id: 'sentinel-mock-client-id',
        client_secret: 'sentinel-mock-client-secret',
        scope: 'https://management.azure.com/.default',
      },
    })).json()
    const workspace = '/subscriptions/00000000-0000-0000-0000-000000000000'
      + '/resourceGroups/mockdr-rg/providers/Microsoft.OperationalInsights'
      + '/workspaces/mockdr-workspace/providers/Microsoft.SecurityInsights'
    // Sentinel's incidents *are* moved by the rest of this suite: the
    // bridge turns a write on another mount into an incident here, which is
    // the mock being one world rather than eight. Five appeared while the
    // create-form tests ran, so these counts are read on both sides too.
    const read = async () => {
      const incidents = await (await request.get(`${API}/sentinel${workspace}/incidents`, {
        params: { 'api-version': '2024-03-01', $top: 1000 },
        headers: { Authorization: `Bearer ${token.access_token}` },
      })).json()
      const by = (status: string) => incidents.value.filter(
        (i: { properties: { status: string } }) => i.properties.status === status).length
      return { total: incidents.value.length as number,
               New: by('New'), Active: by('Active'), Closed: by('Closed') }
    }
    const [before, after] = await around(read, () => signIn(page, '/sentinel'))

    // Bracketed rather than matched against two point reads: the collection
    // grows *during* the page load as the rest of the suite writes, so the
    // card can legitimately land between the two counts instead of on
    // either. What is being asserted is that it counts the estate — a card
    // reading the first page of 50 falls outside the bracket, which is the
    // defect this test exists for.
    const between = async (label: string, low: number, high: number) => {
      const shown = await card(page, label)
      expect(shown, `${label}: ${shown} outside [${low}, ${high}]`)
        .toBeGreaterThanOrEqual(Math.min(low, high))
      expect(shown).toBeLessThanOrEqual(Math.max(low, high))
    }

    await between('Open Incidents', before.New, after.New)
    await between('Active Incidents', before.Active, after.Active)
    await between('Closed Incidents', before.Closed, after.Closed)
    // A page is 50; the estate is larger, which is the whole point.
    expect(after.total).toBeGreaterThan(50)
  })

  test('the Defender dashboard counts past its first page', async ({ page, request }) => {
    const token = await (await request.post(`${API}/mde/oauth2/v2.0/token`, {
      form: {
        grant_type: 'client_credentials', client_id: 'mde-mock-admin-client',
        client_secret: 'mde-mock-admin-secret',
        scope: 'https://api.securitycenter.microsoft.com/.default',
      },
    })).json()
    const machines = await (await request.get(`${API}/mde/api/machines`, {
      params: { $top: 1000 },
      headers: { Authorization: `Bearer ${token.access_token}` },
    })).json()

    await signIn(page, '/defender')
    expect(await card(page, 'Total Machines')).toBe(machines.value.length)
    expect(machines.value.length).toBeGreaterThan(50)
  })
})

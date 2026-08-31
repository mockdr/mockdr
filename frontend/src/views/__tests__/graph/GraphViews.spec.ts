/**
 * Every Graph view, mounted over the answers the mock actually gives.
 *
 * This console had no unit tests at all — 24 views, its store and its API
 * client — and all three defects the end-to-end sweep found on the day it
 * was strengthened were in it: a token call missing its `scope`, autopilot
 * profiles asked for under `v1.0` when they are a beta resource, and a drive
 * listing asking for a path Graph does not serve. Each showed the same
 * symptom, an empty state over a store that had data.
 *
 * The fixtures are not written here. `scripts/gen_graph_fixtures.py` asks
 * the mock exactly what this console asks it and writes the answers down,
 * because a hand-written fixture is a guess at what the backend answers and
 * one of them guessed wrong: `AlertsView`'s gave `agentRealtimeInfo` an
 * object where the product answers `null`, so the view read a property off
 * null and rendered nothing while 2 103 unit tests passed over it.
 * `scripts/frontend_fixture_drift.py` compares the file with the mock again,
 * so a fixture that stops matching fails rather than lies.
 *
 * What each case asserts is deliberately shallow and the same for all of
 * them: the view renders its heading, and it renders a value taken from the
 * captured answer. The second is the one that matters — it is what an empty
 * state, a crashed setup and a refused request all fail.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory, type Router } from 'vue-router'

import responses from './__fixtures__/graph-responses.json'

const captured = responses as Record<string, { value?: unknown[] } & Record<string, unknown>>

/** The captured answer for a path, or an empty collection. */
function answer(path: string): Record<string, unknown> {
  return captured[path] ?? { value: [] }
}

/** The captured answer for a path that carries an id. */
function answerFor(template: string): Record<string, unknown> {
  return captured[template] ?? { value: [] }
}

vi.mock('../../../api/graph', () => ({
  ensureGraphAuth: vi.fn().mockResolvedValue(undefined),
  graphClient: { get: vi.fn((path: string) => Promise.resolve(answer(path))) },
  graphUsersApi: {
    list: vi.fn(() => Promise.resolve(answer('/v1.0/users'))),
    get: vi.fn(() => Promise.resolve(answerFor('/v1.0/users/{id}'))),
  },
  graphGroupsApi: {
    list: vi.fn(() => Promise.resolve(answer('/v1.0/groups'))),
    get: vi.fn(() => Promise.resolve(answerFor('/v1.0/groups/{id}'))),
    getMembers: vi.fn(() => Promise.resolve(answerFor('/v1.0/groups/{id}/members'))),
  },
  graphDevicesApi: {
    list: vi.fn(() => Promise.resolve(answer('/v1.0/deviceManagement/managedDevices'))),
    get: vi.fn(() => Promise.resolve(answerFor('/v1.0/deviceManagement/managedDevices/{id}'))),
    wipe: vi.fn().mockResolvedValue({}),
    sync: vi.fn().mockResolvedValue({}),
    scan: vi.fn().mockResolvedValue({}),
  },
  graphSecurityApi: {
    listAlerts: vi.fn(() => Promise.resolve(answer('/v1.0/security/alerts_v2'))),
    listIncidents: vi.fn(() => Promise.resolve(answer('/v1.0/security/incidents'))),
    listScores: vi.fn(() => Promise.resolve(answer('/v1.0/security/secureScores'))),
  },
  graphIdentityApi: {
    listCaPolicies: vi.fn(() =>
      Promise.resolve(answer('/v1.0/identity/conditionalAccess/policies'))),
    listRiskyUsers: vi.fn(() => Promise.resolve(answer('/v1.0/identityProtection/riskyUsers'))),
    listSignInLogs: vi.fn(() => Promise.resolve(answer('/v1.0/auditLogs/signIns'))),
    listAuditLogs: vi.fn(() => Promise.resolve(answer('/v1.0/auditLogs/directoryAudits'))),
  },
  graphIntuneApi: {
    listCompliance: vi.fn(() =>
      Promise.resolve(answer('/v1.0/deviceManagement/deviceCompliancePolicies'))),
    listConfigs: vi.fn(() =>
      Promise.resolve(answer('/v1.0/deviceManagement/deviceConfigurations'))),
    listAutopilot: vi.fn(() =>
      Promise.resolve(answer('/v1.0/deviceManagement/windowsAutopilotDeviceIdentities'))),
    listApps: vi.fn(() => Promise.resolve(answer('/v1.0/deviceAppManagement/mobileApps'))),
  },
  graphMailApi: {
    listMessages: vi.fn(() => Promise.resolve(answerFor('/v1.0/users/{id}/messages'))),
    listFolders: vi.fn(() => Promise.resolve(answerFor('/v1.0/users/{id}/mailFolders'))),
  },
  graphFilesApi: {
    getDrive: vi.fn(() => Promise.resolve(answerFor('/v1.0/users/{id}/drive'))),
    listChildren: vi.fn(() =>
      Promise.resolve(answerFor('/v1.0/users/{id}/drive/root/children'))),
    listSites: vi.fn(() => Promise.resolve(answer('/v1.0/sites'))),
  },
  graphTeamsApi: {
    list: vi.fn(() => Promise.resolve(answer('/v1.0/teams'))),
    listChannels: vi.fn(() => Promise.resolve(answerFor('/v1.0/teams/{id}/channels'))),
    listMessages: vi.fn().mockResolvedValue({ value: [] }),
  },
  graphAdminApi: {
    list: vi.fn(() => Promise.resolve(answer('/v1.0/subscribedSkus'))),
    listSkus: vi.fn(() => Promise.resolve(answer('/v1.0/subscribedSkus'))),
    listHealth: vi.fn(() =>
      Promise.resolve(answer('/v1.0/admin/serviceAnnouncement/healthOverviews'))),
    listSimulations: vi.fn(() =>
      Promise.resolve(answer('/v1.0/security/attackSimulation/simulations'))),
  },
}))

/** A value from a captured record, to look for in the rendered page. */
function aValueFrom(path: string, field: string): string {
  const body = captured[path]
  const rows = (body?.['value'] ?? []) as Record<string, unknown>[]
  const found = rows.map((r) => r[field]).find((v) => typeof v === 'string' && v.length > 2)
  return String(found ?? '')
}

/**
 * Each view, the captured path it draws from, and a field of that path whose
 * value has to reach the page. `null` where a view shows no field verbatim.
 */
const VIEWS: [string, string, string | null][] = [
  ['GraphUsersView', '/v1.0/users', 'displayName'],
  ['GraphGroupsView', '/v1.0/groups', 'displayName'],
  ['GraphDevicesView', '/v1.0/deviceManagement/managedDevices', 'deviceName'],
  ['GraphSecurityAlertsView', '/v1.0/security/alerts_v2', 'title'],
  ['GraphSecurityIncidentsView', '/v1.0/security/incidents', 'displayName'],
  ['GraphConditionalAccessView', '/v1.0/identity/conditionalAccess/policies', 'displayName'],
  ['GraphIdentityProtectionView', '/v1.0/identityProtection/riskyUsers', 'userDisplayName'],
  ['GraphSignInLogsView', '/v1.0/auditLogs/signIns', 'userDisplayName'],
  ['GraphAuditLogsView', '/v1.0/auditLogs/directoryAudits', 'activityDisplayName'],
  ['GraphComplianceView', '/v1.0/deviceManagement/deviceCompliancePolicies', 'displayName'],
  ['GraphDeviceConfigView', '/v1.0/deviceManagement/deviceConfigurations', 'displayName'],
  ['GraphAppsView', '/v1.0/deviceAppManagement/mobileApps', 'displayName'],
  ['GraphTeamsView', '/v1.0/teams', 'displayName'],
  ['GraphLicensesView', '/v1.0/subscribedSkus', 'skuPartNumber'],
  ['GraphMailView', '/v1.0/users/{id}/messages', 'subject'],
  ['GraphFilesView', '/v1.0/users/{id}/drive/root/children', 'name'],
  ['GraphAttackSimView', '/v1.0/security/attackSimulation/simulations', 'displayName'],
  ['GraphAutopilotView', '/beta/deviceManagement/windowsAutopilotDeploymentProfiles', null],
  ['GraphUpdateRingsView', '/beta/deviceManagement/windowsUpdateForBusinessConfigurations', null],
  ['GraphDashboardView', '/v1.0/users', null],
  ['GraphPlanComparisonView', '/v1.0/subscribedSkus', null],
]

function router(): Router {
  return createRouter({
    history: createWebHistory(),
    routes: [{ path: '/:pathMatch(.*)*', component: { template: '<div />' } }],
  })
}

describe('the Graph console renders what the mock answers', () => {
  beforeEach(() => vi.clearAllMocks())

  it.each(VIEWS)('%s mounts and shows its heading', async (name) => {
    const view = await import(`../../graph/${name}.vue`)
    const wrapper = mount(view.default, { global: { plugins: [router()] } })
    await flushPromises()
    expect(wrapper.find('h1').exists()).toBe(true)
    expect(wrapper.find('h1').text().trim()).not.toBe('')
  })

  it.each(VIEWS.filter(([, , field]) => field !== null))(
    '%s puts a captured value on the page',
    async (name, path, field) => {
      const wanted = aValueFrom(path, field as string)
      expect(wanted, `${path} carries no usable ${field} to look for`).not.toBe('')
      const view = await import(`../../graph/${name}.vue`)
      const wrapper = mount(view.default, { global: { plugins: [router()] } })
      await flushPromises()
      expect(wrapper.text()).toContain(wanted)
    },
  )
})

/**
 * Tests for the S1-native API modules:
 * agents, alerts, threats, tags, system, misc
 *
 * Each module simply wraps `client` (an axios instance), so we mock
 * the client module and verify each API method calls client with the
 * correct HTTP verb and URL/body.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'

// ── Mock the axios-based client ──────────────────────────────────────────────

const mockGet    = vi.hoisted(() => vi.fn().mockResolvedValue({}))
const mockPost   = vi.hoisted(() => vi.fn().mockResolvedValue({}))
const mockPut    = vi.hoisted(() => vi.fn().mockResolvedValue({}))
const mockDelete = vi.hoisted(() => vi.fn().mockResolvedValue({}))

vi.mock('../client', () => ({
  default: {
    get:    mockGet,
    post:   mockPost,
    put:    mockPut,
    delete: mockDelete,
  },
}))

// ── Import APIs after mock is set up ────────────────────────────────────────

import { agentsApi }  from '@/api/agents'
import { alertsApi }  from '@/api/alerts'
import { threatsApi } from '@/api/threats'
import { tagsApi }    from '@/api/tags'
import {
  systemApi,
  proxyApi,
  webhooksApi,
} from '@/api/system'
import {
  sitesApi,
  groupsApi,
  activitiesApi,
  exclusionsApi,
  blocklistApi,
  firewallApi,
  deviceControlApi,
  iocsApi,
  dvApi,
  accountsApi,
  usersApi,
} from '@/api/misc'

// ── Helpers ──────────────────────────────────────────────────────────────────

function isPromise(v: unknown): boolean {
  return v instanceof Promise
}

// ── agentsApi ────────────────────────────────────────────────────────────────

describe('agentsApi', () => {
  beforeEach(() => vi.clearAllMocks())

  it('list returns promise', () => {
    expect(isPromise(agentsApi.list())).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/agents', expect.any(Object))
  })

  it('list passes params', () => {
    agentsApi.list({ limit: 10 })
    expect(mockGet).toHaveBeenCalledWith('/agents', { params: { limit: 10 } })
  })

  it('get returns promise', () => {
    expect(isPromise(agentsApi.get('a1'))).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/agents/a1')
  })

  it('passphrase returns promise', () => {
    expect(isPromise(agentsApi.passphrase('a1'))).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/agents/a1/passphrase')
  })

  it('processes returns promise', () => {
    expect(isPromise(agentsApi.processes('a1'))).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/agents/a1/processes', expect.any(Object))
  })

  it('applications returns promise', () => {
    expect(isPromise(agentsApi.applications('a1'))).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/agents/a1/applications', expect.any(Object))
  })

  it('action returns promise', () => {
    expect(isPromise(agentsApi.action('connect', { filter: { ids: ['a1'] } }))).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/agents/actions/connect', expect.any(Object))
  })
})

// ── alertsApi ────────────────────────────────────────────────────────────────

describe('alertsApi', () => {
  beforeEach(() => vi.clearAllMocks())

  it('list returns promise', () => {
    expect(isPromise(alertsApi.list())).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/cloud-detection/alerts', expect.any(Object))
  })

  it('list passes params', () => {
    alertsApi.list({ limit: 5 })
    expect(mockGet).toHaveBeenCalledWith('/cloud-detection/alerts', { params: { limit: 5 } })
  })

  it('get returns promise', () => {
    expect(isPromise(alertsApi.get('alert-1'))).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/cloud-detection/alerts/alert-1')
  })

  it('action returns promise', () => {
    expect(isPromise(alertsApi.action('star', { filter: { ids: ['alert-1'] } }))).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/alerts/star', expect.any(Object))
  })
})

// ── threatsApi ────────────────────────────────────────────────────────────────

describe('threatsApi', () => {
  beforeEach(() => vi.clearAllMocks())

  it('list returns promise', () => {
    expect(isPromise(threatsApi.list())).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/threats', expect.any(Object))
  })

  it('get returns promise', () => {
    expect(isPromise(threatsApi.get('t1'))).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/threats/t1')
  })

  it('timeline returns promise', () => {
    expect(isPromise(threatsApi.timeline('t1'))).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/threats/t1/timeline')
  })

  it('getNotes returns promise', () => {
    expect(isPromise(threatsApi.getNotes('t1'))).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/threats/t1/notes')
  })

  it('addNote returns promise', () => {
    expect(isPromise(threatsApi.addNote('t1', 'test note'))).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/threats/t1/notes', { text: 'test note' })
  })

  it('setVerdict returns promise', () => {
    expect(isPromise(threatsApi.setVerdict(['t1'], 'true_positive'))).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/threats/analyst-verdict', expect.objectContaining({
      data: { verdict: 'true_positive' },
      filter: { ids: ['t1'] },
    }))
  })

  it('setIncident returns promise', () => {
    expect(isPromise(threatsApi.setIncident(['t1'], 'resolved'))).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/threats/incident', expect.any(Object))
  })

  it('mitigate returns promise', () => {
    expect(isPromise(threatsApi.mitigate('kill', ['t1']))).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/threats/mitigate/kill', expect.any(Object))
  })

  it('addToBlacklist returns promise', () => {
    expect(isPromise(threatsApi.addToBlacklist(['t1']))).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/threats/add-to-blacklist', expect.any(Object))
  })

  it('action returns promise', () => {
    expect(isPromise(threatsApi.action('resolve', { filter: {} }))).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/threats/actions/resolve', expect.any(Object))
  })
})

// ── tagsApi ────────────────────────────────────────────────────────────────

describe('tagsApi', () => {
  beforeEach(() => vi.clearAllMocks())

  it('list returns promise', () => {
    expect(isPromise(tagsApi.list())).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/agents/tags', expect.any(Object))
  })

  it('create returns promise', () => {
    expect(isPromise(tagsApi.create({ key: 'env', value: 'prod' }))).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/tag-manager', expect.any(Object))
  })

  it('update returns promise', () => {
    expect(isPromise(tagsApi.update('tag-1', { value: 'staging' }))).toBe(true)
    expect(mockPut).toHaveBeenCalledWith('/tag-manager/tag-1', expect.any(Object))
  })

  it('delete returns promise', () => {
    expect(isPromise(tagsApi.delete('tag-1'))).toBe(true)
    expect(mockDelete).toHaveBeenCalledWith('/tag-manager/tag-1')
  })
})

// ── systemApi ────────────────────────────────────────────────────────────────

describe('systemApi', () => {
  beforeEach(() => vi.clearAllMocks())

  it('status returns promise', () => {
    expect(isPromise(systemApi.status())).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/system/status')
  })

  it('info returns promise', () => {
    expect(isPromise(systemApi.info())).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/system/info')
  })

  it('stats returns promise', () => {
    expect(isPromise(systemApi.stats())).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/_dev/stats')
  })

  it('tokens returns promise', () => {
    expect(isPromise(systemApi.tokens())).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/_dev/tokens')
  })

  it('reset returns promise', () => {
    expect(isPromise(systemApi.reset())).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/_dev/reset')
  })

  it('scenario returns promise', () => {
    expect(isPromise(systemApi.scenario('mass_infection'))).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/_dev/scenario', { scenario: 'mass_infection' })
  })

  it('listRequests returns promise', () => {
    expect(isPromise(systemApi.listRequests())).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/_dev/requests')
  })

  it('clearRequests returns promise', () => {
    expect(isPromise(systemApi.clearRequests())).toBe(true)
    expect(mockDelete).toHaveBeenCalledWith('/_dev/requests')
  })

  it('exportState returns promise', () => {
    expect(isPromise(systemApi.exportState())).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/_dev/export')
  })

  it('importState returns promise', () => {
    expect(isPromise(systemApi.importState({ agents: [] }))).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/_dev/import', expect.any(Object))
  })

  it('getRateLimit returns promise', () => {
    expect(isPromise(systemApi.getRateLimit())).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/_dev/rate-limit')
  })

  it('setRateLimit returns promise', () => {
    expect(isPromise(systemApi.setRateLimit({ enabled: true }))).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/_dev/rate-limit', expect.any(Object))
  })
})

// ── proxyApi ────────────────────────────────────────────────────────────────

describe('proxyApi', () => {
  beforeEach(() => vi.clearAllMocks())

  it('getConfig returns promise', () => {
    expect(isPromise(proxyApi.getConfig())).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/_dev/proxy/config')
  })

  it('setConfig returns promise', () => {
    expect(isPromise(proxyApi.setConfig({ mode: 'record' }))).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/_dev/proxy/config', expect.any(Object))
  })

  it('listRecordings returns promise', () => {
    expect(isPromise(proxyApi.listRecordings())).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/_dev/proxy/recordings')
  })

  it('clearRecordings returns promise', () => {
    expect(isPromise(proxyApi.clearRecordings())).toBe(true)
    expect(mockDelete).toHaveBeenCalledWith('/_dev/proxy/recordings')
  })
})

// ── webhooksApi ────────────────────────────────────────────────────────────────

describe('webhooksApi', () => {
  beforeEach(() => vi.clearAllMocks())

  it('list returns promise', () => {
    expect(isPromise(webhooksApi.list())).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/webhooks')
  })

  it('create returns promise', () => {
    expect(isPromise(webhooksApi.create({ url: 'https://example.com', event_types: ['alert'] }))).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/webhooks', expect.any(Object))
  })

  it('delete returns promise', () => {
    expect(isPromise(webhooksApi.delete('wh-1'))).toBe(true)
    expect(mockDelete).toHaveBeenCalledWith('/webhooks/wh-1')
  })

  it('fire returns promise', () => {
    expect(isPromise(webhooksApi.fire('alert', { data: 'test' }))).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/webhooks/fire', expect.any(Object))
  })
})

// ── sitesApi ────────────────────────────────────────────────────────────────

describe('sitesApi', () => {
  beforeEach(() => vi.clearAllMocks())

  it('list returns promise', () => {
    expect(isPromise(sitesApi.list())).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/sites', expect.any(Object))
  })

  it('get returns promise', () => {
    expect(isPromise(sitesApi.get('s1'))).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/sites/s1')
  })

  it('create returns promise', () => {
    expect(isPromise(sitesApi.create({ name: 'New Site' }))).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/sites', expect.any(Object))
  })

  it('update returns promise', () => {
    expect(isPromise(sitesApi.update('s1', { name: 'Updated' }))).toBe(true)
    expect(mockPut).toHaveBeenCalledWith('/sites/s1', expect.any(Object))
  })

  it('delete returns promise', () => {
    expect(isPromise(sitesApi.delete('s1'))).toBe(true)
    expect(mockDelete).toHaveBeenCalledWith('/sites/s1')
  })

  it('reactivate returns promise', () => {
    expect(isPromise(sitesApi.reactivate('s1'))).toBe(true)
    expect(mockPut).toHaveBeenCalledWith('/sites/s1/reactivate')
  })

  it('expire returns promise', () => {
    expect(isPromise(sitesApi.expire('s1'))).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/sites/s1/expire-now')
  })
})

// ── groupsApi ────────────────────────────────────────────────────────────────

describe('groupsApi', () => {
  beforeEach(() => vi.clearAllMocks())

  it('list returns promise', () => {
    expect(isPromise(groupsApi.list())).toBe(true)
  })

  it('create returns promise', () => {
    expect(isPromise(groupsApi.create({ name: 'Group A', siteId: 's1' }))).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/groups', expect.any(Object))
  })

  it('update returns promise', () => {
    expect(isPromise(groupsApi.update('g1', { name: 'Updated' }))).toBe(true)
    expect(mockPut).toHaveBeenCalledWith('/groups/g1', expect.any(Object))
  })

  it('delete returns promise', () => {
    expect(isPromise(groupsApi.delete('g1'))).toBe(true)
    expect(mockDelete).toHaveBeenCalledWith('/groups/g1')
  })
})

// ── activitiesApi ────────────────────────────────────────────────────────────

describe('activitiesApi', () => {
  beforeEach(() => vi.clearAllMocks())

  it('list returns promise', () => {
    expect(isPromise(activitiesApi.list())).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/activities', expect.any(Object))
  })
})

// ── exclusionsApi ────────────────────────────────────────────────────────────

describe('exclusionsApi', () => {
  beforeEach(() => vi.clearAllMocks())

  it('list returns promise', () => {
    expect(isPromise(exclusionsApi.list())).toBe(true)
  })

  it('create returns promise', () => {
    expect(isPromise(exclusionsApi.create({ value: '/tmp/*', type: 'path' }))).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/exclusions', expect.any(Object))
  })

  it('delete returns promise', () => {
    expect(isPromise(exclusionsApi.delete('ex-1'))).toBe(true)
    expect(mockDelete).toHaveBeenCalledWith('/exclusions/ex-1')
  })
})

// ── blocklistApi ────────────────────────────────────────────────────────────

describe('blocklistApi', () => {
  beforeEach(() => vi.clearAllMocks())

  it('list returns promise', () => {
    expect(isPromise(blocklistApi.list())).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/restrictions', expect.any(Object))
  })

  it('create returns promise', () => {
    expect(isPromise(blocklistApi.create({ value: 'abc123', type: 'black_hash' }))).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/restrictions', expect.any(Object))
  })

  it('delete returns promise', () => {
    expect(isPromise(blocklistApi.delete('bl-1'))).toBe(true)
    expect(mockDelete).toHaveBeenCalledWith('/restrictions/bl-1')
  })
})

// ── firewallApi ────────────────────────────────────────────────────────────

describe('firewallApi', () => {
  beforeEach(() => vi.clearAllMocks())

  it('list returns promise', () => {
    expect(isPromise(firewallApi.list())).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/firewall-control', expect.any(Object))
  })

  it('create returns promise', () => {
    expect(isPromise(firewallApi.create({ ruleName: 'Block Port 80' }))).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/firewall-control', expect.any(Object))
  })

  it('create with filter returns promise', () => {
    expect(isPromise(firewallApi.create({ ruleName: 'Test' }, { siteIds: ['s1'] }))).toBe(true)
  })

  it('update returns promise', () => {
    expect(isPromise(firewallApi.update('fw-1', { ruleName: 'Updated' }))).toBe(true)
    expect(mockPut).toHaveBeenCalledWith('/firewall-control', expect.any(Object))
  })

  it('delete returns promise', () => {
    expect(isPromise(firewallApi.delete('fw-1'))).toBe(true)
    expect(mockDelete).toHaveBeenCalledWith('/firewall-control', expect.any(Object))
  })
})

// ── deviceControlApi ────────────────────────────────────────────────────────

describe('deviceControlApi', () => {
  beforeEach(() => vi.clearAllMocks())

  it('list returns promise', () => {
    expect(isPromise(deviceControlApi.list())).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/device-control', expect.any(Object))
  })

  it('create returns promise', () => {
    expect(isPromise(deviceControlApi.create({ ruleName: 'Block USB' }))).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/device-control', expect.any(Object))
  })

  it('update returns promise', () => {
    expect(isPromise(deviceControlApi.update('dc-1', { ruleName: 'Updated' }))).toBe(true)
    expect(mockPut).toHaveBeenCalledWith('/device-control/dc-1', expect.any(Object))
  })

  it('delete returns promise', () => {
    expect(isPromise(deviceControlApi.delete('dc-1'))).toBe(true)
    expect(mockDelete).toHaveBeenCalledWith('/device-control', expect.any(Object))
  })
})

// ── iocsApi ────────────────────────────────────────────────────────────────

describe('iocsApi', () => {
  beforeEach(() => vi.clearAllMocks())

  it('list returns promise', () => {
    expect(isPromise(iocsApi.list())).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/threat-intelligence/iocs', expect.any(Object))
  })

  it('create returns promise', () => {
    expect(isPromise(iocsApi.create({ type: 'IPV4', value: '1.2.3.4' }))).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/threat-intelligence/iocs', expect.any(Object))
  })

  it('bulkCreate returns promise', () => {
    expect(isPromise(iocsApi.bulkCreate([{ type: 'IPV4', value: '1.2.3.4' }]))).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/threat-intelligence/iocs/bulk', expect.any(Object))
  })

  it('delete returns promise', () => {
    expect(isPromise(iocsApi.delete(['ioc-1', 'ioc-2']))).toBe(true)
    expect(mockDelete).toHaveBeenCalledWith('/threat-intelligence/iocs', expect.any(Object))
  })
})

// ── dvApi ────────────────────────────────────────────────────────────────

describe('dvApi', () => {
  beforeEach(() => vi.clearAllMocks())

  it('initQuery returns promise', () => {
    expect(isPromise(dvApi.initQuery({ query: 'EventType = "Process"' }))).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/dv/init-query', expect.any(Object))
  })

  it('queryStatus returns promise', () => {
    expect(isPromise(dvApi.queryStatus('q-1'))).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/dv/query-status', expect.any(Object))
  })

  it('events returns promise', () => {
    expect(isPromise(dvApi.events('q-1'))).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/dv/events', expect.any(Object))
  })

  it('events with params returns promise', () => {
    expect(isPromise(dvApi.events('q-1', { limit: 50 }))).toBe(true)
  })

  it('cancel returns promise', () => {
    expect(isPromise(dvApi.cancel('q-1'))).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/dv/cancel-query', { queryId: 'q-1' })
  })
})

// ── accountsApi ────────────────────────────────────────────────────────────

describe('accountsApi', () => {
  beforeEach(() => vi.clearAllMocks())

  it('list returns promise', () => {
    expect(isPromise(accountsApi.list())).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/accounts', expect.any(Object))
  })

  it('get returns promise', () => {
    expect(isPromise(accountsApi.get('acc-1'))).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/accounts/acc-1')
  })

  it('create returns promise', () => {
    expect(isPromise(accountsApi.create({ name: 'Test Corp' }))).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/accounts', expect.any(Object))
  })

  it('update returns promise', () => {
    expect(isPromise(accountsApi.update('acc-1', { name: 'Updated Corp' }))).toBe(true)
    expect(mockPut).toHaveBeenCalledWith('/accounts/acc-1', expect.any(Object))
  })
})

// ── usersApi ────────────────────────────────────────────────────────────────

describe('usersApi', () => {
  beforeEach(() => vi.clearAllMocks())

  it('list returns promise', () => {
    expect(isPromise(usersApi.list())).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/users', expect.any(Object))
  })

  it('get returns promise', () => {
    expect(isPromise(usersApi.get('u1'))).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/users/u1')
  })

  it('create returns promise', () => {
    expect(isPromise(usersApi.create({ email: 'a@b.com', role: 'admin' }))).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/users', expect.any(Object))
  })

  it('update returns promise', () => {
    expect(isPromise(usersApi.update('u1', { fullName: 'Alice' }))).toBe(true)
    expect(mockPut).toHaveBeenCalledWith('/users/u1', expect.any(Object))
  })

  it('delete returns promise', () => {
    expect(isPromise(usersApi.delete('u1'))).toBe(true)
    expect(mockDelete).toHaveBeenCalledWith('/users/u1')
  })

  it('bulkDelete returns promise', () => {
    expect(isPromise(usersApi.bulkDelete(['u1', 'u2']))).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/users/delete-users', expect.any(Object))
  })

  it('generateApiToken returns promise', () => {
    expect(isPromise(usersApi.generateApiToken())).toBe(true)
    expect(mockPost).toHaveBeenCalledWith('/users/generate-api-token')
  })

  it('getApiTokenDetails returns promise', () => {
    expect(isPromise(usersApi.getApiTokenDetails('u1'))).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/users/u1/api-token-details')
  })

  it('loginByToken returns promise', () => {
    expect(isPromise(usersApi.loginByToken())).toBe(true)
    expect(mockGet).toHaveBeenCalledWith('/users/login/by-token')
  })
})

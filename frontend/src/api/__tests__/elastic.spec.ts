import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('axios', () => {
  const mockClient = {
    get: vi.fn().mockResolvedValue({ data: [], total: 0 }),
    post: vi.fn().mockResolvedValue({}),
    put: vi.fn().mockResolvedValue({}),
    patch: vi.fn().mockResolvedValue([]),
    delete: vi.fn().mockResolvedValue(undefined),
    interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
    headers: {},
  }
  return {
    default: {
      create: vi.fn(() => mockClient),
      isAxiosError: vi.fn().mockReturnValue(false),
    },
  }
})

import {
  esSearchApi,
  esEndpointsApi,
  esRulesApi,
  esAlertsApi,
  esCasesApi,
  esExceptionListsApi,
} from '@/api/elastic'

describe('elastic API', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('esSearchApi.search returns promise', async () => {
    expect(esSearchApi.search('logs-*', { query: { match_all: {} } })).toBeInstanceOf(Promise)
  })

  it('esSearchApi.clusterInfo returns promise', async () => {
    expect(esSearchApi.clusterInfo()).toBeInstanceOf(Promise)
  })

  it('esEndpointsApi.list returns promise', async () => {
    expect(esEndpointsApi.list()).toBeInstanceOf(Promise)
  })

  it('esEndpointsApi.get returns promise', async () => {
    expect(esEndpointsApi.get('ep-id')).toBeInstanceOf(Promise)
  })

  it('esEndpointsApi.isolate returns promise', async () => {
    expect(esEndpointsApi.isolate(['ep-id'], 'isolate comment')).toBeInstanceOf(Promise)
  })

  it('esEndpointsApi.unisolate returns promise', async () => {
    expect(esEndpointsApi.unisolate(['ep-id'], 'unisolate comment')).toBeInstanceOf(Promise)
  })

  it('esRulesApi.find returns promise', async () => {
    expect(esRulesApi.find()).toBeInstanceOf(Promise)
  })

  it('esRulesApi.get returns promise', async () => {
    expect(esRulesApi.get('rule-id')).toBeInstanceOf(Promise)
  })

  it('esRulesApi.create returns promise', async () => {
    expect(esRulesApi.create({ name: 'Test Rule', type: 'query' })).toBeInstanceOf(Promise)
  })

  it('esRulesApi.update returns promise', async () => {
    expect(esRulesApi.update({ id: 'rule-id', name: 'Updated' })).toBeInstanceOf(Promise)
  })

  it('esRulesApi.delete returns promise', async () => {
    expect(esRulesApi.delete('rule-id')).toBeInstanceOf(Promise)
  })

  it('esRulesApi.tags returns promise', async () => {
    expect(esRulesApi.tags()).toBeInstanceOf(Promise)
  })

  it('esRulesApi.bulkAction returns promise', async () => {
    expect(esRulesApi.bulkAction({ action: 'enable', ids: ['rule-id'] })).toBeInstanceOf(Promise)
  })

  it('esAlertsApi.search returns promise', async () => {
    expect(esAlertsApi.search({ query: { match_all: {} } })).toBeInstanceOf(Promise)
  })

  it('esAlertsApi.updateStatus returns promise', async () => {
    expect(esAlertsApi.updateStatus({ status: 'closed', id: [] })).toBeInstanceOf(Promise)
  })

  it('esAlertsApi.updateTags returns promise', async () => {
    expect(esAlertsApi.updateTags({ tags: { add: [], remove: [] } })).toBeInstanceOf(Promise)
  })

  it('esCasesApi.find returns promise', async () => {
    expect(esCasesApi.find()).toBeInstanceOf(Promise)
  })

  it('esCasesApi.get returns promise', async () => {
    expect(esCasesApi.get('case-id')).toBeInstanceOf(Promise)
  })

  it('esCasesApi.create returns promise', async () => {
    expect(esCasesApi.create({ title: 'Test', description: 'Test' })).toBeInstanceOf(Promise)
  })

  it('esCasesApi.update returns promise', async () => {
    expect(esCasesApi.update({ cases: [{ id: 'case-id', version: 'v1', status: 'open' }] })).toBeInstanceOf(Promise)
  })

  it('esCasesApi.delete returns promise', async () => {
    expect(esCasesApi.delete(['case-id'])).toBeInstanceOf(Promise)
  })

  it('esCasesApi.addComment returns promise', async () => {
    expect(esCasesApi.addComment('case-id', { comment: 'Test', type: 'user', owner: 'securitySolution' })).toBeInstanceOf(Promise)
  })

  it('esCasesApi.getComments returns promise', async () => {
    expect(esCasesApi.getComments('case-id')).toBeInstanceOf(Promise)
  })

  it('esExceptionListsApi.findLists returns promise', async () => {
    expect(esExceptionListsApi.findLists()).toBeInstanceOf(Promise)
  })

  it('esExceptionListsApi.findItems returns promise', async () => {
    expect(esExceptionListsApi.findItems()).toBeInstanceOf(Promise)
  })

  it('esExceptionListsApi.createList returns promise', async () => {
    expect(esExceptionListsApi.createList({ name: 'Test', namespace_type: 'single', type: 'detection' })).toBeInstanceOf(Promise)
  })

  it('esExceptionListsApi.deleteList returns promise', async () => {
    expect(esExceptionListsApi.deleteList('list-id', 'single')).toBeInstanceOf(Promise)
  })

  it('esExceptionListsApi.createItem returns promise', async () => {
    expect(esExceptionListsApi.createItem({ list_id: 'list-id', type: 'simple', name: 'test' })).toBeInstanceOf(Promise)
  })

  it('esExceptionListsApi.deleteItem returns promise', async () => {
    expect(esExceptionListsApi.deleteItem('item-id', 'single')).toBeInstanceOf(Promise)
  })
})

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useThreatsStore } from '../threats'
import type { ThreatRecord } from '../../types'

vi.mock('../../api/threats', () => ({
  threatsApi: {
    list: vi.fn(),
    action: vi.fn(),
  },
}))

import { threatsApi } from '../../api/threats'

function makeThreat(id: string, overrides: Partial<ThreatRecord> = {}): ThreatRecord {
  return {
    id,
    threatInfo: {
      threatName: `Threat-${id}`,
      classification: 'Malware',
      mitigationStatus: 'active',
      incidentStatus: 'unresolved',
      analystVerdict: 'undefined',
      sha1: 'abc123',
      createdAt: '2024-01-01T00:00:00.000Z',
      filePath: '/tmp/malware.exe',
      confidenceLevel: 'malicious',
      resolved: false,
    },
    agentDetectionInfo: { agentComputerName: `HOST-${id}` },
    agentRealtimeInfo: {},
    indicators: [],
    mitigationStatus: [],
    whiteningOptions: [],
    ...overrides,
  } as ThreatRecord
}

const PAGE_1 = [makeThreat('t1'), makeThreat('t2')]
const mockListPage1 = {
  data: PAGE_1,
  pagination: { totalItems: 4, nextCursor: 'cursor-p2' },
}
const mockListPage2 = {
  data: [makeThreat('t3'), makeThreat('t4')],
  pagination: { totalItems: 4, nextCursor: null },
}

describe('useThreatsStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
  })

  describe('initial state', () => {
    it('items is empty', () => {
      expect(useThreatsStore().items).toHaveLength(0)
    })

    it('loading is false', () => {
      expect(useThreatsStore().loading).toBe(false)
    })

    it('selected is empty', () => {
      expect(useThreatsStore().selected).toHaveLength(0)
    })
  })

  describe('fetchList()', () => {
    it('populates items from API response', async () => {
      vi.mocked(threatsApi.list).mockResolvedValueOnce(mockListPage1 as never)
      const store = useThreatsStore()
      await store.fetchList()
      expect(store.items).toHaveLength(2)
      expect(store.items[0].id).toBe('t1')
    })

    it('sets total from pagination', async () => {
      vi.mocked(threatsApi.list).mockResolvedValueOnce(mockListPage1 as never)
      const store = useThreatsStore()
      await store.fetchList()
      expect(store.total).toBe(4)
    })

    it('sets nextCursor when more pages exist', async () => {
      vi.mocked(threatsApi.list).mockResolvedValueOnce(mockListPage1 as never)
      const store = useThreatsStore()
      await store.fetchList()
      expect(store.nextCursor).toBe('cursor-p2')
    })

    it('replaces items on reset=true (default)', async () => {
      vi.mocked(threatsApi.list).mockResolvedValue(mockListPage1 as never)
      const store = useThreatsStore()
      await store.fetchList()
      await store.fetchList()
      expect(store.items).toHaveLength(2)
    })

    it('appends items on reset=false (load more)', async () => {
      vi.mocked(threatsApi.list)
        .mockResolvedValueOnce(mockListPage1 as never)
        .mockResolvedValueOnce(mockListPage2 as never)
      const store = useThreatsStore()
      await store.fetchList(true)
      await store.fetchList(false)
      expect(store.items).toHaveLength(4)
    })

    it('sets loading=false after success', async () => {
      vi.mocked(threatsApi.list).mockResolvedValueOnce(mockListPage1 as never)
      const store = useThreatsStore()
      await store.fetchList()
      expect(store.loading).toBe(false)
    })

    it('sets loading=false even after API error', async () => {
      vi.mocked(threatsApi.list).mockRejectedValueOnce(new Error('network'))
      const store = useThreatsStore()
      await store.fetchList().catch(() => undefined)
      expect(store.loading).toBe(false)
    })
  })

  describe('toggleSelect()', () => {
    it('adds a threat to selected', () => {
      const store = useThreatsStore()
      const threat = makeThreat('sel1')
      store.toggleSelect(threat)
      expect(store.selected).toHaveLength(1)
    })

    it('removes an already-selected threat', () => {
      const store = useThreatsStore()
      const threat = makeThreat('sel1')
      store.toggleSelect(threat)
      store.toggleSelect(threat)
      expect(store.selected).toHaveLength(0)
    })

    it('identifies selected threat correctly', () => {
      const store = useThreatsStore()
      const t = makeThreat('sel1')
      store.toggleSelect(t)
      expect(store.selected.some((s) => s.id === t.id)).toBe(true)
    })
  })

  describe('performAction()', () => {
    it('calls threatsApi.action with the selected threat ids', async () => {
      vi.mocked(threatsApi.action).mockResolvedValueOnce({ data: { affected: 1 } } as never)
      vi.mocked(threatsApi.list).mockResolvedValueOnce(mockListPage1 as never)

      const store = useThreatsStore()
      const threat = makeThreat('t99')
      store.toggleSelect(threat)

      await store.performAction('resolve')

      expect(threatsApi.action).toHaveBeenCalledWith('resolve', {
        filter: { ids: ['t99'] },
      })
    })

    it('clears selection after action', async () => {
      vi.mocked(threatsApi.action).mockResolvedValueOnce({ data: { affected: 1 } } as never)
      vi.mocked(threatsApi.list).mockResolvedValueOnce(mockListPage1 as never)

      const store = useThreatsStore()
      store.toggleSelect(makeThreat('t99'))
      await store.performAction('mark-as-benign')

      expect(store.selected).toHaveLength(0)
    })

    it('refreshes list after action', async () => {
      vi.mocked(threatsApi.action).mockResolvedValueOnce({ data: { affected: 1 } } as never)
      vi.mocked(threatsApi.list).mockResolvedValueOnce(mockListPage1 as never)

      const store = useThreatsStore()
      store.toggleSelect(makeThreat('t99'))
      await store.performAction('mark-as-threat')

      expect(threatsApi.list).toHaveBeenCalledOnce()
    })
  })
})

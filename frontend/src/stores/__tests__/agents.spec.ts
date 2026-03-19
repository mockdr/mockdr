import { describe, it, expect, beforeEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useAgentsStore } from '@/stores/agents'
import type { Agent } from '@/types'

vi.mock('../../api/agents', () => ({
  agentsApi: {
    list: vi.fn(),
    action: vi.fn(),
  },
}))

import { agentsApi } from '@/api/agents'

// Minimal Agent stub — only fields used by the store logic
function makeAgent(id: string, overrides: Partial<Agent> = {}): Agent {
  return {
    id,
    uuid: `uuid-${id}`,
    computerName: `HOST-${id}`,
    osType: 'windows',
    networkStatus: 'connected',
    infected: false,
    isActive: true,
    ...overrides,
  } as Agent
}

const PAGE_1 = [makeAgent('a1'), makeAgent('a2'), makeAgent('a3')]
const PAGE_2 = [makeAgent('a4'), makeAgent('a5')]

const mockListPage1 = {
  data: PAGE_1,
  pagination: { totalItems: 5, nextCursor: 'cursor-page-2' },
}
const mockListPage2 = {
  data: PAGE_2,
  pagination: { totalItems: 5, nextCursor: null },
}

describe('useAgentsStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
  })

  describe('initial state', () => {
    it('items is empty', () => {
      expect(useAgentsStore().items).toHaveLength(0)
    })

    it('loading is false', () => {
      expect(useAgentsStore().loading).toBe(false)
    })

    it('selected is empty', () => {
      expect(useAgentsStore().selected).toHaveLength(0)
    })

    it('nextCursor is null', () => {
      expect(useAgentsStore().nextCursor).toBeNull()
    })
  })

  describe('fetchList()', () => {
    it('populates items from API response', async () => {
      vi.mocked(agentsApi.list).mockResolvedValueOnce(mockListPage1 as never)
      const store = useAgentsStore()
      await store.fetchList()
      expect(store.items).toHaveLength(3)
      expect(store.items[0].id).toBe('a1')
    })

    it('sets total from pagination', async () => {
      vi.mocked(agentsApi.list).mockResolvedValueOnce(mockListPage1 as never)
      const store = useAgentsStore()
      await store.fetchList()
      expect(store.total).toBe(5)
    })

    it('sets nextCursor when more pages exist', async () => {
      vi.mocked(agentsApi.list).mockResolvedValueOnce(mockListPage1 as never)
      const store = useAgentsStore()
      await store.fetchList()
      expect(store.nextCursor).toBe('cursor-page-2')
    })

    it('resets items on reset=true (default)', async () => {
      vi.mocked(agentsApi.list).mockResolvedValue(mockListPage1 as never)
      const store = useAgentsStore()
      await store.fetchList()
      await store.fetchList() // second call replaces
      expect(store.items).toHaveLength(3)
    })

    it('appends items on reset=false (load more)', async () => {
      vi.mocked(agentsApi.list)
        .mockResolvedValueOnce(mockListPage1 as never)
        .mockResolvedValueOnce(mockListPage2 as never)
      const store = useAgentsStore()
      await store.fetchList(true)
      await store.fetchList(false)
      expect(store.items).toHaveLength(5)
    })

    it('sets loading=false after success', async () => {
      vi.mocked(agentsApi.list).mockResolvedValueOnce(mockListPage1 as never)
      const store = useAgentsStore()
      await store.fetchList()
      expect(store.loading).toBe(false)
    })

    it('sets loading=false even after API error', async () => {
      vi.mocked(agentsApi.list).mockRejectedValueOnce(new Error('network'))
      const store = useAgentsStore()
      await store.fetchList().catch(() => undefined)
      expect(store.loading).toBe(false)
    })
  })

  describe('selection management', () => {
    it('toggleSelect adds an agent to selected', () => {
      const store = useAgentsStore()
      const agent = makeAgent('x1')
      store.toggleSelect(agent)
      expect(store.selected).toHaveLength(1)
      expect(store.isSelected(agent)).toBe(true)
    })

    it('toggleSelect removes an already-selected agent', () => {
      const store = useAgentsStore()
      const agent = makeAgent('x1')
      store.toggleSelect(agent)
      store.toggleSelect(agent)
      expect(store.selected).toHaveLength(0)
    })

    it('isSelected returns false for unselected agent', () => {
      const store = useAgentsStore()
      expect(store.isSelected(makeAgent('z1'))).toBe(false)
    })

    it('clearSelection empties the selected array', () => {
      const store = useAgentsStore()
      store.toggleSelect(makeAgent('x1'))
      store.toggleSelect(makeAgent('x2'))
      store.clearSelection()
      expect(store.selected).toHaveLength(0)
    })
  })

  describe('performAction()', () => {
    it('calls agentsApi.action with correct action and ids', async () => {
      vi.mocked(agentsApi.action).mockResolvedValueOnce({ data: { affected: 1 } } as never)
      vi.mocked(agentsApi.list).mockResolvedValueOnce(mockListPage1 as never)

      const store = useAgentsStore()
      const agent = makeAgent('sel1')
      store.toggleSelect(agent)

      await store.performAction('disconnect')

      expect(agentsApi.action).toHaveBeenCalledWith('disconnect', {
        filter: { ids: ['sel1'] },
      })
    })

    it('clears selection after action', async () => {
      vi.mocked(agentsApi.action).mockResolvedValueOnce({ data: { affected: 1 } } as never)
      vi.mocked(agentsApi.list).mockResolvedValueOnce(mockListPage1 as never)

      const store = useAgentsStore()
      store.toggleSelect(makeAgent('sel1'))
      await store.performAction('connect')

      expect(store.selected).toHaveLength(0)
    })

    it('refreshes list after action', async () => {
      vi.mocked(agentsApi.action).mockResolvedValueOnce({ data: { affected: 1 } } as never)
      vi.mocked(agentsApi.list).mockResolvedValueOnce(mockListPage1 as never)

      const store = useAgentsStore()
      store.toggleSelect(makeAgent('sel1'))
      await store.performAction('initiate-scan')

      expect(agentsApi.list).toHaveBeenCalledOnce()
    })
  })
})

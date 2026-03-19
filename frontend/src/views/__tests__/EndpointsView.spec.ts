import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { flushPromises } from '@vue/test-utils'
import EndpointsView from '@/views/EndpointsView.vue'

const mockFetchList = vi.hoisted(() => vi.fn())
const mockIsSelected = vi.hoisted(() => vi.fn())
const mockToggleSelect = vi.hoisted(() => vi.fn())
const mockClearSelection = vi.hoisted(() => vi.fn())
const mockPerformAction = vi.hoisted(() => vi.fn())

const mockRouter = vi.hoisted(() => ({ push: vi.fn() }))

vi.mock('vue-router', () => ({
  useRouter: vi.fn(() => mockRouter),
  RouterLink: { template: '<a><slot /></a>' },
}))

const mockItems = [
  { id: 'a1', computerName: 'WKSTN-001', osType: 'windows', networkStatus: 'connected', infected: false, isActive: true, agentVersion: '23.1', groupName: 'Workstations', lastActiveDate: '2025-06-01T00:00:00Z', lastIpToMgmt: '10.0.0.1', externalIp: '203.0.113.1', osName: 'Windows 10' },
  { id: 'a2', computerName: 'MAC-001', osType: 'macos', networkStatus: 'disconnected', infected: false, isActive: false, agentVersion: '23.1', groupName: 'Macs', lastActiveDate: '2025-05-01T00:00:00Z', lastIpToMgmt: '10.0.0.2', externalIp: '203.0.113.2', osName: 'macOS 14' },
]

let mockSelected: typeof mockItems = []
let mockNextCursor: string | null = null

vi.mock('../../stores/agents', () => ({
  useAgentsStore: vi.fn(() => ({
    items: mockItems,
    total: 42,
    loading: false,
    get selected() { return mockSelected },
    fetchList: mockFetchList,
    isSelected: mockIsSelected,
    toggleSelect: mockToggleSelect,
    clearSelection: mockClearSelection,
    performAction: mockPerformAction,
    filters: { query: '', osTypes: '', networkStatuses: '' },
    get nextCursor() { return mockNextCursor },
  })),
}))

vi.mock('../../utils/formatters', () => ({
  relativeTime: vi.fn((v) => v ?? ''),
}))

const stubs = { LoadingSkeleton: true, EmptyState: true, StatusBadge: true, OsIcon: true }

describe('EndpointsView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockIsSelected.mockReturnValue(false)
    mockRouter.push.mockReset()
    mockSelected = []
    mockNextCursor = null
  })

  it('renders without error', () => {
    const w = mount(EndpointsView, { global: { stubs } })
    expect(w.exists()).toBe(true)
  })

  it('renders the Endpoints heading', () => {
    const w = mount(EndpointsView, { global: { stubs } })
    expect(w.text()).toContain('Endpoints')
  })

  it('renders the total agent count', () => {
    const w = mount(EndpointsView, { global: { stubs } })
    expect(w.text()).toContain('42')
  })

  it('calls fetchList on mount', () => {
    mount(EndpointsView, { global: { stubs } })
    expect(mockFetchList).toHaveBeenCalledOnce()
  })

  it('allSelected is false when no items are selected', () => {
    mockIsSelected.mockReturnValue(false)
    const w = mount(EndpointsView, { global: { stubs } })
    expect((w.vm as any).allSelected).toBe(false)
  })

  it('allSelected is true when all items are selected', () => {
    mockIsSelected.mockReturnValue(true)
    const w = mount(EndpointsView, { global: { stubs } })
    expect((w.vm as any).allSelected).toBe(true)
  })

  it('toggleAll calls clearSelection when allSelected is true', () => {
    mockIsSelected.mockReturnValue(true)
    const w = mount(EndpointsView, { global: { stubs } })
    ;(w.vm as any).toggleAll()
    expect(mockClearSelection).toHaveBeenCalled()
  })

  it('toggleAll calls toggleSelect for each unselected item when allSelected is false', () => {
    mockIsSelected.mockReturnValue(false)
    const w = mount(EndpointsView, { global: { stubs } })
    ;(w.vm as any).toggleAll()
    expect(mockToggleSelect).toHaveBeenCalledTimes(2)
  })

  it('toggleAll does not call toggleSelect for already-selected items', () => {
    mockIsSelected.mockImplementation((item) => item.id === 'a1')
    const w = mount(EndpointsView, { global: { stubs } })
    ;(w.vm as any).toggleAll()
    expect(mockToggleSelect).toHaveBeenCalledTimes(1)
  })

  it('Refresh button triggers store.fetchList', async () => {
    const w = mount(EndpointsView, { global: { stubs } })
    mockFetchList.mockClear()
    const btn = w.find('button')
    await btn.trigger('click')
    expect(mockFetchList).toHaveBeenCalled()
  })

  it('table row click navigates to endpoint detail', async () => {
    const w = mount(EndpointsView, { global: { stubs } })
    const rows = w.findAll('tr')
    // First tr is header, second is first data row
    const dataRow = rows.find(r => r.text().includes('WKSTN-001'))
    if (dataRow) {
      await dataRow.trigger('click')
      expect(mockRouter.push).toHaveBeenCalledWith('/endpoints/a1')
    }
  })

  it('row checkbox change triggers store.toggleSelect', async () => {
    const w = mount(EndpointsView, { global: { stubs } })
    const checkboxes = w.findAll('input[type="checkbox"]')
    // Second checkbox is the first row checkbox (first is header all-select)
    if (checkboxes.length > 1) {
      await checkboxes[1].trigger('change')
      expect(mockToggleSelect).toHaveBeenCalled()
    }
  })

  it('renders agent computer names', () => {
    const w = mount(EndpointsView, { global: { stubs } })
    expect(w.text()).toContain('WKSTN-001')
    expect(w.text()).toContain('MAC-001')
  })

  it('header checkbox DOM change triggers toggleAll (allSelected false → toggleSelect each)', async () => {
    mockIsSelected.mockReturnValue(false)
    const w = mount(EndpointsView, { global: { stubs } })
    await flushPromises()
    const checkboxes = w.findAll('input[type="checkbox"]')
    // First checkbox is the header select-all checkbox
    await checkboxes[0].trigger('change')
    await flushPromises()
    expect(mockToggleSelect).toHaveBeenCalledTimes(2)
  })

  it('header checkbox DOM change triggers toggleAll (allSelected true → clearSelection)', async () => {
    mockIsSelected.mockReturnValue(true)
    const w = mount(EndpointsView, { global: { stubs } })
    await flushPromises()
    const checkboxes = w.findAll('input[type="checkbox"]')
    await checkboxes[0].trigger('change')
    await flushPromises()
    expect(mockClearSelection).toHaveBeenCalled()
  })

  it('Isolate button triggers store.performAction("disconnect") via DOM click', async () => {
    mockSelected = [mockItems[0]]
    const w = mount(EndpointsView, { global: { stubs } })
    await flushPromises()
    const btn = w.findAll('button').find(b => b.text().includes('Isolate'))
    expect(btn).toBeDefined()
    await btn!.trigger('click')
    await flushPromises()
    expect(mockPerformAction).toHaveBeenCalledWith('disconnect')
  })

  it('Reconnect button triggers store.performAction("connect") via DOM click', async () => {
    mockSelected = [mockItems[0]]
    const w = mount(EndpointsView, { global: { stubs } })
    await flushPromises()
    const btn = w.findAll('button').find(b => b.text().includes('Reconnect'))
    expect(btn).toBeDefined()
    await btn!.trigger('click')
    await flushPromises()
    expect(mockPerformAction).toHaveBeenCalledWith('connect')
  })

  it('Scan button triggers store.performAction("initiate-scan") via DOM click', async () => {
    mockSelected = [mockItems[0]]
    const w = mount(EndpointsView, { global: { stubs } })
    await flushPromises()
    const btn = w.findAll('button').find(b => b.text().includes('Scan'))
    expect(btn).toBeDefined()
    await btn!.trigger('click')
    await flushPromises()
    expect(mockPerformAction).toHaveBeenCalledWith('initiate-scan')
  })

  it('Decommission button triggers store.performAction("decommission") via DOM click', async () => {
    mockSelected = [mockItems[0]]
    const w = mount(EndpointsView, { global: { stubs } })
    await flushPromises()
    const btn = w.findAll('button').find(b => b.text().includes('Decommission'))
    expect(btn).toBeDefined()
    await btn!.trigger('click')
    await flushPromises()
    expect(mockPerformAction).toHaveBeenCalledWith('decommission')
  })

  it('Load more button triggers store.fetchList(false) via DOM click', async () => {
    mockNextCursor = 'cursor-abc'
    const w = mount(EndpointsView, { global: { stubs } })
    await flushPromises()
    mockFetchList.mockClear()
    const btn = w.findAll('button').find(b => b.text().includes('Load more'))
    expect(btn).toBeDefined()
    await btn!.trigger('click')
    await flushPromises()
    expect(mockFetchList).toHaveBeenCalledWith(false)
  })
})

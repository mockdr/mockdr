import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount } from '@vue/test-utils'
import EndpointsView from '../EndpointsView.vue'

const mockFetchList = vi.hoisted(() => vi.fn())

vi.mock('vue-router', () => ({
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
}))

vi.mock('../../stores/agents', () => ({
  useAgentsStore: vi.fn(() => ({
    items: [],
    total: 42,
    loading: false,
    selected: [],
    fetchList: mockFetchList,
    isSelected: vi.fn(() => false),
    toggleSelect: vi.fn(),
    clearSelection: vi.fn(),
    performAction: vi.fn(),
    filters: {},
    nextCursor: null,
  })),
}))

describe('EndpointsView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders without error', () => {
    const w = shallowMount(EndpointsView)
    expect(w.exists()).toBe(true)
  })

  it('renders the Endpoints heading', () => {
    const w = shallowMount(EndpointsView)
    expect(w.text()).toContain('Endpoints')
  })

  it('renders the total agent count', () => {
    const w = shallowMount(EndpointsView)
    expect(w.text()).toContain('42')
  })

  it('calls fetchList on mount', () => {
    shallowMount(EndpointsView)
    expect(mockFetchList).toHaveBeenCalledOnce()
  })
})

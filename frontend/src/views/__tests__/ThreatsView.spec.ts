import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount } from '@vue/test-utils'
import ThreatsView from '../ThreatsView.vue'

const mockFetchList = vi.hoisted(() => vi.fn())

vi.mock('vue-router', () => ({
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
}))

vi.mock('../../stores/threats', () => ({
  useThreatsStore: vi.fn(() => ({
    items: [],
    total: 17,
    loading: false,
    selected: [],
    fetchList: mockFetchList,
    filters: {
      query: '',
      classifications: '',
      mitigationStatuses: '',
      incidentStatuses: '',
    },
    nextCursor: null,
  })),
}))

describe('ThreatsView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders without error', () => {
    const w = shallowMount(ThreatsView)
    expect(w.exists()).toBe(true)
  })

  it('renders the Threats heading', () => {
    const w = shallowMount(ThreatsView)
    expect(w.text()).toContain('Threats')
  })

  it('renders the total threat count', () => {
    const w = shallowMount(ThreatsView)
    expect(w.text()).toContain('17')
  })

  it('calls fetchList on mount', () => {
    shallowMount(ThreatsView)
    expect(mockFetchList).toHaveBeenCalledOnce()
  })
})

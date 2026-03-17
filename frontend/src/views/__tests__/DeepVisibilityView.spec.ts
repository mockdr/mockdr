import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount, flushPromises } from '@vue/test-utils'
import DeepVisibilityView from '../DeepVisibilityView.vue'

vi.mock('vue-router', () => ({
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
}))

vi.mock('../../api/misc', () => ({
  dvApi: {
    initQuery: vi.fn(),
    queryStatus: vi.fn(),
    events: vi.fn(),
    cancel: vi.fn(),
  },
  sitesApi: { list: vi.fn() },
  groupsApi: { list: vi.fn() },
  accountsApi: { list: vi.fn() },
  activitiesApi: { list: vi.fn() },
  exclusionsApi: { list: vi.fn() },
  blocklistApi: { list: vi.fn() },
  firewallApi: { list: vi.fn() },
  deviceControlApi: { list: vi.fn() },
  iocsApi: { list: vi.fn() },
  usersApi: { list: vi.fn() },
}))

describe('DeepVisibilityView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders without error', () => {
    const w = shallowMount(DeepVisibilityView)
    expect(w.exists()).toBe(true)
  })

  it('renders the Deep Visibility heading', () => {
    const w = shallowMount(DeepVisibilityView)
    expect(w.text()).toContain('Deep Visibility')
  })

  it('renders query textarea', () => {
    const w = shallowMount(DeepVisibilityView)
    expect(w.find('textarea').exists()).toBe(true)
  })

  it('shows empty state when no events', () => {
    const w = shallowMount(DeepVisibilityView)
    expect(w.text()).toContain('Enter a query')
  })

  it('renders Run Query button', () => {
    const w = shallowMount(DeepVisibilityView)
    expect(w.text()).toContain('Run Query')
  })
})

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount } from '@vue/test-utils'
import { setActivePinia, createPinia } from 'pinia'
import AppLayout from '../layout/AppLayout.vue'

// Stub all child components that have their own complex setup
vi.mock('vue-router', () => ({
  useRoute: vi.fn(() => ({ path: '/' })),
  useRouter: vi.fn(() => ({ push: vi.fn(), go: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
  RouterView: { template: '<div />' },
}))

vi.mock('../../api/alerts', () => ({
  alertsApi: {
    list: vi.fn().mockResolvedValue({ data: [], pagination: { totalItems: 0, nextCursor: null } }),
  },
}))

vi.mock('../../api/system', () => ({
  systemApi: {
    stats: vi.fn().mockResolvedValue({ data: {} }),
    reset: vi.fn().mockResolvedValue({ data: {} }),
    scenario: vi.fn().mockResolvedValue({ data: {} }),
  },
}))

describe('AppLayout', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  it('renders without error', () => {
    const w = shallowMount(AppLayout)
    expect(w.exists()).toBe(true)
  })

  it('renders a root div container', () => {
    const w = shallowMount(AppLayout)
    expect(w.find('div').exists()).toBe(true)
  })
})

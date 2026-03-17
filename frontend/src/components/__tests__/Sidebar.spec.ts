import { describe, it, expect, vi } from 'vitest'
import { shallowMount } from '@vue/test-utils'
import Sidebar from '../layout/Sidebar.vue'

vi.mock('vue-router', () => ({
  useRoute: vi.fn(() => ({ path: '/endpoints' })),
  RouterLink: { template: '<a><slot /></a>' },
}))

describe('Sidebar', () => {
  it('renders without error', () => {
    const w = shallowMount(Sidebar)
    expect(w.exists()).toBe(true)
  })

  it('renders the mockdr brand name', () => {
    const w = shallowMount(Sidebar)
    expect(w.text()).toContain('mockdr')
  })

  it('renders the Dashboard nav link', () => {
    const w = shallowMount(Sidebar)
    expect(w.text()).toContain('Dashboard')
  })

  it('renders the Endpoints nav link', () => {
    const w = shallowMount(Sidebar)
    expect(w.text()).toContain('Endpoints')
  })

  it('renders the Threats nav link', () => {
    const w = shallowMount(Sidebar)
    expect(w.text()).toContain('Threats')
  })

  it('renders the Users nav link', () => {
    const w = shallowMount(Sidebar)
    expect(w.text()).toContain('Users')
  })

  it('renders the Playbooks nav link', () => {
    const w = shallowMount(Sidebar)
    expect(w.text()).toContain('Playbooks')
  })

  it('renders POLICY section divider', () => {
    const w = shallowMount(Sidebar)
    expect(w.text()).toContain('POLICY')
  })

  it('renders DEV TOOLS section divider', () => {
    const w = shallowMount(Sidebar)
    expect(w.text()).toContain('DEV TOOLS')
  })
})

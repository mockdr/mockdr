import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount, flushPromises } from '@vue/test-utils'
import ExclusionsView from '../ExclusionsView.vue'

const mockExclusionsList = vi.hoisted(() => vi.fn())
const mockExclusionsCreate = vi.hoisted(() => vi.fn())
const mockExclusionsDelete = vi.hoisted(() => vi.fn())

vi.mock('vue-router', () => ({
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
}))

vi.mock('../../api/misc', () => ({
  exclusionsApi: {
    list: mockExclusionsList,
    create: mockExclusionsCreate,
    delete: mockExclusionsDelete,
  },
}))

const FAKE_EXCLUSIONS = [
  { id: 'e1', value: 'C:\\Windows\\Temp\\*', type: 'path', osType: 'windows', mode: 'suppress', createdAt: '2025-04-01T00:00:00Z' },
  { id: 'e2', value: '/opt/app/logs', type: 'path', osType: 'linux', mode: 'suppress', createdAt: '2025-04-02T00:00:00Z' },
]

describe('ExclusionsView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockExclusionsList.mockResolvedValue({
      data: FAKE_EXCLUSIONS,
      pagination: { totalItems: 2 },
    })
  })

  it('renders without error', async () => {
    const w = shallowMount(ExclusionsView)
    await flushPromises()
    expect(w.exists()).toBe(true)
  })

  it('renders the Exclusions heading', async () => {
    const w = shallowMount(ExclusionsView)
    await flushPromises()
    expect(w.text()).toContain('Exclusions')
  })

  it('calls exclusionsApi.list on mount', async () => {
    shallowMount(ExclusionsView)
    await flushPromises()
    expect(mockExclusionsList).toHaveBeenCalledOnce()
  })

  it('renders exclusion values after load', async () => {
    const w = shallowMount(ExclusionsView)
    await flushPromises()
    expect(w.text()).toContain('C:\\Windows\\Temp\\*')
    expect(w.text()).toContain('/opt/app/logs')
  })

  it('renders total exclusions count', async () => {
    const w = shallowMount(ExclusionsView)
    await flushPromises()
    expect(w.text()).toContain('2')
  })

  it('renders Add Exclusion button', async () => {
    const w = shallowMount(ExclusionsView)
    await flushPromises()
    expect(w.text()).toContain('Add Exclusion')
  })

  it('shows add form when Add Exclusion is clicked', async () => {
    const w = shallowMount(ExclusionsView)
    await flushPromises()
    expect(w.find('select').exists()).toBe(false)
    await w.find('.btn-primary').trigger('click')
    // The add form has select elements for Type and OS
    expect(w.findAll('select').length).toBeGreaterThanOrEqual(2)
  })
})

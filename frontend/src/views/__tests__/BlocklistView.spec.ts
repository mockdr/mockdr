import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount, flushPromises } from '@vue/test-utils'
import BlocklistView from '../BlocklistView.vue'

const mockBlocklistList = vi.hoisted(() => vi.fn())
const mockBlocklistCreate = vi.hoisted(() => vi.fn())
const mockBlocklistDelete = vi.hoisted(() => vi.fn())

vi.mock('vue-router', () => ({
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
}))

vi.mock('../../api/misc', () => ({
  blocklistApi: {
    list: mockBlocklistList,
    create: mockBlocklistCreate,
    delete: mockBlocklistDelete,
  },
}))

const FAKE_ENTRIES = [
  { id: 'b1', value: 'abc123def456', type: 'black_hash', osType: 'windows', description: 'Known malware', createdAt: '2025-05-01T00:00:00Z' },
  { id: 'b2', value: '789xyz000111', type: 'black_hash', osType: 'linux', description: '', createdAt: '2025-05-02T00:00:00Z' },
]

describe('BlocklistView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockBlocklistList.mockResolvedValue({
      data: FAKE_ENTRIES,
      pagination: { totalItems: 2 },
    })
  })

  it('renders without error', async () => {
    const w = shallowMount(BlocklistView)
    await flushPromises()
    expect(w.exists()).toBe(true)
  })

  it('renders the Blocklist heading', async () => {
    const w = shallowMount(BlocklistView)
    await flushPromises()
    expect(w.text()).toContain('Blocklist')
  })

  it('calls blocklistApi.list on mount', async () => {
    shallowMount(BlocklistView)
    await flushPromises()
    expect(mockBlocklistList).toHaveBeenCalledOnce()
  })

  it('renders blocklist entry hashes after load', async () => {
    const w = shallowMount(BlocklistView)
    await flushPromises()
    expect(w.text()).toContain('abc123def456')
    expect(w.text()).toContain('789xyz000111')
  })

  it('renders total count', async () => {
    const w = shallowMount(BlocklistView)
    await flushPromises()
    expect(w.text()).toContain('2')
  })

  it('renders Add Hash button', async () => {
    const w = shallowMount(BlocklistView)
    await flushPromises()
    expect(w.text()).toContain('Add Hash')
  })

  it('shows add form when Add Hash is clicked', async () => {
    const w = shallowMount(BlocklistView)
    await flushPromises()
    expect(w.text()).not.toContain('Add Blocklist Entry')
    await w.find('.btn-primary').trigger('click')
    expect(w.text()).toContain('Add Blocklist Entry')
  })
})

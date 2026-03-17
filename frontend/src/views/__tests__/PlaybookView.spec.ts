import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount, flushPromises } from '@vue/test-utils'
import PlaybookView from '../PlaybookView.vue'

const mockAxiosGet = vi.hoisted(() => vi.fn())

vi.mock('vue-router', () => ({
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
}))

vi.mock('axios', () => ({
  default: {
    get: mockAxiosGet,
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
    create: vi.fn(() => ({
      get: vi.fn(),
      post: vi.fn(),
      interceptors: {
        request: { use: vi.fn() },
        response: { use: vi.fn() },
      },
    })),
  },
}))

vi.mock('../../api/client', () => ({
  default: {
    get: vi.fn(() => Promise.resolve({ data: [] })),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  },
}))

const FAKE_PLAYBOOKS = [
  {
    id: 'pb-1',
    title: 'Ransomware Attack',
    description: 'Simulates ransomware infection',
    category: 'ransomware',
    severity: 'CRITICAL',
    estimatedDurationMs: 15000,
    stepCount: 5,
    builtin: true,
  },
  {
    id: 'pb-2',
    title: 'Lateral Movement',
    description: 'PsExec lateral movement',
    category: 'lateral',
    severity: 'HIGH',
    estimatedDurationMs: 10000,
    stepCount: 3,
    builtin: true,
  },
]

const FAKE_AGENTS = [
  { id: 'agent-1', computerName: 'WS-FINANCE-01' },
]

describe('PlaybookView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // localStorage mock for token
    vi.spyOn(Storage.prototype, 'getItem').mockReturnValue('test-token')

    mockAxiosGet.mockImplementation((url: string) => {
      if (url === '/_dev/playbooks') return Promise.resolve({ data: { data: FAKE_PLAYBOOKS } })
      if (url.includes('/agents')) return Promise.resolve({ data: { data: FAKE_AGENTS } })
      if (url === '/_dev/playbooks/status') return Promise.resolve({ data: { data: { status: 'idle' } } })
      return Promise.resolve({ data: { data: {} } })
    })
  })

  it('renders without error', async () => {
    const w = shallowMount(PlaybookView)
    await flushPromises()
    expect(w.exists()).toBe(true)
  })

  it('renders the Playbook Library heading', async () => {
    const w = shallowMount(PlaybookView)
    await flushPromises()
    expect(w.text()).toContain('Playbook Library')
  })

  it('loads playbooks on mount', async () => {
    shallowMount(PlaybookView)
    await flushPromises()
    expect(mockAxiosGet).toHaveBeenCalledWith('/_dev/playbooks', expect.any(Object))
  })

  it('renders playbook titles after load', async () => {
    const w = shallowMount(PlaybookView)
    await flushPromises()
    expect(w.text()).toContain('Ransomware Attack')
    expect(w.text()).toContain('Lateral Movement')
  })

  it('shows Select a Playbook prompt when none selected', async () => {
    const w = shallowMount(PlaybookView)
    await flushPromises()
    expect(w.text()).toContain('Select a Playbook')
  })
})

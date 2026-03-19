import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount, flushPromises } from '@vue/test-utils'
import ActivitiesView from '@/views/ActivitiesView.vue'

const mockActivitiesList = vi.hoisted(() => vi.fn())

vi.mock('vue-router', () => ({
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
}))

vi.mock('../../api/misc', () => ({
  activitiesApi: {
    list: mockActivitiesList,
  },
}))

const FAKE_ACTIVITIES = [
  {
    id: 'act1', activityType: 1001, description: 'Agent WS-HR-03 registered',
    agentComputerName: 'WS-HR-03', primaryDescription: 'Registration',
    createdAt: '2025-06-01T10:00:00Z',
  },
  {
    id: 'act2', activityType: 2001, description: 'Threat detected on DC-PRIMARY',
    agentComputerName: 'DC-PRIMARY', primaryDescription: 'Malware',
    createdAt: '2025-06-02T14:30:00Z',
  },
]

describe('ActivitiesView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockActivitiesList.mockResolvedValue({
      data: FAKE_ACTIVITIES,
      pagination: { totalItems: 2, nextCursor: null },
    })
  })

  it('renders without error', async () => {
    const w = shallowMount(ActivitiesView)
    await flushPromises()
    expect(w.exists()).toBe(true)
  })

  it('renders the Activity Log heading', async () => {
    const w = shallowMount(ActivitiesView)
    await flushPromises()
    expect(w.text()).toContain('Activity Log')
  })

  it('calls activitiesApi.list on mount', async () => {
    shallowMount(ActivitiesView)
    await flushPromises()
    expect(mockActivitiesList).toHaveBeenCalledOnce()
  })

  it('renders activity descriptions after load', async () => {
    const w = shallowMount(ActivitiesView)
    await flushPromises()
    expect(w.text()).toContain('Agent WS-HR-03 registered')
    expect(w.text()).toContain('Threat detected on DC-PRIMARY')
  })

  it('renders total events count', async () => {
    const w = shallowMount(ActivitiesView)
    await flushPromises()
    expect(w.text()).toContain('2')
  })

  it('renders agent computer names', async () => {
    const w = shallowMount(ActivitiesView)
    await flushPromises()
    expect(w.text()).toContain('WS-HR-03')
    expect(w.text()).toContain('DC-PRIMARY')
  })

  it('does not show Load more when no nextCursor', async () => {
    const w = shallowMount(ActivitiesView)
    await flushPromises()
    expect(w.text()).not.toContain('Load more')
  })

  it('shows Load more button when nextCursor is present', async () => {
    mockActivitiesList.mockResolvedValue({
      data: FAKE_ACTIVITIES,
      pagination: { totalItems: 50, nextCursor: 'cursor-abc' },
    })
    const w = shallowMount(ActivitiesView)
    await flushPromises()
    expect(w.text()).toContain('Load more')
  })
})

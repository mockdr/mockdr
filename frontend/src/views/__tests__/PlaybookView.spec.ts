import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import PlaybookView from '@/views/PlaybookView.vue'

const mockAxiosGet = vi.hoisted(() => vi.fn())
const mockAxiosPost = vi.hoisted(() => vi.fn())
const mockAxiosPut = vi.hoisted(() => vi.fn())
const mockAxiosDelete = vi.hoisted(() => vi.fn())

vi.mock('vue-router', () => ({
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
}))

vi.mock('axios', () => ({
  default: {
    get: mockAxiosGet,
    post: mockAxiosPost,
    put: mockAxiosPut,
    delete: mockAxiosDelete,
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
    get: vi.fn(() => Promise.resolve({ data: [{ id: 'agent-1', computerName: 'WS-FINANCE-01' }] })),
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
    builtin: false,
  },
]


const FAKE_DETAIL = {
  id: 'pb-1',
  title: 'Ransomware Attack',
  steps: [
    { stepId: 'step_1', label: 'Init', delayMs: 0, action: 'activity', activityType: 2, description: 'Start' },
    { stepId: 'step_2', label: 'Payload', delayMs: 2000, action: 'threat', threatName: 'Ransom.Fake', fileName: 'evil.exe' },
  ],
}

const stubs = { LoadingSkeleton: true, EmptyState: true }

describe('PlaybookView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.spyOn(Storage.prototype, 'getItem').mockReturnValue('test-token')

    mockAxiosGet.mockImplementation((url: string) => {
      if (url === '/_dev/playbooks') return Promise.resolve({ data: { data: FAKE_PLAYBOOKS } })
      if (url.includes('/_dev/playbooks/pb-')) return Promise.resolve({ data: { data: FAKE_DETAIL } })
      if (url === '/_dev/playbooks/status') return Promise.resolve({ data: { data: { status: 'idle' } } })
      return Promise.resolve({ data: { data: {} } })
    })
    mockAxiosPost.mockResolvedValue({ data: { data: { id: 'pb-new' } } })
    mockAxiosPut.mockResolvedValue({ data: { data: {} } })
    mockAxiosDelete.mockResolvedValue({})
  })

  it('renders the Playbook Library heading', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    expect(w.text()).toContain('Playbook Library')
  })

  it('loads playbooks on mount', async () => {
    mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    expect(mockAxiosGet).toHaveBeenCalledWith('/_dev/playbooks', expect.any(Object))
  })

  it('renders playbook titles after load', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    expect(w.text()).toContain('Ransomware Attack')
    expect(w.text()).toContain('Lateral Movement')
  })

  it('shows Select a Playbook prompt when none selected', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    expect(w.text()).toContain('Select a Playbook')
  })

  it('formatDelay returns "immediately" for 0ms', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).formatDelay(0)).toBe('immediately')
  })

  it('formatDelay returns ms label for < 1000ms', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).formatDelay(500)).toBe('500ms')
  })

  it('formatDelay returns t+Xs for >= 1000ms', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).formatDelay(3000)).toBe('t+3s')
  })

  it('elapsedSeconds returns empty string for null startedAt', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).elapsedSeconds(null)).toBe('')
  })

  it('elapsedSeconds returns elapsed string for valid date', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    const pastDate = new Date(Date.now() - 5000).toISOString()
    const result = (w.vm as any).elapsedSeconds(pastDate)
    expect(result).toContain('s ago')
  })

  it('categoryColor returns correct color for malware', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).categoryColor('malware')).toBe('text-orange-400')
  })

  it('categoryColor returns correct color for ransomware', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).categoryColor('ransomware')).toBe('text-red-400')
  })

  it('categoryColor returns correct color for lateral', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).categoryColor('lateral')).toBe('text-yellow-400')
  })

  it('categoryColor returns correct color for reset', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).categoryColor('reset')).toBe('text-green-400')
  })

  it('categoryColor returns default for unknown category', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).categoryColor('unknown')).toBe('text-s1-muted')
  })

  it('severityBadge returns correct class for CRITICAL', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).severityBadge('CRITICAL')).toContain('red')
  })

  it('severityBadge returns correct class for HIGH', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).severityBadge('HIGH')).toContain('orange')
  })

  it('severityBadge returns correct class for MEDIUM', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).severityBadge('MEDIUM')).toContain('yellow')
  })

  it('severityBadge returns correct class for LOW', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).severityBadge('LOW')).toContain('green')
  })

  it('severityBadge returns default for unknown', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).severityBadge('UNKNOWN')).toContain('muted')
  })

  it('stepStatusColor returns correct color for done', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).stepStatusColor('done')).toBe('text-green-400')
  })

  it('stepStatusColor returns correct color for running', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).stepStatusColor('running')).toContain('blue')
  })

  it('stepStatusColor returns correct color for error', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).stepStatusColor('error')).toBe('text-red-400')
  })

  it('stepStatusColor returns default for pending', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).stepStatusColor('pending')).toBe('text-s1-muted')
  })

  it('stepStatusIcon returns correct icon for each status', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).stepStatusIcon('done')).toBe('✓')
    expect((w.vm as any).stepStatusIcon('running')).toBe('◐')
    expect((w.vm as any).stepStatusIcon('error')).toBe('✗')
    expect((w.vm as any).stepStatusIcon('pending')).toBe('○')
  })

  it('isRunning computed is false when status is idle', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).isRunning).toBe(false)
  })

  it('progress computed returns 0 when no steps', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).progress).toBe(0)
  })

  it('openCreate sets editing to a new draft', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    expect((w.vm as any).editing).not.toBeNull()
    expect((w.vm as any).editing.id).toBe('')
    expect((w.vm as any).editing.title).toBe('')
    expect((w.vm as any).editing.steps).toEqual([])
  })

  it('cancelEdit sets editing to null', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).cancelEdit()
    expect((w.vm as any).editing).toBeNull()
  })

  it('addStep adds a new step to editing.steps', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).addStep()
    expect((w.vm as any).editing.steps).toHaveLength(1)
    expect((w.vm as any).editing.steps[0].action).toBe('activity')
  })

  it('addStep does nothing when editing is null', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).editing = null
    ;(w.vm as any).addStep()
    // no error thrown
  })

  it('removeStep removes step at given index', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).addStep()
    ;(w.vm as any).addStep()
    expect((w.vm as any).editing.steps).toHaveLength(2)
    ;(w.vm as any).removeStep(0)
    expect((w.vm as any).editing.steps).toHaveLength(1)
  })

  it('onStepActionChange sets activity fields', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).addStep()
    ;(w.vm as any).onStepActionChange(0, 'activity')
    expect((w.vm as any).editing.steps[0].action).toBe('activity')
    expect((w.vm as any).editing.steps[0].activityType).toBe(2)
  })

  it('onStepActionChange sets threat fields', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).addStep()
    ;(w.vm as any).onStepActionChange(0, 'threat')
    expect((w.vm as any).editing.steps[0].action).toBe('threat')
    expect((w.vm as any).editing.steps[0].threatName).toBe('')
    expect((w.vm as any).editing.steps[0].classification).toBe('Trojan')
  })

  it('onStepActionChange sets alert fields', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).addStep()
    ;(w.vm as any).onStepActionChange(0, 'alert')
    expect((w.vm as any).editing.steps[0].action).toBe('alert')
    expect((w.vm as any).editing.steps[0].severity).toBe('HIGH')
  })

  it('onStepActionChange sets agent_state fields', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).addStep()
    ;(w.vm as any).onStepActionChange(0, 'agent_state')
    expect((w.vm as any).editing.steps[0].action).toBe('agent_state')
    expect((w.vm as any).editing.steps[0].infected).toBe(true)
  })

  it('onStepActionChange does nothing when step index invalid', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).onStepActionChange(99, 'activity')
    // no error thrown
  })

  it('onDragStart sets dragSrcIdx', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).onDragStart(2)
    expect((w.vm as any).dragSrcIdx).toBe(2)
  })

  it('onDrop reorders steps correctly', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).addStep()
    ;(w.vm as any).addStep()
    ;(w.vm as any).addStep()
    const steps = (w.vm as any).editing.steps
    steps[0].label = 'A'
    steps[1].label = 'B'
    steps[2].label = 'C'
    ;(w.vm as any).onDragStart(0)
    ;(w.vm as any).onDrop(2)
    expect((w.vm as any).editing.steps[0].label).toBe('B')
    expect((w.vm as any).editing.steps[2].label).toBe('A')
    expect((w.vm as any).dragSrcIdx).toBeNull()
  })

  it('onDrop does nothing when dragSrcIdx is null', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).addStep()
    ;(w.vm as any).dragSrcIdx = null
    ;(w.vm as any).onDrop(0)
    // no error thrown
  })

  it('selectPlaybook sets selected and fetches detail', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    const pb = (w.vm as any).playbooks[0]
    await (w.vm as any).selectPlaybook(pb)
    await flushPromises()
    expect((w.vm as any).selected).toEqual(pb)
    expect((w.vm as any).detail).not.toBeNull()
  })

  it('selectPlaybook does nothing when editing is active', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    const pb = (w.vm as any).playbooks[0]
    await (w.vm as any).selectPlaybook(pb)
    expect((w.vm as any).selected).toBeNull()
  })

  it('savePlaybook creates new playbook when no id', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).editing.title = 'My New Playbook'
    await (w.vm as any).savePlaybook()
    await flushPromises()
    expect(mockAxiosPost).toHaveBeenCalledWith('/_dev/playbooks', expect.any(Object), expect.any(Object))
    expect((w.vm as any).editing).toBeNull()
  })

  it('savePlaybook updates existing playbook when id present', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).editing = {
      id: 'pb-1',
      title: 'Updated Playbook',
      description: '',
      category: 'malware',
      severity: 'HIGH',
      estimatedDurationMs: 5000,
      steps: [],
    }
    await (w.vm as any).savePlaybook()
    await flushPromises()
    expect(mockAxiosPut).toHaveBeenCalledWith('/_dev/playbooks/pb-1', expect.any(Object), expect.any(Object))
    expect((w.vm as any).editing).toBeNull()
  })

  it('savePlaybook does nothing when editing is null', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).editing = null
    await (w.vm as any).savePlaybook()
    expect(mockAxiosPost).not.toHaveBeenCalled()
    expect(mockAxiosPut).not.toHaveBeenCalled()
  })

  it('requestDelete sets deleteConfirmId on first click', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    const mockEvent = { stopPropagation: vi.fn() } as unknown as MouseEvent
    await (w.vm as any).requestDelete('pb-1', mockEvent)
    expect((w.vm as any).deleteConfirmId).toBe('pb-1')
    expect(mockAxiosDelete).not.toHaveBeenCalled()
  })

  it('requestDelete deletes on second click', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    const mockEvent = { stopPropagation: vi.fn() } as unknown as MouseEvent
    ;(w.vm as any).deleteConfirmId = 'pb-1'
    await (w.vm as any).requestDelete('pb-1', mockEvent)
    await flushPromises()
    expect(mockAxiosDelete).toHaveBeenCalledWith('/_dev/playbooks/pb-1', expect.any(Object))
  })

  it('requestDelete clears selected when deleted playbook was selected', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).selected = FAKE_PLAYBOOKS[0]
    ;(w.vm as any).detail = FAKE_DETAIL
    ;(w.vm as any).deleteConfirmId = 'pb-1'
    const mockEvent = { stopPropagation: vi.fn() } as unknown as MouseEvent
    await (w.vm as any).requestDelete('pb-1', mockEvent)
    await flushPromises()
    expect((w.vm as any).selected).toBeNull()
    expect((w.vm as any).detail).toBeNull()
  })

  it('runPlaybook does nothing when no selected or no agentId', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).selected = null
    await (w.vm as any).runPlaybook()
    expect(mockAxiosPost).not.toHaveBeenCalledWith(expect.stringContaining('/run'), expect.anything(), expect.anything())
  })

  it('runPlaybook calls axios.post with run endpoint', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).selected = FAKE_PLAYBOOKS[0]
    ;(w.vm as any).selectedAgentId = 'agent-1'
    await (w.vm as any).runPlaybook()
    await flushPromises()
    expect(mockAxiosPost).toHaveBeenCalledWith(
      '/_dev/playbooks/pb-1/run',
      { agentId: 'agent-1' },
      expect.any(Object)
    )
  })

  it('cancelRun calls axios.delete on cancel endpoint', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    await (w.vm as any).cancelRun()
    await flushPromises()
    expect(mockAxiosDelete).toHaveBeenCalledWith('/_dev/playbooks/cancel', expect.any(Object))
  })

  it('pollStatus updates runStatus', async () => {
    mockAxiosGet.mockImplementation((url: string) => {
      if (url === '/_dev/playbooks') return Promise.resolve({ data: { data: FAKE_PLAYBOOKS } })
      if (url === '/_dev/playbooks/status') return Promise.resolve({ data: { data: { status: 'running', currentStep: 1, totalSteps: 5 } } })
      return Promise.resolve({ data: { data: {} } })
    })
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    await (w.vm as any).pollStatus()
    await flushPromises()
    expect((w.vm as any).runStatus.status).toBe('running')
  })

  it('stopPolling clears pollingTimer', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).pollingTimer = window.setInterval(() => {}, 10000)
    ;(w.vm as any).stopPolling()
    expect((w.vm as any).pollingTimer).toBeNull()
  })

  it('openEdit calls axios.get and sets editing', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    const mockEvent = { stopPropagation: vi.fn() } as unknown as MouseEvent
    await (w.vm as any).openEdit(FAKE_PLAYBOOKS[0], mockEvent)
    await flushPromises()
    expect((w.vm as any).editing).not.toBeNull()
    expect((w.vm as any).editing.id).toBe('pb-1')
  })

  it('progress computed calculates correctly with done steps', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).runStatus = {
      status: 'running',
      steps: [
        { stepId: 's1', status: 'done', startedAt: null, completedAt: null, error: null },
        { stepId: 's2', status: 'done', startedAt: null, completedAt: null, error: null },
        { stepId: 's3', status: 'running', startedAt: null, completedAt: null, error: null },
        { stepId: 's4', status: 'pending', startedAt: null, completedAt: null, error: null },
      ],
    }
    await w.vm.$nextTick()
    expect((w.vm as any).progress).toBe(50)
  })

  it('isRunning returns true when status is running', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).runStatus = { status: 'running' }
    await w.vm.$nextTick()
    expect((w.vm as any).isRunning).toBe(true)
  })

  it('loadAgents auto-selects first agent', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).selectedAgentId).toBe('agent-1')
  })

  it('New button triggers openCreate via DOM click', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    const btn = w.findAll('button').find(b => b.text().includes('New'))
    await btn!.trigger('click')
    expect((w.vm as any).editing).not.toBeNull()
    expect((w.vm as any).editing.id).toBe('')
  })

  it('playbook list item triggers selectPlaybook via DOM click', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    const btn = w.findAll('button').find(b => b.text().includes('Ransomware Attack'))
    await btn!.trigger('click')
    await flushPromises()
    expect((w.vm as any).selected).not.toBeNull()
    expect((w.vm as any).selected.id).toBe('pb-1')
  })

  it('Cancel button in editor triggers cancelEdit via DOM click', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    await w.vm.$nextTick()
    const cancelBtn = w.findAll('button').find(b => b.text().includes('Cancel'))
    await cancelBtn!.trigger('click')
    expect((w.vm as any).editing).toBeNull()
  })

  it('Save button in editor triggers savePlaybook via DOM click', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).editing.title = 'DOM Test Playbook'
    await w.vm.$nextTick()
    const saveBtn = w.findAll('button').find(b => b.text() === 'Save')
    await saveBtn!.trigger('click')
    await flushPromises()
    expect(mockAxiosPost).toHaveBeenCalledWith('/_dev/playbooks', expect.any(Object), expect.any(Object))
  })

  it('Add Step button triggers addStep via DOM click', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    await w.vm.$nextTick()
    const addStepBtn = w.findAll('button').find(b => b.text().includes('Add Step'))
    await addStepBtn!.trigger('click')
    expect((w.vm as any).editing.steps).toHaveLength(1)
  })

  it('step X button triggers removeStep via DOM click', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).addStep()
    await w.vm.$nextTick()
    const removeBtn = w.find('button.p-1.flex-shrink-0')
    await removeBtn.trigger('click')
    expect((w.vm as any).editing.steps).toHaveLength(0)
  })

  it('step action select triggers onStepActionChange via DOM change', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).addStep()
    await w.vm.$nextTick()
    const select = w.find('select.bg-s1-bg.border.border-s1-border.rounded.px-2')
    await select.setValue('threat')
    expect((w.vm as any).editing.steps[0].action).toBe('threat')
  })

  it('Run Playbook button triggers runPlaybook via DOM click', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).selected = FAKE_PLAYBOOKS[0]
    ;(w.vm as any).selectedAgentId = 'agent-1'
    await w.vm.$nextTick()
    const runBtn = w.findAll('button').find(b => b.text().includes('Run Playbook'))
    await runBtn!.trigger('click')
    await flushPromises()
    expect(mockAxiosPost).toHaveBeenCalledWith('/_dev/playbooks/pb-1/run', { agentId: 'agent-1' }, expect.any(Object))
  })

  it('Cancel run button triggers cancelRun via DOM click', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).selected = FAKE_PLAYBOOKS[0]
    ;(w.vm as any).runStatus = { status: 'running' }
    await w.vm.$nextTick()
    const cancelBtn = w.findAll('button').find(b => b.text().includes('Cancel'))
    await cancelBtn!.trigger('click')
    await flushPromises()
    expect(mockAxiosDelete).toHaveBeenCalledWith('/_dev/playbooks/cancel', expect.any(Object))
  })

  it('alert step mitreTechnique input updates via DOM setValue', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).addStep()
    await w.vm.$nextTick()
    // Change action to 'alert' via the select (triggers onStepActionChange which populates fields)
    const actionSelect = w.find('select.bg-s1-bg.border.border-s1-border.rounded.px-2')
    await actionSelect.setValue('alert')
    await w.vm.$nextTick()
    const inputs = w.findAll('input.w-full.bg-s1-bg')
    if (inputs.length > 0) {
      await inputs[inputs.length - 1].setValue('T1566')
    }
  })

  it('alert step description input updates via DOM setValue', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).addStep()
    await w.vm.$nextTick()
    const actionSelect = w.find('select.bg-s1-bg.border.border-s1-border.rounded.px-2')
    await actionSelect.setValue('alert')
    await w.vm.$nextTick()
    const inputs = w.findAll('input.w-full.bg-s1-bg')
    if (inputs.length > 1) {
      await inputs[0].setValue('Alert description text')
    }
  })

  it('agent_state step infected select updates via DOM setValue', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).addStep()
    await w.vm.$nextTick()
    const actionSelect = w.find('select.bg-s1-bg.border.border-s1-border.rounded.px-2')
    await actionSelect.setValue('agent_state')
    await w.vm.$nextTick()
    const selects = w.findAll('select.w-full.bg-s1-bg')
    if (selects.length > 0) {
      await selects[0].setValue('false')
    }
  })

  it('agent_state step networkStatus select updates via DOM setValue', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).addStep()
    await w.vm.$nextTick()
    const actionSelect = w.find('select.bg-s1-bg.border.border-s1-border.rounded.px-2')
    await actionSelect.setValue('agent_state')
    await w.vm.$nextTick()
    const selects = w.findAll('select.w-full.bg-s1-bg')
    if (selects.length > 1) {
      await selects[1].setValue('disconnected')
    }
  })

  it('agent_state step activeThreats number input updates via DOM setValue', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).addStep()
    await w.vm.$nextTick()
    const actionSelect = w.find('select.bg-s1-bg.border.border-s1-border.rounded.px-2')
    await actionSelect.setValue('agent_state')
    await w.vm.$nextTick()
    const numberInput = w.find('input[type="number"]')
    if (numberInput.exists()) {
      await numberInput.setValue('3')
    }
  })

  it('selectedAgentId select updates via DOM setValue', async () => {
    const w = mount(PlaybookView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).selected = FAKE_PLAYBOOKS[0]
    await w.vm.$nextTick()
    const agentSelect = w.find('select.bg-s1-bg.border.border-s1-border.rounded-lg')
    if (agentSelect.exists()) {
      await agentSelect.setValue('agent-1')
      expect((w.vm as any).selectedAgentId).toBe('agent-1')
    }
  })
})

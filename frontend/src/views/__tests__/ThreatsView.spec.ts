import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'

// vi.mock is hoisted - all data must be inlined, no external variable references.
// We use vi.hoisted to create a stable shared store object so the component and
// tests both reference the exact same spy instance.
const mockFetchList = vi.hoisted(() => vi.fn().mockResolvedValue(undefined))
const mockPerformAction = vi.hoisted(() => vi.fn().mockResolvedValue(undefined))

vi.mock('vue-router', () => ({
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
}))

vi.mock('../../stores/threats', () => ({
  useThreatsStore: vi.fn(() => ({
    items: [
      {
        id: 'threat-1',
        threatInfo: {
          threatName: 'EICAR-Test-File',
          sha1: 'aabbccddeeff00112233445566778899aabbccdd',
          classification: 'Malware',
          mitigationStatus: 'active',
          incidentStatus: 'unresolved',
          analystVerdict: 'undefined',
          createdAt: '2025-01-15T10:00:00Z',
        },
        agentDetectionInfo: { agentComputerName: 'WIN-WORKSTATION-01' },
      },
      {
        id: 'threat-2',
        threatInfo: {
          threatName: 'Ransomware.Generic',
          sha1: '112233445566778899aabbccddeeff001122334',
          classification: 'Ransomware',
          mitigationStatus: 'mitigated',
          incidentStatus: 'resolved',
          analystVerdict: 'true_positive',
          createdAt: '2025-02-20T14:30:00Z',
        },
        agentDetectionInfo: { agentComputerName: 'MAC-LAPTOP-02' },
      },
    ],
    total: 2,
    loading: false,
    selected: [],
    nextCursor: null,
    filters: {
      query: '',
      classifications: '',
      mitigationStatuses: '',
      analystVerdicts: '',
      incidentStatuses: '',
      siteIds: '',
    },
    fetchList: mockFetchList,
    performAction: mockPerformAction,
    toggleSelect: vi.fn(),
  })),
}))

import ThreatsView from '@/views/ThreatsView.vue'

const GLOBAL_STUBS = {
  LoadingSkeleton: true,
  EmptyState: true,
  StatusBadge: true,
  RouterLink: { template: '<a><slot /></a>' },
  Teleport: true,
}

describe('ThreatsView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  // ── Basic rendering ───────────────────────────────────────────────────────

  it('renders without error', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.exists()).toBe(true)
  })

  it('renders the Threats heading', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.text()).toContain('Threats')
  })

  it('renders the total threat count', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.text()).toContain('2')
  })

  it('calls store.fetchList on mount', async () => {
    mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(mockFetchList).toHaveBeenCalledOnce()
  })

  it('renders threat names from store items', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.text()).toContain('EICAR-Test-File')
    expect(w.text()).toContain('Ransomware.Generic')
  })

  it('renders agent/endpoint names from store items', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.text()).toContain('WIN-WORKSTATION-01')
    expect(w.text()).toContain('MAC-LAPTOP-02')
  })

  // ── formatDate ────────────────────────────────────────────────────────────

  it('formatDate returns a locale date string for a valid ISO timestamp', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const result = (w.vm as any).formatDate('2025-01-15T10:00:00Z')
    expect(typeof result).toBe('string')
    expect(result).not.toBe('—')
    expect(result.length).toBeGreaterThan(0)
  })

  it('formatDate returns em dash for an empty string', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect((w.vm as any).formatDate('')).toBe('—')
  })

  it('formatDate returns em dash for a null value', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect((w.vm as any).formatDate(null as unknown as string)).toBe('—')
  })

  it('formatDate returns em dash for undefined', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect((w.vm as any).formatDate(undefined as unknown as string)).toBe('—')
  })

  it('formatDate output contains the year from the timestamp', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const result = (w.vm as any).formatDate('2025-06-01T00:00:00Z')
    expect(result).toContain('2025')
  })

  // ── toggleSelect ──────────────────────────────────────────────────────────

  it('toggleSelect adds an id to selected when not present', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).toggleSelect('threat-1')
    expect((w.vm as any).selected.has('threat-1')).toBe(true)
  })

  it('toggleSelect removes an id from selected when already present', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).toggleSelect('threat-1')
    expect((w.vm as any).selected.has('threat-1')).toBe(true)
    ;(w.vm as any).toggleSelect('threat-1')
    expect((w.vm as any).selected.has('threat-1')).toBe(false)
  })

  it('toggleSelect can select multiple independent items', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).toggleSelect('threat-1')
    ;(w.vm as any).toggleSelect('threat-2')
    expect((w.vm as any).selected.has('threat-1')).toBe(true)
    expect((w.vm as any).selected.has('threat-2')).toBe(true)
  })

  it('toggleSelect does not affect other selected items when removing one', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).toggleSelect('threat-1')
    ;(w.vm as any).toggleSelect('threat-2')
    ;(w.vm as any).toggleSelect('threat-1')
    expect((w.vm as any).selected.has('threat-1')).toBe(false)
    expect((w.vm as any).selected.has('threat-2')).toBe(true)
  })

  // ── toggleAll ─────────────────────────────────────────────────────────────

  it('toggleAll selects all store items when none are selected', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).toggleAll()
    expect((w.vm as any).selected.has('threat-1')).toBe(true)
    expect((w.vm as any).selected.has('threat-2')).toBe(true)
  })

  it('toggleAll deselects all items when all are already selected', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    // First call selects all
    ;(w.vm as any).toggleAll()
    expect((w.vm as any).selected.size).toBe(2)
    // Second call clears all
    ;(w.vm as any).toggleAll()
    expect((w.vm as any).selected.size).toBe(0)
  })

  it('toggleAll selects all when only some items are selected (partial selection)', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    // Partially select one
    ;(w.vm as any).toggleSelect('threat-1')
    expect((w.vm as any).selected.size).toBe(1)
    // toggleAll should select all since not all are selected
    ;(w.vm as any).toggleAll()
    expect((w.vm as any).selected.has('threat-1')).toBe(true)
    expect((w.vm as any).selected.has('threat-2')).toBe(true)
  })

  // ── allSelected computed ──────────────────────────────────────────────────

  it('allSelected is false when nothing is selected', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect((w.vm as any).allSelected).toBe(false)
  })

  it('allSelected is true when all items are selected', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).toggleAll()
    expect((w.vm as any).allSelected).toBe(true)
  })

  it('allSelected is false when only some items are selected', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).toggleSelect('threat-1')
    expect((w.vm as any).allSelected).toBe(false)
  })

  // ── checkbox interaction via DOM ──────────────────────────────────────────

  it('triggering the select-all checkbox calls toggleAll and selects all', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const selectAllCheckbox = w.find('input[type="checkbox"]')
    await selectAllCheckbox.trigger('change')
    expect((w.vm as any).selected.size).toBe(2)
  })

  it('triggering a row checkbox selects that threat', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const checkboxes = w.findAll('input[type="checkbox"]')
    // index 0 is the select-all, index 1 is the first row
    await checkboxes[1].trigger('change')
    expect((w.vm as any).selected.has('threat-1')).toBe(true)
  })

  it('triggering a row checkbox twice deselects the threat', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const checkboxes = w.findAll('input[type="checkbox"]')
    await checkboxes[1].trigger('change')
    expect((w.vm as any).selected.has('threat-1')).toBe(true)
    await checkboxes[1].trigger('change')
    expect((w.vm as any).selected.has('threat-1')).toBe(false)
  })

  // ── bulk action toolbar visibility ────────────────────────────────────────

  it('bulk action toolbar is hidden when nothing is selected', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    // The toolbar only renders when selected.size > 0
    expect(w.text()).not.toContain(' selected')
  })

  it('bulk action toolbar appears after selecting an item', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).toggleSelect('threat-1')
    await w.vm.$nextTick()
    expect(w.text()).toContain('1 selected')
  })

  it('bulk action toolbar shows correct count for multiple selections', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).toggleAll()
    await w.vm.$nextTick()
    expect(w.text()).toContain('2 selected')
  })

  // ── Refresh button ────────────────────────────────────────────────────────

  it('Refresh button calls store.fetchList again', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const callsBefore = mockFetchList.mock.calls.length
    const refreshBtn = w.find('button')
    await refreshBtn.trigger('click')
    // fetchList should have been called one more time after click
    expect(mockFetchList.mock.calls.length).toBe(callsBefore + 1)
  })

  // ── formatDate shown in table ─────────────────────────────────────────────

  it('rendered table contains the year from threat createdAt timestamps', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.text()).toContain('2025')
  })

  // ── bulk action toolbar buttons ───────────────────────────────────────────

  it('Mark as Threat button calls store.performAction via DOM click', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).toggleSelect('threat-1')
    await w.vm.$nextTick()
    const btn = w.findAll('button').find(b => b.text().includes('Mark as Threat'))
    await btn!.trigger('click')
    expect(mockPerformAction).toHaveBeenCalledWith('mark-as-threat', expect.any(Array))
  })

  it('Mark as Benign button calls store.performAction via DOM click', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).toggleSelect('threat-1')
    await w.vm.$nextTick()
    const btn = w.findAll('button').find(b => b.text().includes('Mark as Benign'))
    await btn!.trigger('click')
    expect(mockPerformAction).toHaveBeenCalledWith('mark-as-benign', expect.any(Array))
  })

  it('Resolve button calls store.performAction via DOM click', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).toggleSelect('threat-1')
    await w.vm.$nextTick()
    const btn = w.findAll('button').find(b => b.text().includes('Resolve'))
    await btn!.trigger('click')
    expect(mockPerformAction).toHaveBeenCalledWith('resolve', expect.any(Array))
  })

  it('Add to Blocklist button calls store.performAction via DOM click', async () => {
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).toggleSelect('threat-1')
    await w.vm.$nextTick()
    const btn = w.findAll('button').find(b => b.text().includes('Add to Blocklist'))
    await btn!.trigger('click')
    expect(mockPerformAction).toHaveBeenCalledWith('add-to-blocklist', expect.any(Array))
  })

  it('table row click navigates to threat detail', async () => {
    const { useRouter } = await import('vue-router')
    const mockPush = vi.fn()
    vi.mocked(useRouter).mockReturnValueOnce({ push: mockPush } as any)
    const w = mount(ThreatsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const rows = w.findAll('tr')
    const dataRow = rows.find(r => r.text().includes('EICAR-Test-File'))
    if (dataRow) {
      await dataRow.trigger('click')
      expect(mockPush).toHaveBeenCalledWith('/threats/threat-1')
    }
  })
})

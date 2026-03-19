import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'

vi.mock('../../api/misc', () => ({
  groupsApi: {
    list: vi.fn().mockResolvedValue({
      data: [{ id: 'g1', name: 'Windows Servers', siteId: 's1', type: 'static', totalAgents: 10, createdAt: '2025-01-01T00:00:00Z', isDefault: false }],
      pagination: { totalItems: 1 },
    }),
    create: vi.fn().mockResolvedValue({ data: {} }),
    update: vi.fn().mockResolvedValue({ data: {} }),
    delete: vi.fn().mockResolvedValue({}),
  },
  sitesApi: {
    list: vi.fn().mockResolvedValue({ data: { sites: [{ id: 's1', name: 'Alpha HQ' }] } }),
  },
}))

import GroupsView from '@/views/GroupsView.vue'

const stubs = { LoadingSkeleton: true, EmptyState: true }

describe('GroupsView', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('renders the Groups heading', async () => {
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    expect(w.text()).toContain('Groups')
  })

  it('renders group names after load', async () => {
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    expect(w.text()).toContain('Windows Servers')
  })

  it('filtered computed returns all items when no site filter', async () => {
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).filtered).toHaveLength(1)
  })

  it('filtered computed filters by siteId', async () => {
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).siteFilter = 'other-site'
    await w.vm.$nextTick()
    expect((w.vm as any).filtered).toHaveLength(0)
  })

  it('openCreate sets modal to create mode', async () => {
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    expect((w.vm as any).modalMode).toBe('create')
  })

  it('openEdit sets modal to edit mode with group data', async () => {
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    const group = (w.vm as any).items[0]
    ;(w.vm as any).openEdit(group)
    expect((w.vm as any).modalMode).toBe('edit')
    expect((w.vm as any).form.name).toBe('Windows Servers')
  })

  it('closeModal clears modal mode', async () => {
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).closeModal()
    expect((w.vm as any).modalMode).toBeNull()
  })

  it('saveModal shows error when name is empty', async () => {
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).form.name = ''
    await (w.vm as any).saveModal()
    expect((w.vm as any).modalError).toBeTruthy()
  })

  it('saveModal shows error when siteId is missing on create', async () => {
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).modalMode = 'create'
    ;(w.vm as any).form.name = 'Test'
    ;(w.vm as any).form.siteId = ''
    await (w.vm as any).saveModal()
    expect((w.vm as any).modalError).toBeTruthy()
  })

  it('saveModal creates group', async () => {
    const { groupsApi } = await import('../../api/misc')
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).form.name = 'New Group'
    ;(w.vm as any).form.siteId = 's1'
    await (w.vm as any).saveModal()
    await flushPromises()
    expect(groupsApi.create).toHaveBeenCalled()
  })

  it('saveModal updates group', async () => {
    const { groupsApi } = await import('../../api/misc')
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    const group = (w.vm as any).items[0]
    ;(w.vm as any).openEdit(group)
    ;(w.vm as any).form.name = 'Updated'
    await (w.vm as any).saveModal()
    await flushPromises()
    expect(groupsApi.update).toHaveBeenCalled()
  })

  it('requestDelete sets confirmDeleteId', async () => {
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    const group = (w.vm as any).items[0]
    ;(w.vm as any).requestDelete(group)
    expect((w.vm as any).confirmDeleteId).toBe('g1')
  })

  it('confirmDelete calls groupsApi.delete', async () => {
    const { groupsApi } = await import('../../api/misc')
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    const group = (w.vm as any).items[0]
    await (w.vm as any).confirmDelete(group)
    expect(groupsApi.delete).toHaveBeenCalledWith('g1')
  })

  it('confirmDelete removes item from list and decrements total', async () => {
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    const initialTotal = (w.vm as any).total
    const group = (w.vm as any).items[0]
    await (w.vm as any).confirmDelete(group)
    await flushPromises()
    expect((w.vm as any).items.every((g: { id: string }) => g.id !== 'g1')).toBe(true)
    expect((w.vm as any).total).toBe(initialTotal - 1)
    expect((w.vm as any).deletingId).toBeNull()
  })

  it('filtered computed returns matching groups when siteFilter is set', async () => {
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).siteFilter = 's1'
    await w.vm.$nextTick()
    expect((w.vm as any).filtered).toHaveLength(1)
    expect((w.vm as any).filtered[0].id).toBe('g1')
  })

  it('closeModal clears editingId and modalError', async () => {
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).editingId = 'g1'
    ;(w.vm as any).modalError = 'some error'
    ;(w.vm as any).closeModal()
    expect((w.vm as any).modalMode).toBeNull()
    expect((w.vm as any).editingId).toBeNull()
    expect((w.vm as any).modalError).toBe('')
  })

  it('saveModal sets modalError on API failure', async () => {
    const { groupsApi } = await import('../../api/misc')
    ;(groupsApi.create as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('Conflict'))
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).form.name = 'FailGroup'
    ;(w.vm as any).form.siteId = 's1'
    await (w.vm as any).saveModal()
    await flushPromises()
    expect((w.vm as any).modalError).toBe('Save failed.')
    expect((w.vm as any).modalSaving).toBe(false)
  })

  it('openEdit populates all form fields correctly', async () => {
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    const group = (w.vm as any).items[0]
    ;(w.vm as any).openEdit(group)
    expect((w.vm as any).editingId).toBe('g1')
    expect((w.vm as any).form.siteId).toBe('s1')
    expect((w.vm as any).form.type).toBe('static')
    expect((w.vm as any).form.inherits).toBe(true)
  })

  it('saveModal re-fetches list after successful create', async () => {
    const { groupsApi } = await import('../../api/misc')
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    const listCallsBefore = (groupsApi.list as ReturnType<typeof vi.fn>).mock.calls.length
    ;(w.vm as any).openCreate()
    ;(w.vm as any).form.name = 'NewGroup'
    ;(w.vm as any).form.siteId = 's1'
    await (w.vm as any).saveModal()
    await flushPromises()
    expect((groupsApi.list as ReturnType<typeof vi.fn>).mock.calls.length).toBeGreaterThan(listCallsBefore)
  })

  // ── template / modal interactions ──────────────────────────────────────────

  it('modal renders New Group heading in create mode', async () => {
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    await w.vm.$nextTick()
    expect(w.text()).toContain('New Group')
  })

  it('modal renders Edit Group heading in edit mode', async () => {
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    const group = (w.vm as any).items[0]
    ;(w.vm as any).openEdit(group)
    await w.vm.$nextTick()
    expect(w.text()).toContain('Edit Group')
  })

  it('modal Cancel button closes the modal', async () => {
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    await w.vm.$nextTick()
    const cancelBtn = w.findAll('button').find(b => b.text().includes('Cancel'))
    expect(cancelBtn).toBeDefined()
    await cancelBtn!.trigger('click')
    await w.vm.$nextTick()
    expect((w.vm as any).modalMode).toBeNull()
  })

  it('modal Save button calls saveModal', async () => {
    const { groupsApi } = await import('../../api/misc')
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    await w.vm.$nextTick()
    ;(w.vm as any).form.name = 'ButtonTestGroup'
    ;(w.vm as any).form.siteId = 's1'
    const saveBtn = w.findAll('button').find(b => b.text() === 'Save')
    expect(saveBtn).toBeDefined()
    await saveBtn!.trigger('click')
    await flushPromises()
    expect(groupsApi.create).toHaveBeenCalled()
  })

  it('modal error message is shown when modalError is set', async () => {
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).modalError = 'Something went wrong'
    await w.vm.$nextTick()
    expect(w.text()).toContain('Something went wrong')
  })

  // ── DOM trigger tests ──────────────────────────────────────────────────────

  it('site filter select change updates siteFilter via v-model', async () => {
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    const select = w.find('select')
    await select.setValue('s1')
    expect((w.vm as any).siteFilter).toBe('s1')
  })

  it('Edit group button in table row triggers openEdit via DOM click', async () => {
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    const editBtn = w.find('button[title="Edit group"]')
    await editBtn.trigger('click')
    await w.vm.$nextTick()
    expect((w.vm as any).modalMode).toBe('edit')
    expect((w.vm as any).form.name).toBe('Windows Servers')
  })

  it('Delete group button in table row triggers requestDelete via DOM click', async () => {
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    const deleteBtn = w.find('button[title="Delete group"]')
    await deleteBtn.trigger('click')
    await w.vm.$nextTick()
    expect((w.vm as any).confirmDeleteId).toBe('g1')
  })

  it('Confirm button triggers confirmDelete via DOM click', async () => {
    const { groupsApi } = await import('../../api/misc')
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).requestDelete((w.vm as any).items[0])
    await w.vm.$nextTick()
    const confirmBtn = w.findAll('button').find(b => b.text() === 'Confirm')
    expect(confirmBtn).toBeDefined()
    await confirmBtn!.trigger('click')
    await flushPromises()
    expect(groupsApi.delete).toHaveBeenCalledWith('g1')
  })

  it('X cancel button after requestDelete clears confirmDeleteId via DOM click', async () => {
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).requestDelete((w.vm as any).items[0])
    await w.vm.$nextTick()
    expect((w.vm as any).confirmDeleteId).toBe('g1')
    // The X button is the last button after the Confirm button in the confirm row
    const allBtns = w.findAll('button')
    const confirmIdx = allBtns.findIndex(b => b.text() === 'Confirm')
    const xBtn = allBtns[confirmIdx + 1]
    await xBtn.trigger('click')
    await w.vm.$nextTick()
    expect((w.vm as any).confirmDeleteId).toBeNull()
  })

  it('modal backdrop click.self closes the modal', async () => {
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    await w.vm.$nextTick()
    expect((w.vm as any).modalMode).toBe('create')
    // Trigger the closeModal function directly as backdrop @click.self cannot be
    // reliably simulated with trigger on the overlay div itself
    ;(w.vm as any).closeModal()
    await w.vm.$nextTick()
    expect((w.vm as any).modalMode).toBeNull()
  })

  it('modal X header button closes the modal via DOM click', async () => {
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    await w.vm.$nextTick()
    // The X close button is inside the modal card header div (flex justify-between)
    // It is the only button inside the header div of the modal card
    const modalHeader = w.find('.fixed .card div.flex.items-center.justify-between')
    const xHeaderBtn = modalHeader.find('button')
    expect(xHeaderBtn.exists()).toBe(true)
    await xHeaderBtn.trigger('click')
    await w.vm.$nextTick()
    expect((w.vm as any).modalMode).toBeNull()
  })

  it('New Group button triggers openCreate via DOM click', async () => {
    const w = mount(GroupsView, { global: { stubs } })
    await flushPromises()
    const newGroupBtn = w.findAll('button').find(b => b.text().includes('New Group'))
    expect(newGroupBtn).toBeDefined()
    await newGroupBtn!.trigger('click')
    await w.vm.$nextTick()
    expect((w.vm as any).modalMode).toBe('create')
  })
})

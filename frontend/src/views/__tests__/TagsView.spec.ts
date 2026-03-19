import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'

vi.mock('../../api/tags', () => ({
  tagsApi: {
    list: vi.fn().mockResolvedValue({
      data: [{ id: 'tag-1', key: 'Environment', value: 'Production', scopeLevel: 'global', scopePath: '/', totalEndpoints: 40, endpointsInCurrentScope: 40, description: 'Prod endpoints', createdAt: '2025-04-01T10:00:00Z' }],
      pagination: { totalItems: 1 },
    }),
    create: vi.fn().mockResolvedValue({ data: {} }),
    update: vi.fn().mockResolvedValue({ data: {} }),
    delete: vi.fn().mockResolvedValue({}),
  },
}))

vi.mock('../../api/misc', () => ({
  sitesApi: { list: vi.fn().mockResolvedValue({ data: { sites: [{ id: 's1', name: 'Site A' }] } }) },
  groupsApi: { list: vi.fn().mockResolvedValue({ data: [{ id: 'g1', name: 'Group A' }] }) },
  accountsApi: { list: vi.fn().mockResolvedValue({ data: [{ id: 'a1', name: 'Account A' }] }) },
}))

import TagsView from '@/views/TagsView.vue'

const stubs = { LoadingSkeleton: true, EmptyState: true }

describe('TagsView', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('renders heading', async () => {
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    expect(w.text()).toContain('Endpoint Tags')
  })

  it('renders tag key after load', async () => {
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    expect(w.text()).toContain('Environment')
  })

  it('scopeBadge returns correct class for global', async () => {
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).scopeBadge('global')).toContain('purple')
  })

  it('scopeBadge returns correct class for account', async () => {
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).scopeBadge('account')).toContain('blue')
  })

  it('scopeBadge returns correct class for site', async () => {
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).scopeBadge('site')).toContain('green')
  })

  it('scopeBadge returns correct class for group', async () => {
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).scopeBadge('group')).toContain('gray')
  })

  it('scopeBadge returns default for unknown', async () => {
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).scopeBadge('unknown')).toContain('gray')
  })

  it('scopeOptions computed returns accounts when scopeLevel is account', async () => {
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).newScopeLevel = 'account'
    await w.vm.$nextTick()
    expect((w.vm as any).scopeOptions).toEqual([{ id: 'a1', name: 'Account A' }])
  })

  it('scopeOptions computed returns sites when scopeLevel is site', async () => {
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).newScopeLevel = 'site'
    await w.vm.$nextTick()
    expect((w.vm as any).scopeOptions).toEqual([{ id: 's1', name: 'Site A' }])
  })

  it('scopeOptions computed returns groups when scopeLevel is group', async () => {
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).newScopeLevel = 'group'
    await w.vm.$nextTick()
    expect((w.vm as any).scopeOptions).toEqual([{ id: 'g1', name: 'Group A' }])
  })

  it('addTag shows error when key is empty', async () => {
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).newKey = ''
    await (w.vm as any).addTag()
    expect((w.vm as any).formError).toBeTruthy()
  })

  it('addTag creates tag with global scope', async () => {
    const { tagsApi } = await import('../../api/tags')
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).newKey = 'MyTag'
    ;(w.vm as any).newScopeLevel = 'global'
    await (w.vm as any).addTag()
    await flushPromises()
    expect(tagsApi.create).toHaveBeenCalled()
  })

  it('addTag creates tag with account scope', async () => {
    const { tagsApi } = await import('../../api/tags')
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).newKey = 'MyTag'
    ;(w.vm as any).newScopeLevel = 'account'
    ;(w.vm as any).newScopeId = 'a1'
    await (w.vm as any).addTag()
    await flushPromises()
    expect(tagsApi.create).toHaveBeenCalled()
  })

  it('addTag creates tag with site scope', async () => {
    const { tagsApi } = await import('../../api/tags')
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).newKey = 'MyTag'
    ;(w.vm as any).newScopeLevel = 'site'
    ;(w.vm as any).newScopeId = 's1'
    await (w.vm as any).addTag()
    await flushPromises()
    expect(tagsApi.create).toHaveBeenCalled()
  })

  it('addTag creates tag with group scope', async () => {
    const { tagsApi } = await import('../../api/tags')
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).newKey = 'MyTag'
    ;(w.vm as any).newScopeLevel = 'group'
    ;(w.vm as any).newScopeId = 'g1'
    await (w.vm as any).addTag()
    await flushPromises()
    expect(tagsApi.create).toHaveBeenCalled()
  })

  it('startEdit sets editingId and fields', async () => {
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    const tag = (w.vm as any).items[0]
    ;(w.vm as any).startEdit(tag)
    expect((w.vm as any).editingId).toBe('tag-1')
    expect((w.vm as any).editKey).toBe('Environment')
  })

  it('saveEdit calls tagsApi.update', async () => {
    const { tagsApi } = await import('../../api/tags')
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    await (w.vm as any).saveEdit('tag-1')
    expect(tagsApi.update).toHaveBeenCalledWith('tag-1', expect.any(Object))
  })

  it('removeTag calls tagsApi.delete after confirm', async () => {
    const { tagsApi } = await import('../../api/tags')
    vi.stubGlobal('confirm', vi.fn().mockReturnValue(true))
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    await (w.vm as any).removeTag('tag-1')
    expect(tagsApi.delete).toHaveBeenCalledWith('tag-1')
  })

  it('removeTag does nothing when confirm is cancelled', async () => {
    const { tagsApi } = await import('../../api/tags')
    vi.stubGlobal('confirm', vi.fn().mockReturnValue(false))
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    await (w.vm as any).removeTag('tag-1')
    expect(tagsApi.delete).not.toHaveBeenCalled()
  })

  it('removeTag removes item from list and decrements total on success', async () => {
    vi.stubGlobal('confirm', vi.fn().mockReturnValue(true))
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    const initialLen = (w.vm as any).items.length
    const initialTotal = (w.vm as any).total
    await (w.vm as any).removeTag('tag-1')
    await flushPromises()
    expect((w.vm as any).items).toHaveLength(initialLen - 1)
    expect((w.vm as any).total).toBe(initialTotal - 1)
    expect((w.vm as any).items.every((t: { id: string }) => t.id !== 'tag-1')).toBe(true)
  })

  it('removeTag sets error when tagsApi.delete rejects', async () => {
    const { tagsApi } = await import('../../api/tags')
    vi.stubGlobal('confirm', vi.fn().mockReturnValue(true))
    ;(tagsApi.delete as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('Cannot delete'))
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    await (w.vm as any).removeTag('tag-1')
    await flushPromises()
    expect((w.vm as any).error).toBe('Cannot delete')
  })

  it('addTag falls back to tenant filter when scope has no scopeId', async () => {
    const { tagsApi } = await import('../../api/tags')
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).newKey = 'NoScopeId'
    ;(w.vm as any).newScopeLevel = 'account'
    ;(w.vm as any).newScopeId = ''
    await (w.vm as any).addTag()
    await flushPromises()
    expect(tagsApi.create).toHaveBeenCalledWith(
      expect.objectContaining({ filter: expect.objectContaining({ tenant: true }) })
    )
  })

  it('addTag sets error.value when tagsApi.create rejects', async () => {
    const { tagsApi } = await import('../../api/tags')
    ;(tagsApi.create as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('Duplicate'))
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).newKey = 'FailTag'
    ;(w.vm as any).newScopeLevel = 'global'
    await (w.vm as any).addTag()
    await flushPromises()
    expect((w.vm as any).error).toBe('Duplicate')
  })

  it('addTag resets form and hides panel on success', async () => {
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).showAdd = true
    ;(w.vm as any).newKey = 'ResetTest'
    ;(w.vm as any).newValue = 'Something'
    ;(w.vm as any).newDescription = 'Desc'
    await (w.vm as any).addTag()
    await flushPromises()
    expect((w.vm as any).newKey).toBe('')
    expect((w.vm as any).newValue).toBe('')
    expect((w.vm as any).newDescription).toBe('')
    expect((w.vm as any).showAdd).toBe(false)
  })

  it('saveEdit clears editingId after updating', async () => {
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    const tag = (w.vm as any).items[0]
    ;(w.vm as any).startEdit(tag)
    await wrapper_nextTick(w)
    await (w.vm as any).saveEdit('tag-1')
    await flushPromises()
    expect((w.vm as any).editingId).toBeNull()
  })

  it('scopeOptions returns empty array for global scopeLevel', async () => {
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).newScopeLevel = 'global'
    await w.vm.$nextTick()
    expect((w.vm as any).scopeOptions).toHaveLength(0)
  })

  it('inline save button click in edit row calls saveEdit', async () => {
    const { tagsApi } = await import('../../api/tags')
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    const tag = (w.vm as any).items[0]
    ;(w.vm as any).startEdit(tag)
    await w.vm.$nextTick()
    const saveBtn = w.findAll('button').find(b => b.text() === 'Save')
    expect(saveBtn).toBeDefined()
    await saveBtn!.trigger('click')
    await flushPromises()
    expect(tagsApi.update).toHaveBeenCalledWith('tag-1', expect.any(Object))
  })

  it('inline cancel button click in edit row clears editingId', async () => {
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    const tag = (w.vm as any).items[0]
    ;(w.vm as any).startEdit(tag)
    await w.vm.$nextTick()
    expect((w.vm as any).editingId).toBe('tag-1')
    const cancelBtn = w.find('[aria-label="Cancel edit"]')
    await cancelBtn.trigger('click')
    await w.vm.$nextTick()
    expect((w.vm as any).editingId).toBeNull()
  })

  it('Edit tag button click in row calls startEdit', async () => {
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    const editBtn = w.find('[aria-label="Edit tag"]')
    await editBtn.trigger('click')
    await w.vm.$nextTick()
    expect((w.vm as any).editingId).toBe('tag-1')
  })

  it('Delete tag button click in row calls removeTag', async () => {
    const { tagsApi } = await import('../../api/tags')
    vi.stubGlobal('confirm', vi.fn().mockReturnValue(true))
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    const deleteBtn = w.find('[aria-label="Delete tag"]')
    await deleteBtn.trigger('click')
    await flushPromises()
    expect(tagsApi.delete).toHaveBeenCalled()
  })

  // ── DOM trigger tests ──────────────────────────────────────────────────────

  it('Create Tag button toggles showAdd via DOM click', async () => {
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    expect((w.vm as any).showAdd).toBe(false)
    const createTagBtn = w.findAll('button').find(b => b.text().includes('Create Tag'))
    expect(createTagBtn).toBeDefined()
    await createTagBtn!.trigger('click')
    await w.vm.$nextTick()
    expect((w.vm as any).showAdd).toBe(true)
    // Clicking again toggles it back
    await createTagBtn!.trigger('click')
    await w.vm.$nextTick()
    expect((w.vm as any).showAdd).toBe(false)
  })

  it('Create button in add form triggers addTag via DOM click', async () => {
    const { tagsApi } = await import('../../api/tags')
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).showAdd = true
    ;(w.vm as any).newKey = 'DOMTestTag'
    ;(w.vm as any).newScopeLevel = 'global'
    await w.vm.$nextTick()
    const createBtn = w.findAll('button').find(b => b.text() === 'Create')
    expect(createBtn).toBeDefined()
    await createBtn!.trigger('click')
    await flushPromises()
    expect(tagsApi.create).toHaveBeenCalled()
  })

  it('Cancel button in add form sets showAdd to false via DOM click', async () => {
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).showAdd = true
    await w.vm.$nextTick()
    const cancelBtn = w.findAll('button').find(b => b.text() === 'Cancel')
    expect(cancelBtn).toBeDefined()
    await cancelBtn!.trigger('click')
    await w.vm.$nextTick()
    expect((w.vm as any).showAdd).toBe(false)
  })

  it('scope select @change clears newScopeId via DOM change event', async () => {
    const w = mount(TagsView, { global: { stubs } })
    await flushPromises()
    ;(w.vm as any).showAdd = true
    ;(w.vm as any).newScopeId = 'some-id'
    await w.vm.$nextTick()
    const scopeSelect = w.find('#tag-scope')
    await scopeSelect.setValue('site')
    await w.vm.$nextTick()
    expect((w.vm as any).newScopeLevel).toBe('site')
    expect((w.vm as any).newScopeId).toBe('')
  })
})

// helper to avoid import confusion
async function wrapper_nextTick(w: ReturnType<typeof mount>) {
  await w.vm.$nextTick()
}

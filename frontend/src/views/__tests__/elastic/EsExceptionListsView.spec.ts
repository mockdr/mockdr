import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

vi.mock('../../../api/elastic', () => ({
  esExceptionListsApi: {
    findLists: vi.fn().mockResolvedValue({
      data: [
        {
          id: 'list-1',
          list_id: 'my-exception-list',
          name: 'Known Good Processes',
          description: 'Processes excluded from detection',
          type: 'detection',
          namespace_type: 'single',
          total_items: 3,
        },
        {
          id: 'list-2',
          list_id: 'endpoint-exceptions',
          name: 'Endpoint Exclusions',
          description: 'Endpoint specific exclusions',
          type: 'endpoint',
          namespace_type: 'agnostic',
          total_items: 1,
        },
      ],
      total: 2,
    }),
    findItems: vi.fn().mockResolvedValue({
      data: [
        {
          id: 'item-1',
          name: 'Chrome Browser',
          description: 'Allow chrome.exe',
          type: 'simple',
          entries: [
            { field: 'process.name', operator: 'included', type: 'match', value: 'chrome.exe' },
          ],
          created_at: '2025-01-10T08:00:00Z',
        },
        {
          id: 'item-2',
          name: 'System Utilities',
          description: 'Windows system utils',
          type: 'simple',
          entries: [
            { field: 'process.name', operator: 'included', type: 'match', value: 'svchost.exe' },
          ],
          created_at: '2025-01-11T09:00:00Z',
        },
      ],
      total: 2,
    }),
    createList: vi.fn().mockResolvedValue({ id: 'list-new', list_id: 'new-list', name: 'New List' }),
    deleteList: vi.fn().mockResolvedValue(undefined),
    createItem: vi.fn().mockResolvedValue({ id: 'item-new' }),
    deleteItem: vi.fn().mockResolvedValue(undefined),
  },
}))

import EsExceptionListsView from '@/views/elastic/EsExceptionListsView.vue'
import { esExceptionListsApi } from '@/api/elastic'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/elastic/exception-lists', component: { template: '<div />' } },
  ],
})

const STUBS = {
  LoadingSkeleton: true,
  EmptyState: true,
  StatusBadge: true,
  RouterLink: { template: '<a><slot /></a>' },
  Teleport: true,
}

describe('EsExceptionListsView', () => {
  beforeEach(async () => {
    vi.clearAllMocks()
    await router.push('/')
    await router.isReady()
  })

  it('renders the page header with Exception Lists title', async () => {
    const wrapper = mount(EsExceptionListsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('Exception Lists')
  })

  it('calls fetchLists on mount', async () => {
    mount(EsExceptionListsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(esExceptionListsApi.findLists).toHaveBeenCalledWith({ per_page: 100 })
  })

  it('displays loaded lists', async () => {
    const wrapper = mount(EsExceptionListsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('Known Good Processes')
    expect(wrapper.text()).toContain('Endpoint Exclusions')
  })

  it('auto-selects first list and fetches its items', async () => {
    mount(EsExceptionListsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(esExceptionListsApi.findItems).toHaveBeenCalledWith(
      expect.objectContaining({ list_id: 'my-exception-list' })
    )
  })

  it('displays list items after loading', async () => {
    const wrapper = mount(EsExceptionListsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('Chrome Browser')
    expect(wrapper.text()).toContain('System Utilities')
  })

  it('displays item entry field and value', async () => {
    const wrapper = mount(EsExceptionListsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('process.name')
    expect(wrapper.text()).toContain('chrome.exe')
  })

  // fetchLists function - explicit call
  it('fetchLists can be called explicitly to refresh', async () => {
    const wrapper = mount(EsExceptionListsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    vi.mocked(esExceptionListsApi.findLists).mockClear()
    const vm = wrapper.vm as unknown as { fetchLists: () => Promise<void> }
    await vm.fetchLists()
    await flushPromises()
    expect(esExceptionListsApi.findLists).toHaveBeenCalled()
  })

  // fetchItems function
  it('fetchItems fetches items for selected list', async () => {
    const wrapper = mount(EsExceptionListsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    vi.mocked(esExceptionListsApi.findItems).mockClear()
    const vm = wrapper.vm as unknown as {
      selectedListId: string
      fetchItems: () => Promise<void>
    }
    vm.selectedListId = 'list-2'
    await vm.fetchItems()
    await flushPromises()
    expect(esExceptionListsApi.findItems).toHaveBeenCalledWith(
      expect.objectContaining({ list_id: 'endpoint-exceptions' })
    )
  })

  it('fetchItems clears items when no list is selected', async () => {
    const wrapper = mount(EsExceptionListsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      selectedListId: string
      items: unknown[]
      fetchItems: () => Promise<void>
    }
    vm.selectedListId = ''
    await vm.fetchItems()
    expect(vm.items).toEqual([])
  })

  // createList function
  it('createList calls esExceptionListsApi.createList and refreshes', async () => {
    const wrapper = mount(EsExceptionListsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      showCreateList: boolean
      newList: { name: string; description: string; type: string }
      createList: () => Promise<void>
    }
    vm.showCreateList = true
    vm.newList.name = 'My New List'
    vm.newList.description = 'Test list'
    vm.newList.type = 'detection'
    vi.mocked(esExceptionListsApi.findLists).mockClear()
    await vm.createList()
    await flushPromises()
    expect(esExceptionListsApi.createList).toHaveBeenCalledWith(
      expect.objectContaining({
        name: 'My New List',
        namespace_type: 'single',
      })
    )
    expect(esExceptionListsApi.findLists).toHaveBeenCalled()
    expect(vm.showCreateList).toBe(false)
    expect(vm.newList.name).toBe('')
  })

  // deleteList function
  it('deleteList calls esExceptionListsApi.deleteList', async () => {
    const wrapper = mount(EsExceptionListsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const vm = wrapper.vm as unknown as { deleteList: (id: string, ns: string) => Promise<void> }
    vi.mocked(esExceptionListsApi.findLists).mockClear()
    await vm.deleteList('list-1', 'single')
    await flushPromises()
    expect(esExceptionListsApi.deleteList).toHaveBeenCalledWith('list-1', 'single')
    expect(esExceptionListsApi.findLists).toHaveBeenCalled()
  })

  it('deleteList clears selectedListId if deleted list was selected', async () => {
    const wrapper = mount(EsExceptionListsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      selectedListId: string
      deleteList: (id: string, ns: string) => Promise<void>
    }
    // After mount the first list is auto-selected
    const currentSelected = vm.selectedListId
    expect(currentSelected).toBe('list-1')
    // Mock findLists to return empty so it doesn't re-select
    vi.mocked(esExceptionListsApi.findLists).mockResolvedValueOnce({ page: 1, per_page: 100, data: [], total: 0 })
    await vm.deleteList(currentSelected, 'single')
    await flushPromises()
    expect(vm.selectedListId).toBe('')
  })

  // createItem function
  it('createItem calls esExceptionListsApi.createItem and refreshes items', async () => {
    const wrapper = mount(EsExceptionListsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const vm = wrapper.vm as unknown as {
      showCreateItem: boolean
      newItem: { name: string; description: string; field: string; operator: string; value: string }
      createItem: () => Promise<void>
    }
    vm.showCreateItem = true
    vm.newItem.name = 'New Item'
    vm.newItem.description = 'Block bad process'
    vm.newItem.field = 'process.name'
    vm.newItem.operator = 'included'
    vm.newItem.value = 'malware.exe'
    vi.mocked(esExceptionListsApi.findItems).mockClear()
    await vm.createItem()
    await flushPromises()
    expect(esExceptionListsApi.createItem).toHaveBeenCalledWith(
      expect.objectContaining({
        name: 'New Item',
        type: 'simple',
        entries: [
          expect.objectContaining({
            field: 'process.name',
            value: 'malware.exe',
          }),
        ],
      })
    )
    expect(esExceptionListsApi.findItems).toHaveBeenCalled()
    expect(vm.showCreateItem).toBe(false)
    expect(vm.newItem.name).toBe('')
  })

  it('createItem does nothing when no list is selected', async () => {
    // Reset mock to return no lists so no list is selected
    vi.mocked(esExceptionListsApi.findLists).mockResolvedValueOnce({ page: 1, per_page: 100, data: [], total: 0 })
    const wrapper = mount(EsExceptionListsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    vi.mocked(esExceptionListsApi.createItem).mockClear()
    const vm = wrapper.vm as unknown as { createItem: () => Promise<void>; selectedListId: string }
    vm.selectedListId = ''
    await vm.createItem()
    await flushPromises()
    expect(esExceptionListsApi.createItem).not.toHaveBeenCalled()
  })

  // deleteItem function
  it('deleteItem calls esExceptionListsApi.deleteItem and refreshes', async () => {
    const wrapper = mount(EsExceptionListsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const vm = wrapper.vm as unknown as { deleteItem: (id: string) => Promise<void> }
    vi.mocked(esExceptionListsApi.findItems).mockClear()
    await vm.deleteItem('item-1')
    await flushPromises()
    expect(esExceptionListsApi.deleteItem).toHaveBeenCalledWith('item-1', expect.any(String))
    expect(esExceptionListsApi.findItems).toHaveBeenCalled()
  })

  // watch on selectedListId triggers fetchItems
  it('changing selectedListId triggers fetchItems', async () => {
    const wrapper = mount(EsExceptionListsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    vi.mocked(esExceptionListsApi.findItems).mockClear()
    const vm = wrapper.vm as unknown as { selectedListId: string }
    vm.selectedListId = 'list-2'
    await flushPromises()
    expect(esExceptionListsApi.findItems).toHaveBeenCalled()
  })

  // Error handling
  it('sets loading to false when fetchLists throws', async () => {
    const wrapper = mount(EsExceptionListsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    vi.mocked(esExceptionListsApi.findLists).mockRejectedValueOnce(new Error('API error'))
    const vm = wrapper.vm as unknown as { loading: boolean; fetchLists: () => Promise<void> }
    try { await vm.fetchLists() } catch { /* expected */ }
    await flushPromises()
    expect(vm.loading).toBe(false)
  })

  it('sets loading to false when fetchItems throws', async () => {
    const wrapper = mount(EsExceptionListsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    vi.mocked(esExceptionListsApi.findItems).mockRejectedValueOnce(new Error('Items API error'))
    const vm = wrapper.vm as unknown as { loading: boolean; fetchItems: () => Promise<void> }
    try { await vm.fetchItems() } catch { /* expected */ }
    await flushPromises()
    expect(vm.loading).toBe(false)
  })

  // Open create list dialog
  it('shows create list dialog on Plus button click', async () => {
    const wrapper = mount(EsExceptionListsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const vm = wrapper.vm as unknown as { showCreateList: boolean }
    vm.showCreateList = true
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Create Exception List')
  })

  // Show "Select a list" message when nothing selected
  it('shows select-list message when no list is selected', async () => {
    vi.mocked(esExceptionListsApi.findLists).mockResolvedValueOnce({ page: 1, per_page: 100, data: [], total: 0 })
    const wrapper = mount(EsExceptionListsView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('Select an exception list')
  })

  it('Refresh button calls fetchLists via DOM click', async () => {
    const wrapper = mount(EsExceptionListsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(esExceptionListsApi.findLists).mockClear()
    const btn = wrapper.findAll('button').find(b => b.text().includes('Refresh'))
    await btn!.trigger('click')
    await flushPromises()
    expect(esExceptionListsApi.findLists).toHaveBeenCalled()
  })

  it('Plus button in list header sets showCreateList via DOM click', async () => {
    const wrapper = mount(EsExceptionListsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { showCreateList: boolean }
    expect(vm.showCreateList).toBe(false)
    // The plus button inside Lists panel header
    const plusBtns = wrapper.findAll('button.btn-ghost.p-1.text-purple-400')
    await plusBtns[0].trigger('click')
    expect(vm.showCreateList).toBe(true)
  })

  it('clicking a list item sets selectedListId via DOM click', async () => {
    const wrapper = mount(EsExceptionListsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { selectedListId: string }
    // Click the second list item
    const listItems = wrapper.findAll('.divide-y > div')
    await listItems[1].trigger('click')
    expect(vm.selectedListId).toBe('list-2')
  })

  it('delete list button calls deleteList via DOM click', async () => {
    const wrapper = mount(EsExceptionListsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(esExceptionListsApi.deleteList).mockClear()
    // delete list buttons are inside each list item row
    const deleteListBtn = wrapper.find('.divide-y button.text-red-400')
    await deleteListBtn.trigger('click')
    await flushPromises()
    expect(esExceptionListsApi.deleteList).toHaveBeenCalled()
  })

  it('Create button in create-list dialog calls createList via DOM', async () => {
    const wrapper = mount(EsExceptionListsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { showCreateList: boolean; newList: { name: string } }
    vm.showCreateList = true
    vm.newList.name = 'DOM List'
    await wrapper.vm.$nextTick()
    const createBtn = wrapper.findAll('button').find(b => b.text() === 'Create')
    await createBtn!.trigger('click')
    await flushPromises()
    expect(esExceptionListsApi.createList).toHaveBeenCalled()
  })

  it('Cancel button in create-list dialog closes it via DOM', async () => {
    const wrapper = mount(EsExceptionListsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { showCreateList: boolean }
    vm.showCreateList = true
    await wrapper.vm.$nextTick()
    const cancelBtn = wrapper.findAll('button').find(b => b.text() === 'Cancel')
    await cancelBtn!.trigger('click')
    expect(vm.showCreateList).toBe(false)
  })

  it('Plus button for items panel sets showCreateItem via DOM click', async () => {
    const wrapper = mount(EsExceptionListsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { showCreateItem: boolean }
    const plusBtns = wrapper.findAll('button.btn-ghost.p-1.text-purple-400')
    // Second plus button is for items
    await plusBtns[1].trigger('click')
    expect(vm.showCreateItem).toBe(true)
  })

  it('Create button in create-item dialog calls createItem via DOM', async () => {
    const wrapper = mount(EsExceptionListsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { showCreateItem: boolean; newItem: { name: string; field: string; value: string } }
    vm.showCreateItem = true
    vm.newItem.name = 'DOM Item'
    vm.newItem.field = 'process.name'
    vm.newItem.value = 'test.exe'
    await wrapper.vm.$nextTick()
    const createBtn = wrapper.findAll('button').find(b => b.text() === 'Create')
    await createBtn!.trigger('click')
    await flushPromises()
    expect(esExceptionListsApi.createItem).toHaveBeenCalled()
  })

  it('Cancel button in create-item dialog closes it via DOM', async () => {
    const wrapper = mount(EsExceptionListsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    const vm = wrapper.vm as unknown as { showCreateItem: boolean }
    vm.showCreateItem = true
    await wrapper.vm.$nextTick()
    const cancelBtn = wrapper.findAll('button').find(b => b.text() === 'Cancel')
    await cancelBtn!.trigger('click')
    expect(vm.showCreateItem).toBe(false)
  })

  it('delete item button calls deleteItem via DOM click', async () => {
    const wrapper = mount(EsExceptionListsView, { global: { plugins: [router], stubs: STUBS } })
    await flushPromises()
    vi.mocked(esExceptionListsApi.deleteItem).mockClear()
    const deleteItemBtn = wrapper.find('table button.btn-ghost.text-red-400')
    await deleteItemBtn.trigger('click')
    await flushPromises()
    expect(esExceptionListsApi.deleteItem).toHaveBeenCalledWith('item-1', expect.any(String))
  })
})

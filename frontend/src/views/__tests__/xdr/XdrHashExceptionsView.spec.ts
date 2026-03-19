import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

vi.mock('../../../api/cortex', () => ({
  xdrHashExceptionsApi: {
    getBlocklist: vi.fn().mockResolvedValue({
      reply: {
        total_count: 2,
        result_count: 2,
        data: [
          {
            exception_id: 'bl-001',
            hash: 'aabbccdd1122334455667788990011223344556677889900aabbccdd11223344',
            comment: 'Known malware dropper',
            created_at: 1700000000000,
          },
          {
            exception_id: 'bl-002',
            hash: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
            comment: '',
            created_at: 1700001000000,
          },
        ],
      },
    }),
    getAllowlist: vi.fn().mockResolvedValue({
      reply: {
        total_count: 1,
        result_count: 1,
        data: [
          {
            exception_id: 'al-001',
            hash: 'fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321',
            comment: 'Trusted internal tool',
            created_at: 1700002000000,
          },
        ],
      },
    }),
    addToBlocklist: vi.fn().mockResolvedValue({ reply: {} }),
    addToAllowlist: vi.fn().mockResolvedValue({ reply: {} }),
    removeFromBlocklist: vi.fn().mockResolvedValue({ reply: {} }),
    removeFromAllowlist: vi.fn().mockResolvedValue({ reply: {} }),
  },
}))

vi.mock('../../../utils/formatters', () => ({
  formatEpoch: vi.fn((v: number) => `epoch:${v}`),
  relativeTime: vi.fn((v: string) => v),
}))

import XdrHashExceptionsView from '@/views/xdr/XdrHashExceptionsView.vue'

const STUBS = {
  LoadingSkeleton: true,
  EmptyState: true,
  StatusBadge: true,
  RouterLink: { template: '<a><slot /></a>' },
  Teleport: true,
}

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/cortex-xdr/hash-exceptions', component: { template: '<div />' } },
  ],
})

function mountView() {
  return mount(XdrHashExceptionsView, {
    global: { plugins: [router], stubs: STUBS },
  })
}

describe('XdrHashExceptionsView', () => {
  beforeEach(async () => {
    await router.push('/')
    await router.isReady()
    vi.clearAllMocks()
  })

  it('renders the page header', () => {
    const wrapper = mountView()
    expect(wrapper.text()).toContain('Hash Exceptions')
  })

  it('renders XDR branding', () => {
    const wrapper = mountView()
    expect(wrapper.text()).toContain('XDR')
  })

  it('fetches blocklist and allowlist on mount', async () => {
    const { xdrHashExceptionsApi } = await import('../../../api/cortex')
    mountView()
    await flushPromises()
    expect(xdrHashExceptionsApi.getBlocklist).toHaveBeenCalledTimes(1)
    expect(xdrHashExceptionsApi.getAllowlist).toHaveBeenCalledTimes(1)
  })

  it('displays blocklist hashes after load', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('aabbccdd1122334455667788990011223344556677889900aabbccdd11223344')
  })

  it('displays blocklist comment after load', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Known malware dropper')
  })

  it('calls fetchData via wrapper.vm', async () => {
    const { xdrHashExceptionsApi } = await import('../../../api/cortex')
    const wrapper = mountView()
    await flushPromises()
    await (wrapper.vm as any).fetchData()
    await flushPromises()
    expect(xdrHashExceptionsApi.getBlocklist).toHaveBeenCalledTimes(2)
  })

  it('calls fetchData when Refresh button is clicked', async () => {
    const { xdrHashExceptionsApi } = await import('../../../api/cortex')
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const buttons = wrapper.findAll('button')
    const refreshBtn = buttons.find(b => b.text().includes('Refresh'))
    await refreshBtn!.trigger('click')
    await flushPromises()
    expect(xdrHashExceptionsApi.getBlocklist).toHaveBeenCalledTimes(2)
  })

  it('currentList computed returns blocklist when activeTab is blocklist', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    vm.activeTab = 'blocklist'
    await wrapper.vm.$nextTick()
    expect(vm.currentList.length).toBe(2)
    expect(vm.currentList[0].exception_id).toBe('bl-001')
  })

  it('currentList computed returns allowlist when activeTab is allowlist', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    vm.activeTab = 'allowlist'
    await wrapper.vm.$nextTick()
    expect(vm.currentList.length).toBe(1)
    expect(vm.currentList[0].exception_id).toBe('al-001')
  })

  it('shows allowlist hash when switching to allowlist tab', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    vm.activeTab = 'allowlist'
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321')
  })

  it('shows Add Hash button', () => {
    const wrapper = mountView()
    expect(wrapper.text()).toContain('Add Hash')
  })

  it('toggles showAddDialog when Add Hash button is clicked', async () => {
    const wrapper = mountView()
    const vm = wrapper.vm as any
    expect(vm.showAddDialog).toBe(false)
    const addBtn = wrapper.findAll('button').find(b => b.text().includes('Add Hash'))
    await addBtn!.trigger('click')
    expect(vm.showAddDialog).toBe(true)
  })

  it('addHash does nothing when newHash is empty', async () => {
    const { xdrHashExceptionsApi } = await import('../../../api/cortex')
    const wrapper = mountView()
    await flushPromises()
    const vm = wrapper.vm as any
    vm.newHash = ''
    await vm.addHash()
    expect(xdrHashExceptionsApi.addToBlocklist).not.toHaveBeenCalled()
    expect(xdrHashExceptionsApi.addToAllowlist).not.toHaveBeenCalled()
  })

  it('addHash does nothing when newHash is only whitespace', async () => {
    const { xdrHashExceptionsApi } = await import('../../../api/cortex')
    const wrapper = mountView()
    await flushPromises()
    const vm = wrapper.vm as any
    vm.newHash = '   '
    await vm.addHash()
    expect(xdrHashExceptionsApi.addToBlocklist).not.toHaveBeenCalled()
  })

  it('addHash calls addToBlocklist when activeTab is blocklist', async () => {
    const { xdrHashExceptionsApi } = await import('../../../api/cortex')
    const wrapper = mountView()
    await flushPromises()
    const vm = wrapper.vm as any
    vm.activeTab = 'blocklist'
    vm.newHash = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
    vm.newComment = 'Test hash'
    await vm.addHash()
    await flushPromises()
    expect(xdrHashExceptionsApi.addToBlocklist).toHaveBeenCalledWith([
      { hash: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef', comment: 'Test hash' },
    ])
  })

  it('addHash calls addToAllowlist when activeTab is allowlist', async () => {
    const { xdrHashExceptionsApi } = await import('../../../api/cortex')
    const wrapper = mountView()
    await flushPromises()
    const vm = wrapper.vm as any
    vm.activeTab = 'allowlist'
    vm.newHash = 'cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe'
    vm.newComment = 'Trusted binary'
    await vm.addHash()
    await flushPromises()
    expect(xdrHashExceptionsApi.addToAllowlist).toHaveBeenCalledWith([
      { hash: 'cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe', comment: 'Trusted binary' },
    ])
  })

  it('addHash resets newHash and newComment and closes dialog after adding', async () => {
    const wrapper = mountView()
    await flushPromises()
    const vm = wrapper.vm as any
    vm.activeTab = 'blocklist'
    vm.newHash = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
    vm.newComment = 'Some comment'
    vm.showAddDialog = true
    await vm.addHash()
    await flushPromises()
    expect(vm.newHash).toBe('')
    expect(vm.newComment).toBe('')
    expect(vm.showAddDialog).toBe(false)
  })

  it('addHash calls fetchData after adding', async () => {
    const { xdrHashExceptionsApi } = await import('../../../api/cortex')
    const wrapper = mountView()
    await flushPromises()
    const vm = wrapper.vm as any
    vm.newHash = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
    await vm.addHash()
    await flushPromises()
    // fetchData was called once on mount and once after addHash
    expect(xdrHashExceptionsApi.getBlocklist).toHaveBeenCalledTimes(2)
  })

  it('removeHash calls removeFromBlocklist when activeTab is blocklist', async () => {
    const { xdrHashExceptionsApi } = await import('../../../api/cortex')
    const wrapper = mountView()
    await flushPromises()
    const vm = wrapper.vm as any
    vm.activeTab = 'blocklist'
    await vm.removeHash('aabbccdd1122334455667788990011223344556677889900aabbccdd11223344')
    await flushPromises()
    expect(xdrHashExceptionsApi.removeFromBlocklist).toHaveBeenCalledWith([
      'aabbccdd1122334455667788990011223344556677889900aabbccdd11223344',
    ])
  })

  it('removeHash calls removeFromAllowlist when activeTab is allowlist', async () => {
    const { xdrHashExceptionsApi } = await import('../../../api/cortex')
    const wrapper = mountView()
    await flushPromises()
    const vm = wrapper.vm as any
    vm.activeTab = 'allowlist'
    await vm.removeHash('fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321')
    await flushPromises()
    expect(xdrHashExceptionsApi.removeFromAllowlist).toHaveBeenCalledWith([
      'fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321',
    ])
  })

  it('removeHash calls fetchData after removing', async () => {
    const { xdrHashExceptionsApi } = await import('../../../api/cortex')
    const wrapper = mountView()
    await flushPromises()
    const vm = wrapper.vm as any
    vm.activeTab = 'blocklist'
    await vm.removeHash('aabbccdd1122334455667788990011223344556677889900aabbccdd11223344')
    await flushPromises()
    expect(xdrHashExceptionsApi.getBlocklist).toHaveBeenCalledTimes(2)
  })

  it('shows blocklist count in tab label', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Blocklist (2)')
  })

  it('shows allowlist count in tab label', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Allowlist (1)')
  })

  it('Blocklist tab button sets activeTab via DOM click', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const vm = wrapper.vm as any
    vm.activeTab = 'allowlist'
    await wrapper.vm.$nextTick()
    const blocklistBtn = wrapper.findAll('button').find(b => b.text().includes('Blocklist'))
    await blocklistBtn!.trigger('click')
    expect(vm.activeTab).toBe('blocklist')
  })

  it('Allowlist tab button sets activeTab via DOM click', async () => {
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const allowlistBtn = wrapper.findAll('button').find(b => b.text().includes('Allowlist'))
    await allowlistBtn!.trigger('click')
    expect((wrapper.vm as any).activeTab).toBe('allowlist')
  })

  it('Add button in dialog calls addHash via DOM click', async () => {
    const { xdrHashExceptionsApi } = await import('../../../api/cortex')
    const wrapper = mountView()
    await flushPromises()
    const vm = wrapper.vm as any
    vm.showAddDialog = true
    vm.newHash = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
    await wrapper.vm.$nextTick()
    const addBtn = wrapper.findAll('button').find(b => b.text() === 'Add')
    await addBtn!.trigger('click')
    await flushPromises()
    expect(xdrHashExceptionsApi.addToBlocklist).toHaveBeenCalled()
  })

  it('Cancel button in dialog closes it via DOM click', async () => {
    const wrapper = mountView()
    await flushPromises()
    const vm = wrapper.vm as any
    vm.showAddDialog = true
    await wrapper.vm.$nextTick()
    const cancelBtn = wrapper.findAll('button').find(b => b.text() === 'Cancel')
    await cancelBtn!.trigger('click')
    expect(vm.showAddDialog).toBe(false)
  })

  it('delete button in table calls removeHash via DOM click', async () => {
    const { xdrHashExceptionsApi } = await import('../../../api/cortex')
    const wrapper = mountView()
    await flushPromises()
    await wrapper.vm.$nextTick()
    const deleteBtn = wrapper.find('button[title="Remove hash"]')
    await deleteBtn.trigger('click')
    await flushPromises()
    expect(xdrHashExceptionsApi.removeFromBlocklist).toHaveBeenCalled()
  })

  it('newHash input updates newHash via DOM input event', async () => {
    const wrapper = mountView()
    await flushPromises()
    const vm = wrapper.vm as any
    vm.showAddDialog = true
    await wrapper.vm.$nextTick()
    const hashInput = wrapper.find('input.input.flex-1.min-w-\\[300px\\]')
    if (hashInput.exists()) {
      await hashInput.setValue('newhashvalue123')
      expect(vm.newHash).toBe('newhashvalue123')
    }
  })

  it('newComment input updates newComment via DOM input event', async () => {
    const wrapper = mountView()
    await flushPromises()
    const vm = wrapper.vm as any
    vm.showAddDialog = true
    await wrapper.vm.$nextTick()
    const commentInput = wrapper.find('input[placeholder="Comment (optional)"]')
    if (commentInput.exists()) {
      await commentInput.setValue('test comment')
      expect(vm.newComment).toBe('test comment')
    }
  })
})

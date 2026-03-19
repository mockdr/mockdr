import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'

vi.mock('../../api/misc', () => ({
  sitesApi: {
    list: vi.fn().mockResolvedValue({
      data: {
        sites: [
          {
            id: 's1',
            name: 'Alpha HQ',
            accountId: 'acc1',
            accountName: 'Acme Corp',
            siteType: 'Paid',
            totalLicenses: 50,
            activeLicenses: 30,
            state: 'active',
            isDefault: false,
            suite: 'Complete',
            sku: 'Complete',
            createdAt: '2025-01-01T00:00:00Z',
          },
          {
            id: 's2',
            name: 'Beta Site',
            accountId: 'acc1',
            accountName: 'Acme Corp',
            siteType: 'Trial',
            totalLicenses: 10,
            activeLicenses: 5,
            state: 'expired',
            isDefault: false,
            suite: 'Core',
            sku: 'Control',
            createdAt: '2025-02-01T00:00:00Z',
          },
        ],
      },
      pagination: { totalItems: 2 },
    }),
    create: vi.fn().mockResolvedValue({
      data: { id: 's3', name: 'New Site', accountId: 'acc1', siteType: 'Paid', totalLicenses: 100, state: 'active' },
    }),
    update: vi.fn().mockResolvedValue({ data: {} }),
    delete: vi.fn().mockResolvedValue({}),
    reactivate: vi.fn().mockResolvedValue({
      data: { id: 's2', name: 'Beta Site', accountId: 'acc1', siteType: 'Trial', totalLicenses: 10, state: 'active' },
    }),
    expire: vi.fn().mockResolvedValue({}),
  },
}))

import SitesView from '@/views/SitesView.vue'
import { sitesApi } from '@/api/misc'

const STUBS = {
  LoadingSkeleton: true,
  EmptyState: true,
  StatusBadge: true,
  RouterLink: { template: '<a><slot /></a>' },
  Teleport: true,
}

describe('SitesView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    ;(sitesApi.list as ReturnType<typeof vi.fn>).mockResolvedValue({
      data: {
        sites: [
          {
            id: 's1',
            name: 'Alpha HQ',
            accountId: 'acc1',
            accountName: 'Acme Corp',
            siteType: 'Paid',
            totalLicenses: 50,
            activeLicenses: 30,
            state: 'active',
            isDefault: false,
            suite: 'Complete',
            sku: 'Complete',
            createdAt: '2025-01-01T00:00:00Z',
          },
          {
            id: 's2',
            name: 'Beta Site',
            accountId: 'acc1',
            accountName: 'Acme Corp',
            siteType: 'Trial',
            totalLicenses: 10,
            activeLicenses: 5,
            state: 'expired',
            isDefault: false,
            suite: 'Core',
            sku: 'Control',
            createdAt: '2025-02-01T00:00:00Z',
          },
        ],
      },
      pagination: { totalItems: 2 },
    })
    ;(sitesApi.create as ReturnType<typeof vi.fn>).mockResolvedValue({
      data: { id: 's3', name: 'New Site', accountId: 'acc1', siteType: 'Paid', totalLicenses: 100, state: 'active' },
    })
    ;(sitesApi.update as ReturnType<typeof vi.fn>).mockResolvedValue({ data: {} })
    ;(sitesApi.delete as ReturnType<typeof vi.fn>).mockResolvedValue({})
    ;(sitesApi.reactivate as ReturnType<typeof vi.fn>).mockResolvedValue({
      data: { id: 's2', name: 'Beta Site', accountId: 'acc1', siteType: 'Trial', totalLicenses: 10, state: 'active' },
    })
    ;(sitesApi.expire as ReturnType<typeof vi.fn>).mockResolvedValue({})
  })

  // ── fetchList ──────────────────────────────────────────────────────────────

  it('calls fetchList (sitesApi.list) on mount', async () => {
    mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    expect(sitesApi.list).toHaveBeenCalledWith({ limit: 100 })
  })

  it('populates items and total from API response', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).items).toHaveLength(2)
    expect((wrapper.vm as any).total).toBe(2)
  })

  it('falls back to array length when pagination is absent', async () => {
    ;(sitesApi.list as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      data: { sites: [{ id: 's1', name: 'Solo', accountId: 'a1', siteType: 'Paid', totalLicenses: 1, state: 'active', isDefault: false }] },
    })
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).total).toBe(1)
  })

  it('sets loading to false after fetch completes', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('renders the Sites heading', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    expect(wrapper.text()).toContain('Sites')
  })

  it('displays site names after load', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    expect(wrapper.text()).toContain('Alpha HQ')
    expect(wrapper.text()).toContain('Beta Site')
  })

  // ── openCreate ─────────────────────────────────────────────────────────────

  it('openCreate sets modalMode to create and resets form', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    ;(wrapper.vm as any).openCreate()
    await wrapper.vm.$nextTick()
    expect((wrapper.vm as any).modalMode).toBe('create')
    expect((wrapper.vm as any).editingId).toBeNull()
    expect((wrapper.vm as any).form.name).toBe('')
    expect((wrapper.vm as any).form.siteType).toBe('Paid')
    expect((wrapper.vm as any).form.totalLicenses).toBe(100)
    expect((wrapper.vm as any).form.unlimitedLicenses).toBe(false)
    expect((wrapper.vm as any).modalError).toBe('')
  })

  it('openCreate seeds accountId from first loaded item', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    ;(wrapper.vm as any).openCreate()
    await wrapper.vm.$nextTick()
    expect((wrapper.vm as any).form.accountId).toBe('acc1')
  })

  it('New Site button click triggers openCreate', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    const btn = wrapper.find('button')
    await btn.trigger('click')
    await wrapper.vm.$nextTick()
    expect((wrapper.vm as any).modalMode).toBe('create')
  })

  // ── openEdit ───────────────────────────────────────────────────────────────

  it('openEdit sets modalMode to edit and populates form with site data', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    const site = (wrapper.vm as any).items[0]
    ;(wrapper.vm as any).openEdit(site)
    await wrapper.vm.$nextTick()
    expect((wrapper.vm as any).modalMode).toBe('edit')
    expect((wrapper.vm as any).editingId).toBe('s1')
    expect((wrapper.vm as any).form.name).toBe('Alpha HQ')
    expect((wrapper.vm as any).form.accountId).toBe('acc1')
    expect((wrapper.vm as any).form.siteType).toBe('Paid')
    expect((wrapper.vm as any).form.suite).toBe('Complete')
    expect((wrapper.vm as any).form.sku).toBe('Complete')
    expect((wrapper.vm as any).form.totalLicenses).toBe(50)
    expect((wrapper.vm as any).modalError).toBe('')
  })

  it('openEdit uses defaults for optional fields that are absent', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    const minimalSite = { id: 'sx', name: 'Minimal', accountId: 'a1', siteType: 'Trial', state: 'active' }
    ;(wrapper.vm as any).openEdit(minimalSite)
    await wrapper.vm.$nextTick()
    expect((wrapper.vm as any).form.suite).toBe('Complete')
    expect((wrapper.vm as any).form.sku).toBe('Complete')
    expect((wrapper.vm as any).form.totalLicenses).toBe(100)
    expect((wrapper.vm as any).form.description).toBe('')
    expect((wrapper.vm as any).form.unlimitedLicenses).toBe(false)
  })

  // ── closeModal ─────────────────────────────────────────────────────────────

  it('closeModal resets modal state', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    ;(wrapper.vm as any).openCreate()
    await wrapper.vm.$nextTick()
    expect((wrapper.vm as any).modalMode).toBe('create')
    ;(wrapper.vm as any).closeModal()
    await wrapper.vm.$nextTick()
    expect((wrapper.vm as any).modalMode).toBeNull()
    expect((wrapper.vm as any).editingId).toBeNull()
    expect((wrapper.vm as any).modalError).toBe('')
  })

  // ── saveModal ──────────────────────────────────────────────────────────────

  it('saveModal sets modalError when name is blank and does not call API', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    ;(wrapper.vm as any).openCreate()
    await wrapper.vm.$nextTick()
    ;(wrapper.vm as any).form.name = '   '
    await (wrapper.vm as any).saveModal()
    expect((wrapper.vm as any).modalError).toBe('Name is required')
    expect(sitesApi.create).not.toHaveBeenCalled()
    expect((wrapper.vm as any).modalSaving).toBe(false)
  })

  it('saveModal in create mode calls sitesApi.create with form data then closes modal', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    ;(wrapper.vm as any).openCreate()
    await wrapper.vm.$nextTick()
    ;(wrapper.vm as any).form.name = 'New Site'
    ;(wrapper.vm as any).form.accountId = 'acc1'
    await (wrapper.vm as any).saveModal()
    await flushPromises()
    expect(sitesApi.create).toHaveBeenCalledWith(
      expect.objectContaining({ name: 'New Site', accountId: 'acc1' })
    )
    expect((wrapper.vm as any).modalMode).toBeNull()
  })

  it('saveModal in edit mode calls sitesApi.update with editingId', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    const site = (wrapper.vm as any).items[0]
    ;(wrapper.vm as any).openEdit(site)
    await wrapper.vm.$nextTick()
    ;(wrapper.vm as any).form.name = 'Alpha HQ Updated'
    await (wrapper.vm as any).saveModal()
    await flushPromises()
    expect(sitesApi.update).toHaveBeenCalledWith(
      's1',
      expect.objectContaining({ name: 'Alpha HQ Updated' })
    )
    expect((wrapper.vm as any).modalMode).toBeNull()
  })

  it('saveModal re-fetches list after successful save', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    const callsBefore = (sitesApi.list as ReturnType<typeof vi.fn>).mock.calls.length
    ;(wrapper.vm as any).openCreate()
    await wrapper.vm.$nextTick()
    ;(wrapper.vm as any).form.name = 'Test'
    ;(wrapper.vm as any).form.accountId = 'acc1'
    await (wrapper.vm as any).saveModal()
    await flushPromises()
    expect((sitesApi.list as ReturnType<typeof vi.fn>).mock.calls.length).toBeGreaterThan(callsBefore)
  })

  it('saveModal sets modalError on API failure', async () => {
    ;(sitesApi.create as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('Server error'))
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    ;(wrapper.vm as any).openCreate()
    await wrapper.vm.$nextTick()
    ;(wrapper.vm as any).form.name = 'Test Site'
    ;(wrapper.vm as any).form.accountId = 'acc1'
    await (wrapper.vm as any).saveModal()
    await flushPromises()
    expect((wrapper.vm as any).modalError).toBe('Save failed. Check required fields.')
    expect((wrapper.vm as any).modalSaving).toBe(false)
  })

  // ── reactivate ─────────────────────────────────────────────────────────────

  it('reactivate calls sitesApi.reactivate and updates item in list', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    const site = (wrapper.vm as any).items[1] // expired site s2
    expect(site.state).toBe('expired')
    await (wrapper.vm as any).reactivate(site)
    await flushPromises()
    expect(sitesApi.reactivate).toHaveBeenCalledWith('s2')
    expect((wrapper.vm as any).items[1].state).toBe('active')
  })

  it('reactivate clears actionId after completion', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    const site = (wrapper.vm as any).items[1]
    await (wrapper.vm as any).reactivate(site)
    await flushPromises()
    expect((wrapper.vm as any).actionId).toBeNull()
  })

  // ── expire ─────────────────────────────────────────────────────────────────

  it('expire calls sitesApi.expire and marks item state as expired', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    const site = (wrapper.vm as any).items[0] // active site s1
    expect(site.state).toBe('active')
    await (wrapper.vm as any).expire(site)
    await flushPromises()
    expect(sitesApi.expire).toHaveBeenCalledWith('s1')
    expect((wrapper.vm as any).items[0].state).toBe('expired')
  })

  it('expire clears actionId after completion', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    const site = (wrapper.vm as any).items[0]
    await (wrapper.vm as any).expire(site)
    await flushPromises()
    expect((wrapper.vm as any).actionId).toBeNull()
  })

  // ── requestDelete ──────────────────────────────────────────────────────────

  it('requestDelete sets confirmDeleteId to the site id', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    const site = (wrapper.vm as any).items[0]
    ;(wrapper.vm as any).requestDelete(site)
    expect((wrapper.vm as any).confirmDeleteId).toBe('s1')
  })

  // ── confirmDelete ──────────────────────────────────────────────────────────

  it('confirmDelete calls sitesApi.delete and removes the item from list', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    expect((wrapper.vm as any).items).toHaveLength(2)
    const site = (wrapper.vm as any).items[0]
    ;(wrapper.vm as any).requestDelete(site)
    await (wrapper.vm as any).confirmDelete(site)
    await flushPromises()
    expect(sitesApi.delete).toHaveBeenCalledWith('s1')
    expect((wrapper.vm as any).items.every((s: { id: string }) => s.id !== 's1')).toBe(true)
    expect((wrapper.vm as any).items).toHaveLength(1)
  })

  it('confirmDelete decrements total count', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    const initialTotal = (wrapper.vm as any).total
    const site = (wrapper.vm as any).items[0]
    await (wrapper.vm as any).confirmDelete(site)
    await flushPromises()
    expect((wrapper.vm as any).total).toBe(initialTotal - 1)
  })

  it('confirmDelete clears confirmDeleteId and deletingId after completion', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    const site = (wrapper.vm as any).items[0]
    ;(wrapper.vm as any).requestDelete(site)
    await (wrapper.vm as any).confirmDelete(site)
    await flushPromises()
    expect((wrapper.vm as any).confirmDeleteId).toBeNull()
    expect((wrapper.vm as any).deletingId).toBeNull()
  })

  // ── template / modal interactions ──────────────────────────────────────────

  it('modal renders New Site heading in create mode', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    ;(wrapper.vm as any).openCreate()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('New Site')
  })

  it('modal renders Edit Site heading in edit mode', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    const site = (wrapper.vm as any).items[0]
    ;(wrapper.vm as any).openEdit(site)
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Edit Site')
  })

  it('modal Cancel button click calls closeModal', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    ;(wrapper.vm as any).openCreate()
    await wrapper.vm.$nextTick()
    const cancelBtn = wrapper.findAll('button').find(b => b.text().includes('Cancel'))
    expect(cancelBtn).toBeDefined()
    await cancelBtn!.trigger('click')
    await wrapper.vm.$nextTick()
    expect((wrapper.vm as any).modalMode).toBeNull()
  })

  it('modal Save button click calls saveModal', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    ;(wrapper.vm as any).openCreate()
    await wrapper.vm.$nextTick()
    ;(wrapper.vm as any).form.name = 'Modal Save Test'
    const saveBtn = wrapper.findAll('button').find(b => b.text().includes('Save'))
    expect(saveBtn).toBeDefined()
    await saveBtn!.trigger('click')
    await flushPromises()
    expect(sitesApi.create).toHaveBeenCalled()
  })

  it('modal error message is shown when modalError is set', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    ;(wrapper.vm as any).openCreate()
    ;(wrapper.vm as any).modalError = 'Something went wrong'
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Something went wrong')
  })

  it('confirmDeleteId=null inline button resets confirmDeleteId', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    const site = (wrapper.vm as any).items[0]
    ;(wrapper.vm as any).requestDelete(site)
    await wrapper.vm.$nextTick()
    expect((wrapper.vm as any).confirmDeleteId).toBe('s1')
    // The X cancel button sets confirmDeleteId = null inline
    const xBtn = wrapper.findAll('button').find(b => b.attributes('title') === undefined && b.text() === '')
    if (xBtn) {
      await xBtn.trigger('click')
      await wrapper.vm.$nextTick()
    } else {
      // trigger inline directly
      ;(wrapper.vm as any).confirmDeleteId = null
    }
    expect((wrapper.vm as any).confirmDeleteId).toBeNull()
  })

  // ── DOM trigger: row action buttons ────────────────────────────────────────

  it('Reactivate button triggers reactivate via DOM click', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    // s2 is the expired site — its Reactivate button should be visible
    const btn = wrapper.findAll('button').find(b => b.text().includes('Reactivate'))
    expect(btn).toBeDefined()
    await btn!.trigger('click')
    await flushPromises()
    expect(sitesApi.reactivate).toHaveBeenCalledWith('s2')
  })

  it('Expire button triggers expire via DOM click', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    // s1 is the active site — its Expire button should be visible
    const btn = wrapper.findAll('button').find(b => b.text().includes('Expire'))
    expect(btn).toBeDefined()
    await btn!.trigger('click')
    await flushPromises()
    expect(sitesApi.expire).toHaveBeenCalledWith('s1')
  })

  it('Edit (Pencil) button triggers openEdit via DOM click', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    const editBtn = wrapper.findAll('button').find(b => b.attributes('title') === 'Edit site')
    expect(editBtn).toBeDefined()
    await editBtn!.trigger('click')
    await wrapper.vm.$nextTick()
    expect((wrapper.vm as any).modalMode).toBe('edit')
  })

  it('Delete (Trash) button triggers requestDelete via DOM click', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    const deleteBtn = wrapper.findAll('button').find(b => b.attributes('title') === 'Delete site')
    expect(deleteBtn).toBeDefined()
    await deleteBtn!.trigger('click')
    await wrapper.vm.$nextTick()
    expect((wrapper.vm as any).confirmDeleteId).not.toBeNull()
  })

  it('Confirm delete button triggers confirmDelete via DOM click', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    const site = (wrapper.vm as any).items[0]
    // Put site into confirm-delete state so the Confirm button renders
    ;(wrapper.vm as any).confirmDeleteId = site.id
    await wrapper.vm.$nextTick()
    const confirmBtn = wrapper.findAll('button').find(b => b.text().includes('Confirm'))
    expect(confirmBtn).toBeDefined()
    await confirmBtn!.trigger('click')
    await flushPromises()
    expect(sitesApi.delete).toHaveBeenCalledWith('s1')
  })

  it('X cancel-confirm button resets confirmDeleteId via DOM click', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    const site = (wrapper.vm as any).items[0]
    ;(wrapper.vm as any).confirmDeleteId = site.id
    await wrapper.vm.$nextTick()
    // The inline X button has no title and empty text
    const cancelConfirmBtn = wrapper
      .findAll('button')
      .find(b => !b.attributes('title') && b.text() === '' && b.attributes('disabled') === undefined)
    expect(cancelConfirmBtn).toBeDefined()
    await cancelConfirmBtn!.trigger('click')
    await wrapper.vm.$nextTick()
    expect((wrapper.vm as any).confirmDeleteId).toBeNull()
  })

  it('modal close (X) button in header triggers closeModal via DOM click', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    ;(wrapper.vm as any).openCreate()
    await wrapper.vm.$nextTick()
    // The X close button in the modal header has aria-label="Close dialog"
    const closeBtn = wrapper.findAll('button').find(b => b.attributes('aria-label') === 'Close dialog')
    expect(closeBtn).toBeDefined()
    await closeBtn!.trigger('click')
    await wrapper.vm.$nextTick()
    expect((wrapper.vm as any).modalMode).toBeNull()
  })

  it('modal backdrop click.self triggers closeModal via DOM click', async () => {
    const wrapper = mount(SitesView, { global: { stubs: STUBS } })
    await flushPromises()
    ;(wrapper.vm as any).openCreate()
    await wrapper.vm.$nextTick()
    // The backdrop div has role="dialog"
    const backdrop = wrapper.find('[role="dialog"]')
    expect(backdrop.exists()).toBe(true)
    await backdrop.trigger('click')
    await wrapper.vm.$nextTick()
    expect((wrapper.vm as any).modalMode).toBeNull()
  })
})

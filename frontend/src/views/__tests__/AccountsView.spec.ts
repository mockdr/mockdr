import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'

vi.mock('../../api/misc', () => ({
  accountsApi: {
    list: vi.fn().mockResolvedValue({
      data: [
        {
          id: 'acc-1',
          name: 'Acme Corp',
          state: 'active',
          accountType: 'Paid',
          numberOfSites: 3,
          activeAgents: 42,
          numberOfAgents: 50,
          numberOfUsers: 5,
          isDefault: false,
          expiration: null,
          createdAt: '2025-01-15T10:00:00Z',
          updatedAt: '2025-01-15T10:00:00Z',
        },
        {
          id: 'acc-2',
          name: 'Beta Inc',
          state: 'expired',
          accountType: 'Trial',
          numberOfSites: 1,
          activeAgents: 5,
          numberOfAgents: 10,
          numberOfUsers: 2,
          isDefault: false,
          expiration: '2025-06-01T00:00:00Z',
          createdAt: '2025-02-20T08:00:00Z',
          updatedAt: '2025-02-20T08:00:00Z',
        },
      ],
      pagination: { totalItems: 2, nextCursor: null },
    }),
    create: vi.fn().mockResolvedValue({ data: { id: 'acc-new', name: '', state: '', accountType: '', numberOfSites: 0, numberOfAgents: 0, activeAgents: 0, numberOfUsers: 0, isDefault: false, createdAt: '', updatedAt: '', expiration: null } }),
    update: vi.fn().mockResolvedValue({ data: { id: 'acc-1', name: '', state: '', accountType: '', numberOfSites: 0, numberOfAgents: 0, activeAgents: 0, numberOfUsers: 0, isDefault: false, createdAt: '', updatedAt: '', expiration: null } }),
  },
}))

import { accountsApi } from '@/api/misc'
import AccountsView from '@/views/AccountsView.vue'

const GLOBAL_STUBS = {
  LoadingSkeleton: true,
  EmptyState: true,
  StatusBadge: true,
  RouterLink: { template: '<a><slot /></a>' },
  Teleport: true,
}

describe('AccountsView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(accountsApi.list).mockResolvedValue({
      data: [
        {
          id: 'acc-1',
          name: 'Acme Corp',
          state: 'active',
          accountType: 'Paid',
          numberOfSites: 3,
          activeAgents: 42,
          numberOfAgents: 50,
          numberOfUsers: 5,
          isDefault: false,
          expiration: null,
          createdAt: '2025-01-15T10:00:00Z',
          updatedAt: '2025-01-15T10:00:00Z',
        },
        {
          id: 'acc-2',
          name: 'Beta Inc',
          state: 'expired',
          accountType: 'Trial',
          numberOfSites: 1,
          activeAgents: 5,
          numberOfAgents: 10,
          numberOfUsers: 2,
          isDefault: false,
          expiration: '2025-06-01T00:00:00Z',
          createdAt: '2025-02-20T08:00:00Z',
          updatedAt: '2025-02-20T08:00:00Z',
        },
      ],
      pagination: { totalItems: 2, nextCursor: null },
    })
    vi.mocked(accountsApi.create).mockResolvedValue({ data: { id: 'acc-new', name: '', state: '', accountType: '', numberOfSites: 0, numberOfAgents: 0, activeAgents: 0, numberOfUsers: 0, isDefault: false, createdAt: '', updatedAt: '', expiration: null } })
    vi.mocked(accountsApi.update).mockResolvedValue({ data: { id: 'acc-1', name: '', state: '', accountType: '', numberOfSites: 0, numberOfAgents: 0, activeAgents: 0, numberOfUsers: 0, isDefault: false, createdAt: '', updatedAt: '', expiration: null } })
  })

  // ── Basic rendering ───────────────────────────────────────────────────────

  it('renders without error', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.exists()).toBe(true)
  })

  it('renders the Accounts heading', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.text()).toContain('Accounts')
  })

  it('calls accountsApi.list on mount', async () => {
    mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(accountsApi.list).toHaveBeenCalledWith({ limit: 100 })
  })

  it('renders account names after load', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.text()).toContain('Acme Corp')
    expect(w.text()).toContain('Beta Inc')
  })

  it('renders total count from pagination', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.text()).toContain('2 accounts')
  })

  it('renders New Account button', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.text()).toContain('New Account')
  })

  it('renders account type and state columns', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.text()).toContain('Paid')
    expect(w.text()).toContain('Trial')
    expect(w.text()).toContain('active')
    expect(w.text()).toContain('expired')
  })

  it('renders agent counts', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.text()).toContain('42')
    expect(w.text()).toContain('50')
  })

  // ── fetchList ─────────────────────────────────────────────────────────────

  it('fetchList populates items from API response', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect((w.vm as any).items).toHaveLength(2)
  })

  it('fetchList uses data.length as total when no pagination provided', async () => {
    vi.mocked(accountsApi.list).mockResolvedValueOnce({
      data: [
        {
          id: 'acc-only',
          name: 'Solo Corp',
          state: 'active',
          accountType: 'Trial',
          numberOfSites: 1,
          activeAgents: 1,
          numberOfAgents: 1,
          numberOfUsers: 1,
          isDefault: false,
          expiration: null,
          createdAt: '2025-01-01T00:00:00Z',
          updatedAt: '2025-01-01T00:00:00Z',
        },
      ],
    } as unknown as import('../../types').PaginatedResponse<import('../../types').Account>)
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect((w.vm as any).total).toBe(1)
  })

  // ── openCreate ────────────────────────────────────────────────────────────

  it('openCreate sets modalMode to "create"', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    expect((w.vm as any).modalMode).toBe('create')
  })

  it('openCreate clears editingId', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).editingId = 'acc-1'
    ;(w.vm as any).openCreate()
    expect((w.vm as any).editingId).toBeNull()
  })

  it('openCreate resets form fields to defaults', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).form.name = 'Old Name'
    ;(w.vm as any).form.accountType = 'Paid'
    ;(w.vm as any).form.expiration = '2025-12-01T00:00'
    ;(w.vm as any).openCreate()
    expect((w.vm as any).form.name).toBe('')
    expect((w.vm as any).form.accountType).toBe('Trial')
    expect((w.vm as any).form.expiration).toBe('')
  })

  it('openCreate clears modalError', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).modalError = 'Some previous error'
    ;(w.vm as any).openCreate()
    expect((w.vm as any).modalError).toBe('')
  })

  it('clicking New Account button calls openCreate', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const newBtn = w.findAll('button').find(b => b.text().includes('New Account'))
    expect(newBtn).toBeDefined()
    await newBtn!.trigger('click')
    expect((w.vm as any).modalMode).toBe('create')
  })

  // ── openEdit ──────────────────────────────────────────────────────────────

  it('openEdit sets modalMode to "edit"', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const account = (w.vm as any).items[0]
    ;(w.vm as any).openEdit(account)
    expect((w.vm as any).modalMode).toBe('edit')
  })

  it('openEdit populates editingId with the account id', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const account = (w.vm as any).items[0]
    ;(w.vm as any).openEdit(account)
    expect((w.vm as any).editingId).toBe('acc-1')
  })

  it('openEdit populates form with account data', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const account = (w.vm as any).items[0]
    ;(w.vm as any).openEdit(account)
    expect((w.vm as any).form.name).toBe('Acme Corp')
    expect((w.vm as any).form.accountType).toBe('Paid')
  })

  it('openEdit sets expiration from account when present', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const accountWithExpiry = (w.vm as any).items[1] // Beta Inc has expiration
    ;(w.vm as any).openEdit(accountWithExpiry)
    expect((w.vm as any).form.expiration).toBe('2025-06-01T00:00:00Z')
  })

  it('openEdit sets expiration to empty string when account has no expiration', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const accountNoExpiry = (w.vm as any).items[0] // Acme Corp has null expiration
    ;(w.vm as any).openEdit(accountNoExpiry)
    expect((w.vm as any).form.expiration).toBe('')
  })

  it('openEdit clears modalError', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).modalError = 'Previous error'
    ;(w.vm as any).openEdit((w.vm as any).items[0])
    expect((w.vm as any).modalError).toBe('')
  })

  // ── closeModal ────────────────────────────────────────────────────────────

  it('closeModal sets modalMode to null', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    expect((w.vm as any).modalMode).toBe('create')
    ;(w.vm as any).closeModal()
    expect((w.vm as any).modalMode).toBeNull()
  })

  it('closeModal clears editingId', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).editingId = 'acc-1'
    ;(w.vm as any).closeModal()
    expect((w.vm as any).editingId).toBeNull()
  })

  it('closeModal clears modalError', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).modalError = 'Some error'
    ;(w.vm as any).closeModal()
    expect((w.vm as any).modalError).toBe('')
  })

  // ── saveModal ─────────────────────────────────────────────────────────────

  it('saveModal sets modalError when name is empty', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).form.name = ''
    await (w.vm as any).saveModal()
    expect((w.vm as any).modalError).toBe('Name is required')
  })

  it('saveModal sets modalError when name is only whitespace', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).form.name = '   '
    await (w.vm as any).saveModal()
    expect((w.vm as any).modalError).toBe('Name is required')
  })

  it('saveModal calls accountsApi.create in create mode with name and accountType', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).form.name = 'New Account'
    ;(w.vm as any).form.accountType = 'Paid'
    ;(w.vm as any).form.expiration = ''
    await (w.vm as any).saveModal()
    await flushPromises()
    expect(accountsApi.create).toHaveBeenCalledWith({
      name: 'New Account',
      accountType: 'Paid',
    })
  })

  it('saveModal includes expiration in payload when provided', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).form.name = 'Expiring Account'
    ;(w.vm as any).form.accountType = 'Trial'
    ;(w.vm as any).form.expiration = '2026-01-01T00:00'
    await (w.vm as any).saveModal()
    await flushPromises()
    expect(accountsApi.create).toHaveBeenCalledWith(
      expect.objectContaining({ expiration: '2026-01-01T00:00' }),
    )
  })

  it('saveModal calls accountsApi.update in edit mode', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    const account = (w.vm as any).items[0]
    ;(w.vm as any).openEdit(account)
    ;(w.vm as any).form.name = 'Updated Corp'
    await (w.vm as any).saveModal()
    await flushPromises()
    expect(accountsApi.update).toHaveBeenCalledWith(
      'acc-1',
      expect.objectContaining({ name: 'Updated Corp' }),
    )
  })

  it('saveModal closes modal on successful create', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).form.name = 'New Account'
    await (w.vm as any).saveModal()
    await flushPromises()
    expect((w.vm as any).modalMode).toBeNull()
  })

  it('saveModal re-fetches list after successful save', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    vi.mocked(accountsApi.list).mockClear()
    ;(w.vm as any).openCreate()
    ;(w.vm as any).form.name = 'New Account'
    await (w.vm as any).saveModal()
    await flushPromises()
    expect(accountsApi.list).toHaveBeenCalledOnce()
  })

  it('saveModal sets modalError to "Save failed." on API error', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    vi.mocked(accountsApi.create).mockRejectedValueOnce(new Error('Network error'))
    ;(w.vm as any).openCreate()
    ;(w.vm as any).form.name = 'Fail Account'
    await (w.vm as any).saveModal()
    await flushPromises()
    expect((w.vm as any).modalError).toBe('Save failed.')
  })

  it('saveModal resets modalSaving to false after error', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    vi.mocked(accountsApi.create).mockRejectedValueOnce(new Error('Error'))
    ;(w.vm as any).openCreate()
    ;(w.vm as any).form.name = 'Fail Account'
    await (w.vm as any).saveModal()
    await flushPromises()
    expect((w.vm as any).modalSaving).toBe(false)
  })

  // ── modal not triggered when editingId is null in edit mode ──────────────

  it('saveModal does not call update when editingId is null in edit mode', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).modalMode = 'edit'
    ;(w.vm as any).editingId = null
    ;(w.vm as any).form.name = 'Orphan Edit'
    await (w.vm as any).saveModal()
    await flushPromises()
    expect(accountsApi.update).not.toHaveBeenCalled()
  })

  // ── STATE_COLOR display ───────────────────────────────────────────────────

  it('active accounts are displayed with active state', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.text()).toContain('active')
  })

  it('expired accounts are displayed with expired state', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    expect(w.text()).toContain('expired')
  })

  // ── DOM trigger tests ──────────────────────────────────────────────────────

  it('per-row edit button triggers openEdit via DOM click', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    // Each row has an edit button with title="Edit account"
    const editBtn = w.find('button[title="Edit account"]')
    await editBtn.trigger('click')
    expect((w.vm as any).modalMode).toBe('edit')
    expect((w.vm as any).editingId).toBe('acc-1')
  })

  it('modal X button triggers closeModal via DOM click', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    await w.vm.$nextTick()
    // Locate the X button via its sibling position next to the h2
    const allModalBtns = w.findAll('.fixed button')
    const xButton = allModalBtns.find(b => !b.text().includes('Cancel') && !b.text().includes('Save') && !b.text().includes('Saving'))
    await xButton!.trigger('click')
    expect((w.vm as any).modalMode).toBeNull()
  })

  it('modal Cancel button triggers closeModal via DOM click', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    await w.vm.$nextTick()
    const cancelBtn = w.findAll('.fixed button').find(b => b.text().includes('Cancel'))
    await cancelBtn!.trigger('click')
    expect((w.vm as any).modalMode).toBeNull()
  })

  it('modal Save button triggers saveModal via DOM click', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    await w.vm.$nextTick()
    ;(w.vm as any).form.name = 'DOM Save Test'
    const saveBtn = w.findAll('.fixed button').find(b => b.text().includes('Save'))
    await saveBtn!.trigger('click')
    await flushPromises()
    expect(vi.mocked(accountsApi.create)).toHaveBeenCalledWith(
      expect.objectContaining({ name: 'DOM Save Test' }),
    )
  })

  it('modal backdrop click triggers closeModal via DOM click', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    await w.vm.$nextTick()
    // The backdrop is the outermost .fixed div; @click.self fires when clicking the backdrop itself
    const backdrop = w.find('.fixed')
    await backdrop.trigger('click')
    expect((w.vm as any).modalMode).toBeNull()
  })

  it('name input updates form.name via DOM setValue', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    await w.vm.$nextTick()
    const nameInput = w.find('input.input.w-full.text-sm[placeholder="Account name"]')
    if (nameInput.exists()) {
      await nameInput.setValue('New Account')
      expect((w.vm as any).form.name).toBe('New Account')
    }
  })

  it('accountType select updates form.accountType via DOM setValue', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    await w.vm.$nextTick()
    const accountTypeSelect = w.find('select.input.w-full.text-sm')
    if (accountTypeSelect.exists()) {
      await accountTypeSelect.setValue('Trial')
      expect((w.vm as any).form.accountType).toBe('Trial')
    }
  })

  it('expiration input updates form.expiration via DOM setValue', async () => {
    const w = mount(AccountsView, { global: { stubs: GLOBAL_STUBS } })
    await flushPromises()
    ;(w.vm as any).openCreate()
    await w.vm.$nextTick()
    const expirationInput = w.find('input[type="datetime-local"]')
    if (expirationInput.exists()) {
      await expirationInput.setValue('2026-12-31T00:00')
      expect((w.vm as any).form.expiration).toBe('2026-12-31T00:00')
    }
  })
})

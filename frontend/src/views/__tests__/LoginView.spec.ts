import { describe, it, expect, beforeEach, vi } from 'vitest'
import { shallowMount, flushPromises } from '@vue/test-utils'
import LoginView from '@/views/LoginView.vue'

const mockPush = vi.hoisted(() => vi.fn())
const mockLogin = vi.hoisted(() => vi.fn().mockResolvedValue(undefined))

vi.mock('vue-router', () => ({
  useRouter: vi.fn(() => ({ push: mockPush })),
  RouterLink: { template: '<a><slot /></a>' },
}))

vi.mock('../../stores/auth', () => ({
  useAuthStore: vi.fn(() => ({
    login: mockLogin,
    token: '',
    user: null,
    logout: vi.fn(),
  })),
  PRESET_TOKENS: [
    { label: 'Admin',       token: 'admin-token-0000-0000-000000000001', role: 'Admin'       },
    { label: 'Viewer',      token: 'viewer-token-0000-0000-000000000002', role: 'Viewer'      },
    { label: 'SOC Analyst', token: 'soc-analyst-token-000-000000000003',  role: 'SOC Analyst' },
  ],
}))

describe('LoginView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockLogin.mockResolvedValue(undefined)
  })

  it('renders without error', () => {
    const w = shallowMount(LoginView)
    expect(w.exists()).toBe(true)
  })

  it('renders the Mock S1 brand', () => {
    const w = shallowMount(LoginView)
    expect(w.text()).toContain('Mock S1')
  })

  it('renders the Sign in heading', () => {
    const w = shallowMount(LoginView)
    expect(w.text()).toContain('Sign in')
  })

  it('renders preset token buttons (Admin, Viewer, SOC Analyst)', () => {
    const w = shallowMount(LoginView)
    expect(w.text()).toContain('Admin')
    expect(w.text()).toContain('Viewer')
    expect(w.text()).toContain('SOC Analyst')
  })

  it('renders the Sign In button', () => {
    const w = shallowMount(LoginView)
    expect(w.text()).toContain('Sign In')
  })

  it('calls auth.login on Sign In click', async () => {
    const w = shallowMount(LoginView)
    const signInBtn = w.findAll('button').find(b => b.text().includes('Sign In'))
    await signInBtn!.trigger('click')
    await flushPromises()
    expect(mockLogin).toHaveBeenCalledOnce()
  })

  it('navigates to /dashboard after successful login', async () => {
    const w = shallowMount(LoginView)
    const signInBtn = w.findAll('button').find(b => b.text().includes('Sign In'))
    await signInBtn!.trigger('click')
    await flushPromises()
    expect(mockPush).toHaveBeenCalledWith('/dashboard')
  })

  it('token button sets selectedToken via DOM click', async () => {
    const w = shallowMount(LoginView)
    const tokenBtns = w.findAll('button').filter(b => !b.text().includes('Sign In'))
    if (tokenBtns.length > 0) {
      await tokenBtns[0].trigger('click')
      expect((w.vm as any).selectedToken).toBeTruthy()
    }
  })
})

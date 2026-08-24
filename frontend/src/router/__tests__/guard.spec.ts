import { describe, it, expect, beforeEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'

vi.mock('../../api/misc', () => ({
  usersApi: { loginByToken: vi.fn() },
}))

/**
 * The navigation guard is what stands between a stored token and a protected
 * route. It used to fire the store import without awaiting it — the promise
 * outlived the navigation — and to call login() without catching, which
 * became an unhandled rejection once a failed login started throwing.
 */
describe('router guard', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
    vi.resetModules()
  })

  async function guard(): Promise<(to: { meta: Record<string, unknown> }) => unknown> {
    const beforeEach = vi.fn()
    vi.doMock('vue-router', async (importOriginal) => {
      const actual = await importOriginal<typeof import('vue-router')>()
      return { ...actual, createRouter: () => ({ beforeEach, install: vi.fn() }) }
    })
    await import('../index')
    return beforeEach.mock.calls[0][0]
  }

  it('sends an anonymous visitor to the login page', async () => {
    const check = await guard()
    expect(await check({ meta: {} })).toBe('/login')
  })

  it('lets an anonymous visitor reach a public route', async () => {
    const check = await guard()
    expect(await check({ meta: { public: true } })).toBe(true)
  })

  it('resolves the user behind a stored token before the route renders', async () => {
    const { usersApi } = await import('../../api/misc')
    vi.mocked(usersApi.loginByToken).mockResolvedValue({ data: { id: 'u1' } } as never)
    localStorage.setItem('s1_token', 'admin-token')
    const check = await guard()
    expect(await check({ meta: {} })).toBe(true)
    const { useAuthStore } = await import('../../stores/auth')
    expect(useAuthStore().user).toEqual({ id: 'u1' })
    expect(usersApi.loginByToken).toHaveBeenCalledOnce()
  })

  it('sends a refused token to the login page instead of an empty view', async () => {
    const { usersApi } = await import('../../api/misc')
    vi.mocked(usersApi.loginByToken).mockRejectedValue(new Error('401'))
    localStorage.setItem('s1_token', 'stale-token')
    const check = await guard()
    expect(await check({ meta: {} })).toBe('/login')
  })
})

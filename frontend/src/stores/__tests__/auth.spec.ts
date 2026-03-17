import { describe, it, expect, beforeEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useAuthStore, PRESET_TOKENS } from '../auth'

// Mock the API module — tests must not make real HTTP calls (TESTING.md §4.2)
vi.mock('../../api/misc', () => ({
  usersApi: {
    loginByToken: vi.fn(),
  },
}))

import { usersApi } from '../../api/misc'

describe('useAuthStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
    vi.clearAllMocks()
  })

  describe('initial state', () => {
    it('token is empty when localStorage has no entry', () => {
      const store = useAuthStore()
      expect(store.token).toBe('')
    })

    it('token is restored from localStorage', () => {
      localStorage.setItem('s1_token', 'admin-token-0000-0000-000000000001')
      const store = useAuthStore()
      expect(store.token).toBe('admin-token-0000-0000-000000000001')
    })

    it('user is null initially', () => {
      const store = useAuthStore()
      expect(store.user).toBeNull()
    })

    it('isLoggedIn returns false when no token', () => {
      expect(useAuthStore().isLoggedIn()).toBe(false)
    })
  })

  describe('login()', () => {
    it('sets token and persists to localStorage', async () => {
      const mockUser = { id: 'u1', email: 'admin@example.com' }
      vi.mocked(usersApi.loginByToken).mockResolvedValueOnce({ data: mockUser } as never)

      const store = useAuthStore()
      await store.login('admin-token-0000-0000-000000000001')

      expect(store.token).toBe('admin-token-0000-0000-000000000001')
      expect(localStorage.getItem('s1_token')).toBe('admin-token-0000-0000-000000000001')
    })

    it('sets user from API response on success', async () => {
      const mockUser = { id: 'u1', email: 'admin@example.com' }
      vi.mocked(usersApi.loginByToken).mockResolvedValueOnce({ data: mockUser } as never)

      const store = useAuthStore()
      await store.login('admin-token-0000-0000-000000000001')

      expect(store.user).toEqual(mockUser)
    })

    it('falls back to preset token metadata when API throws', async () => {
      vi.mocked(usersApi.loginByToken).mockRejectedValueOnce(new Error('network error'))

      const store = useAuthStore()
      const presetToken = PRESET_TOKENS[0]
      await store.login(presetToken.token)

      expect(store.user).toEqual(presetToken)
    })

    it('sets user to null when API throws and token is not a preset', async () => {
      vi.mocked(usersApi.loginByToken).mockRejectedValueOnce(new Error('network error'))

      const store = useAuthStore()
      await store.login('unknown-token-xyz')

      expect(store.user).toBeNull()
    })

    it('isLoggedIn returns true after login', async () => {
      vi.mocked(usersApi.loginByToken).mockResolvedValueOnce({ data: {} } as never)
      const store = useAuthStore()
      await store.login('admin-token-0000-0000-000000000001')
      expect(store.isLoggedIn()).toBe(true)
    })
  })

  describe('logout()', () => {
    it('clears token and user', async () => {
      vi.mocked(usersApi.loginByToken).mockResolvedValueOnce({ data: { id: 'u1' } } as never)
      const store = useAuthStore()
      await store.login('admin-token-0000-0000-000000000001')

      store.logout()

      expect(store.token).toBe('')
      expect(store.user).toBeNull()
    })

    it('removes token from localStorage', async () => {
      vi.mocked(usersApi.loginByToken).mockResolvedValueOnce({ data: {} } as never)
      const store = useAuthStore()
      await store.login('admin-token-0000-0000-000000000001')

      store.logout()

      expect(localStorage.getItem('s1_token')).toBeNull()
    })

    it('isLoggedIn returns false after logout', async () => {
      vi.mocked(usersApi.loginByToken).mockResolvedValueOnce({ data: {} } as never)
      const store = useAuthStore()
      await store.login('admin-token-0000-0000-000000000001')

      store.logout()

      expect(store.isLoggedIn()).toBe(false)
    })
  })

  describe('PRESET_TOKENS', () => {
    it('contains Admin, Viewer, and SOC Analyst entries', () => {
      const roles = PRESET_TOKENS.map((t) => t.role)
      expect(roles).toContain('Admin')
      expect(roles).toContain('Viewer')
      expect(roles).toContain('SOC Analyst')
    })

    it('every preset token has a non-empty token string', () => {
      for (const pt of PRESET_TOKENS) {
        expect(pt.token.length).toBeGreaterThan(0)
      }
    })
  })
})

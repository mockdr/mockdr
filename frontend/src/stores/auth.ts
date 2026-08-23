import { defineStore } from 'pinia'
import { ref } from 'vue'
import type { PresetToken, User } from '../types'
import { usersApi } from '../api/misc'

/** API tokens available in the mock server's seed data, sourced from env vars. */
export const PRESET_TOKENS: PresetToken[] = [
  { label: 'Admin',       token: import.meta.env.VITE_ADMIN_TOKEN,   role: 'Admin'       },
  { label: 'Viewer',      token: import.meta.env.VITE_VIEWER_TOKEN,  role: 'Viewer'      },
  { label: 'SOC Analyst', token: import.meta.env.VITE_ANALYST_TOKEN, role: 'SOC Analyst' },
]

/**
 * Pinia store for authentication state.
 *
 * Manages the active API token and the resolved user record.
 * Token is persisted to localStorage under the key `s1_token`.
 */
export const useAuthStore = defineStore('auth', () => {
  const token = ref<string>(localStorage.getItem('s1_token') ?? '')
  const user = ref<User | PresetToken | null>(null)

  /**
   * Authenticate with the given API token.
   *
   * Resolves the user via the API. A login that cannot reach the backend
   * fails — it used to "succeed" on preset metadata and leave the user on
   * a dashboard where every panel was silently empty.
   *
   * @param selectedToken - The API token string to activate.
   * @throws When the backend is unreachable or rejects the token.
   */
  async function login(selectedToken: string): Promise<void> {
    token.value = selectedToken
    localStorage.setItem('s1_token', selectedToken)
    try {
      const res = await usersApi.loginByToken()
      user.value = res.data ?? PRESET_TOKENS.find((t) => t.token === selectedToken) ?? null
    } catch (error) {
      token.value = ''
      user.value = null
      localStorage.removeItem('s1_token')
      throw error
    }
  }

  /** Clear the active token and user, and remove the token from localStorage. */
  function logout(): void {
    token.value = ''
    user.value = null
    localStorage.removeItem('s1_token')
  }

  return { token, user, login, logout }
})

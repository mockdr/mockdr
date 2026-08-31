/**
 * The Graph client's token call, which is where this console's data came from
 * and, for a while, did not.
 *
 * `ensureGraphAuth` omitted `scope` from its client-credentials grant. Entra
 * requires it and answers `AADSTS900144: The request body must contain the
 * following parameter: 'scope'` without one, so every Graph page showed its
 * empty state — "No users found" over a store holding users. Nothing here
 * covered it: this module had no spec at all.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import axios from 'axios'

vi.mock('axios', async () => {
  const actual = await vi.importActual<typeof import('axios')>('axios')
  return {
    ...actual,
    default: {
      ...actual.default,
      create: vi.fn(() => ({
        get: vi.fn(),
        post: vi.fn(),
        interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
      })),
      post: vi.fn(),
    },
  }
})

describe('ensureGraphAuth', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.clearAllMocks()
    vi.mocked(axios.post).mockResolvedValue({
      data: { access_token: 'a-token', expires_in: 3599, token_type: 'Bearer' },
    })
  })

  afterEach(() => localStorage.clear())

  it('asks for a token with every member Entra requires', async () => {
    const { ensureGraphAuth } = await import('../graph')
    await ensureGraphAuth()

    expect(axios.post).toHaveBeenCalledTimes(1)
    const [url, form] = vi.mocked(axios.post).mock.calls[0] as [string, URLSearchParams]
    expect(url).toBe('/graph/oauth2/v2.0/token')
    // The one that was missing. Without it the grant is refused outright and
    // every page in this section renders empty.
    expect(form.get('scope')).toBe('https://graph.microsoft.com/.default')
    expect(form.get('grant_type')).toBe('client_credentials')
    expect(form.get('client_id')).toBeTruthy()
    expect(form.get('client_secret')).toBeTruthy()
  })

  it('keeps the token so the next call does not ask again', async () => {
    const { ensureGraphAuth } = await import('../graph')
    await ensureGraphAuth()
    await ensureGraphAuth()
    expect(axios.post).toHaveBeenCalledTimes(1)
    expect(localStorage.getItem('graph_token')).toBe('a-token')
  })

  it('asks again once the token is close to expiring', async () => {
    const { ensureGraphAuth } = await import('../graph')
    localStorage.setItem('graph_token', 'stale')
    localStorage.setItem('graph_token_expires_at', String(Date.now() + 30_000))
    await ensureGraphAuth()
    expect(axios.post).toHaveBeenCalledTimes(1)
  })
})

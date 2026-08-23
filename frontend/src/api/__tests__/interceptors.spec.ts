import { describe, it, expect, vi, beforeEach } from 'vitest'

/**
 * Every vendor client installs the same two response interceptors: unwrap
 * the body on success; on failure report it and, for a 401, drop the cached
 * credential. Those callbacks only run inside axios, so this captures them.
 */

type Handler = (arg: unknown) => unknown
const captured: { request: Handler[]; success: Handler[]; failure: Handler[] } = {
  request: [],
  success: [],
  failure: [],
}

vi.mock('axios', () => {
  const create = vi.fn(() => ({
    interceptors: {
      request: { use: vi.fn((fn: Handler) => captured.request.push(fn)) },
      response: {
        use: vi.fn((ok: Handler, fail: Handler) => {
          captured.success.push(ok)
          captured.failure.push(fail)
        }),
      },
    },
    defaults: { headers: { common: {} } },
    get: vi.fn(),
    post: vi.fn(),
  }))
  return {
    default: {
      create,
      post: vi.fn().mockResolvedValue({ data: { access_token: 't', expires_in: 3600 } }),
      get: vi.fn().mockResolvedValue({ data: {} }),
      isAxiosError: (e: unknown) => !!(e as { isAxiosError?: boolean })?.isAxiosError,
    },
  }
})

const reportFailure = vi.fn()
vi.mock('../report', () => ({ reportFailure: (...args: unknown[]) => reportFailure(...args) }))

describe('vendor client interceptors', () => {
  beforeEach(async () => {
    captured.request.length = 0
    captured.success.length = 0
    captured.failure.length = 0
    reportFailure.mockClear()
    localStorage.clear()
    vi.resetModules()
    await Promise.all([
      import('../client'),
      import('../crowdstrike'),
      import('../defender'),
      import('../graph'),
      import('../sentinel'),
      import('../splunk'),
      import('../cortex'),
      import('../elastic'),
    ])
  })

  it('installs a response interceptor on every client', () => {
    expect(captured.failure.length).toBeGreaterThanOrEqual(8)
  })

  it('unwraps the response body on success', () => {
    for (const ok of captured.success) {
      expect(ok({ data: { marker: 1 } })).toEqual({ marker: 1 })
    }
  })

  it('reports every failure and rejects with it', async () => {
    const error = { isAxiosError: true, response: { status: 503 } }
    for (const fail of captured.failure) {
      await expect(fail(error)).rejects.toBe(error)
    }
    expect(reportFailure).toHaveBeenCalledTimes(captured.failure.length)
  })

  it('drops cached credentials on 401', async () => {
    localStorage.setItem('s1_token', 't')
    localStorage.setItem('cs_token', 't')
    localStorage.setItem('mde_token', 't')
    const error = { isAxiosError: true, response: { status: 401 } }
    for (const fail of captured.failure) {
      await (fail(error) as Promise<unknown>).catch(() => undefined)
    }
    expect(localStorage.getItem('s1_token')).toBeNull()
    expect(localStorage.getItem('cs_token')).toBeNull()
    expect(localStorage.getItem('mde_token')).toBeNull()
  })

  it('attaches the SentinelOne token on request', () => {
    localStorage.setItem('s1_token', 'abc')
    const configs = captured.request.map((fn) => fn({ headers: {} }) as { headers: Record<string, string> })
    expect(configs.some((c) => c.headers.Authorization === 'ApiToken abc')).toBe(true)
  })
})

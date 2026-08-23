import { describe, it, expect } from 'vitest'
import { AxiosError, AxiosHeaders } from 'axios'
import { describeFailure } from '../report'

function axiosError(partial: Partial<AxiosError>): AxiosError {
  const err = new AxiosError('boom')
  Object.assign(err, partial)
  return err
}

describe('describeFailure', () => {
  it('is silent on 401 (the clients re-authenticate)', () => {
    const err = axiosError({ response: { status: 401, data: {}, statusText: '', headers: {}, config: { headers: new AxiosHeaders() } } })
    expect(describeFailure(err, 'Defender')).toBeNull()
  })

  it('names the status and path for other responses', () => {
    const err = axiosError({
      response: { status: 503, data: {}, statusText: '', headers: {}, config: { headers: new AxiosHeaders() } },
      config: { url: '/api/alerts', headers: new AxiosHeaders() },
    })
    expect(describeFailure(err, 'Defender')).toBe('Defender: 503 on /api/alerts')
  })

  it('says unreachable when there is no response', () => {
    expect(describeFailure(axiosError({}), 'Splunk')).toBe('Splunk: backend unreachable')
  })

  it('says timed out on ECONNABORTED', () => {
    expect(describeFailure(axiosError({ code: 'ECONNABORTED' }), 'Graph')).toBe('Graph: request timed out')
  })

  it('handles non-axios errors', () => {
    expect(describeFailure(new Error('x'), 'Elastic')).toBe('Elastic: unexpected error')
  })
})

describe('reportFailure', () => {
  it('pushes the description into the notifications store', async () => {
    const { setActivePinia, createPinia } = await import('pinia')
    setActivePinia(createPinia())
    const { useNotificationsStore } = await import('../../stores/notifications')
    const { reportFailure } = await import('../report')
    await reportFailure(axiosError({}), 'Splunk')
    expect(useNotificationsStore().notices.map((n) => n.text)).toEqual(['Splunk: backend unreachable'])
  })

  it('stays silent on a 401', async () => {
    const { setActivePinia, createPinia } = await import('pinia')
    setActivePinia(createPinia())
    const { useNotificationsStore } = await import('../../stores/notifications')
    const { reportFailure } = await import('../report')
    await reportFailure(
      axiosError({ response: { status: 401, data: {}, statusText: '', headers: {}, config: { headers: new AxiosHeaders() } } }),
      'Graph',
    )
    expect(useNotificationsStore().notices).toHaveLength(0)
  })
})

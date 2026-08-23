import { describe, it, expect, beforeEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useNotificationsStore } from '../notifications'

describe('useNotificationsStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.useFakeTimers()
  })

  it('pushes a notice and expires it', () => {
    const store = useNotificationsStore()
    store.push('Splunk: backend unreachable')
    expect(store.notices).toHaveLength(1)
    expect(store.notices[0].kind).toBe('error')
    vi.advanceTimersByTime(6001)
    expect(store.notices).toHaveLength(0)
  })

  it('collapses identical texts within five seconds', () => {
    const store = useNotificationsStore()
    store.push('Graph: backend unreachable')
    store.push('Graph: backend unreachable')
    store.push('Graph: backend unreachable')
    expect(store.notices).toHaveLength(1)
    vi.advanceTimersByTime(5001)
    store.push('Graph: backend unreachable')
    expect(store.notices).toHaveLength(2)
  })

  it('dismisses one and clears all', () => {
    const store = useNotificationsStore()
    store.push('a')
    store.push('b')
    store.dismiss(store.notices[0].id)
    expect(store.notices.map((n) => n.text)).toEqual(['b'])
    store.clear()
    expect(store.notices).toHaveLength(0)
  })
})

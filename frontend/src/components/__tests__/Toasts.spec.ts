import { describe, it, expect, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { setActivePinia, createPinia } from 'pinia'
import Toasts from '../shared/Toasts.vue'
import { useNotificationsStore } from '../../stores/notifications'

describe('Toasts', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('is a polite live region that renders and dismisses notices', async () => {
    const w = mount(Toasts)
    const region = w.get('[aria-live="polite"]')
    expect(region.attributes('role')).toBe('status')
    const store = useNotificationsStore()
    store.push('CrowdStrike: 500 on /devices/queries/devices/v1')
    await w.vm.$nextTick()
    expect(w.text()).toContain('CrowdStrike: 500')
    await w.get('button[aria-label="Dismiss notification"]').trigger('click')
    expect(store.notices).toHaveLength(0)
  })
})

import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import StatusBadge from '../shared/StatusBadge.vue'

describe('StatusBadge', () => {
  describe('agent type (default)', () => {
    it('connected → Online', () => {
      const w = mount(StatusBadge, { props: { status: 'connected' } })
      expect(w.text()).toBe('Online')
    })

    it('disconnected → Disconnected', () => {
      const w = mount(StatusBadge, { props: { status: 'disconnected' } })
      expect(w.text()).toBe('Disconnected')
    })

    it('unknown status falls back to the raw value', () => {
      const w = mount(StatusBadge, { props: { status: 'custom-status' } })
      expect(w.text()).toBe('custom-status')
    })
  })

  describe('threat type', () => {
    it('mitigated → Mitigated', () => {
      const w = mount(StatusBadge, { props: { status: 'mitigated', type: 'threat' } })
      expect(w.text()).toBe('Mitigated')
    })

    it('active → Active', () => {
      const w = mount(StatusBadge, { props: { status: 'active', type: 'threat' } })
      expect(w.text()).toBe('Active')
    })
  })

  describe('incident type', () => {
    it('unresolved → Unresolved', () => {
      const w = mount(StatusBadge, { props: { status: 'unresolved', type: 'incident' } })
      expect(w.text()).toBe('Unresolved')
    })

    it('RESOLVED (uppercase) → Resolved', () => {
      const w = mount(StatusBadge, { props: { status: 'RESOLVED', type: 'incident' } })
      expect(w.text()).toBe('Resolved')
    })
  })

  describe('verdict type', () => {
    it('true_positive → True Positive', () => {
      const w = mount(StatusBadge, { props: { status: 'true_positive', type: 'verdict' } })
      expect(w.text()).toBe('True Positive')
    })

    it('FALSE_POSITIVE (uppercase) → False Positive', () => {
      const w = mount(StatusBadge, { props: { status: 'FALSE_POSITIVE', type: 'verdict' } })
      expect(w.text()).toBe('False Positive')
    })
  })

  it('renders a span element', () => {
    const w = mount(StatusBadge, { props: { status: 'connected' } })
    expect(w.element.tagName).toBe('SPAN')
  })
})

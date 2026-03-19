import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import EmptyState from '@/components/shared/EmptyState.vue'

describe('EmptyState', () => {
  describe('defaults', () => {
    it('renders default icon 🔍', () => {
      const w = mount(EmptyState)
      expect(w.text()).toContain('🔍')
    })

    it('renders default title', () => {
      const w = mount(EmptyState)
      expect(w.text()).toContain('No results found')
    })

    it('renders default description', () => {
      const w = mount(EmptyState)
      expect(w.text()).toContain('Try adjusting your filters.')
    })
  })

  describe('custom props', () => {
    it('renders custom icon', () => {
      const w = mount(EmptyState, { props: { icon: '🚫' } })
      expect(w.text()).toContain('🚫')
    })

    it('renders custom title', () => {
      const w = mount(EmptyState, { props: { title: 'No users' } })
      expect(w.text()).toContain('No users')
    })

    it('renders custom description', () => {
      const w = mount(EmptyState, { props: { description: 'Create one to get started.' } })
      expect(w.text()).toContain('Create one to get started.')
    })
  })
})

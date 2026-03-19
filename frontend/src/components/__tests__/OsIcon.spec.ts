import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import OsIcon from '@/components/shared/OsIcon.vue'

describe('OsIcon', () => {
  it('windows → 🪟', () => {
    const w = mount(OsIcon, { props: { osType: 'windows' } })
    expect(w.text()).toBe('🪟')
  })

  it('macos → 🍎', () => {
    const w = mount(OsIcon, { props: { osType: 'macos' } })
    expect(w.text()).toBe('🍎')
  })

  it('linux → 🐧', () => {
    const w = mount(OsIcon, { props: { osType: 'linux' } })
    expect(w.text()).toBe('🐧')
  })

  it('unknown osType → 💻', () => {
    const w = mount(OsIcon, { props: { osType: 'freebsd' } })
    expect(w.text()).toBe('💻')
  })

  it('sets title attribute to osType', () => {
    const w = mount(OsIcon, { props: { osType: 'linux' } })
    expect(w.element.getAttribute('title')).toBe('linux')
  })

  it('renders a span element', () => {
    const w = mount(OsIcon, { props: { osType: 'windows' } })
    expect(w.element.tagName).toBe('SPAN')
  })
})

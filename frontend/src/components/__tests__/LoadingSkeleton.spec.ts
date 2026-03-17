import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import LoadingSkeleton from '../shared/LoadingSkeleton.vue'

describe('LoadingSkeleton', () => {
  it('renders 5 rows by default', () => {
    const w = mount(LoadingSkeleton)
    expect(w.findAll('.flex.gap-4')).toHaveLength(5)
  })

  it('renders the number of rows given via prop', () => {
    const w = mount(LoadingSkeleton, { props: { rows: 3 } })
    expect(w.findAll('.flex.gap-4')).toHaveLength(3)
  })

  it('renders 10 rows when rows=10', () => {
    const w = mount(LoadingSkeleton, { props: { rows: 10 } })
    expect(w.findAll('.flex.gap-4')).toHaveLength(10)
  })

  it('has animate-pulse class', () => {
    const w = mount(LoadingSkeleton)
    expect(w.find('.animate-pulse').exists()).toBe(true)
  })
})

import { describe, it, expect, vi } from 'vitest'
import { shallowMount } from '@vue/test-utils'
import ExportImportView from '../ExportImportView.vue'

vi.mock('vue-router', () => ({
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: { template: '<a><slot /></a>' },
}))

vi.mock('../../api/system', () => ({
  systemApi: {
    exportState: vi.fn(),
    importState: vi.fn(),
    status: vi.fn(),
    info: vi.fn(),
    listRequests: vi.fn(),
    getRateLimit: vi.fn(),
  },
  webhooksApi: { list: vi.fn() },
  proxyApi: { getConfig: vi.fn() },
}))

describe('ExportImportView', () => {
  it('renders without error', () => {
    const w = shallowMount(ExportImportView)
    expect(w.exists()).toBe(true)
  })

  it('renders the Export / Import heading', () => {
    const w = shallowMount(ExportImportView)
    expect(w.text()).toContain('Export / Import')
  })

  it('renders Export Snapshot section', () => {
    const w = shallowMount(ExportImportView)
    expect(w.text()).toContain('Export Snapshot')
    expect(w.text()).toContain('Download Snapshot')
  })

  it('renders Import Snapshot section', () => {
    const w = shallowMount(ExportImportView)
    expect(w.text()).toContain('Import Snapshot')
    expect(w.text()).toContain('Upload Snapshot')
  })

  it('has a hidden file input for import', () => {
    const w = shallowMount(ExportImportView)
    const fileInput = w.find('input[type="file"]')
    expect(fileInput.exists()).toBe(true)
    expect(fileInput.classes()).toContain('hidden')
  })
})

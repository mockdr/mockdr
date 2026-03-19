import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import ExportImportView from '@/views/ExportImportView.vue'

const mockExportState = vi.hoisted(() => vi.fn())
const mockImportState = vi.hoisted(() => vi.fn())

vi.mock('../../api/system', () => ({
  systemApi: {
    exportState: mockExportState,
    importState: mockImportState,
    status: vi.fn(),
    info: vi.fn(),
    listRequests: vi.fn(),
    getRateLimit: vi.fn(),
  },
  webhooksApi: { list: vi.fn() },
  proxyApi: { getConfig: vi.fn() },
}))

describe('ExportImportView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockExportState.mockResolvedValue({ data: { agents: [], sites: [] } })
    mockImportState.mockResolvedValue({})

    // Mock URL.createObjectURL and URL.revokeObjectURL
    vi.stubGlobal('URL', {
      createObjectURL: vi.fn().mockReturnValue('blob:mock-url'),
      revokeObjectURL: vi.fn(),
    })
  })

  it('renders the Export / Import heading', () => {
    const w = mount(ExportImportView)
    expect(w.text()).toContain('Export / Import')
  })

  it('renders Export Snapshot section', () => {
    const w = mount(ExportImportView)
    expect(w.text()).toContain('Export Snapshot')
    expect(w.text()).toContain('Download Snapshot')
  })

  it('renders Import Snapshot section', () => {
    const w = mount(ExportImportView)
    expect(w.text()).toContain('Import Snapshot')
    expect(w.text()).toContain('Upload Snapshot')
  })

  it('has a hidden file input for import', () => {
    const w = mount(ExportImportView)
    const fileInput = w.find('input[type="file"]')
    expect(fileInput.exists()).toBe(true)
    expect(fileInput.classes()).toContain('hidden')
  })

  it('doExport calls systemApi.exportState', async () => {
    const w = mount(ExportImportView)
    // Mock document.createElement to avoid real anchor
    const mockClick = vi.fn()
    const mockAnchor = { href: '', download: '', click: mockClick }
    vi.spyOn(document, 'createElement').mockReturnValueOnce(mockAnchor as unknown as HTMLElement)

    await (w.vm as any).doExport()
    await flushPromises()
    expect(mockExportState).toHaveBeenCalled()
  })

  it('doExport sets exporting to false after completion', async () => {
    const w = mount(ExportImportView)
    const mockAnchor = { href: '', download: '', click: vi.fn() }
    vi.spyOn(document, 'createElement').mockReturnValueOnce(mockAnchor as unknown as HTMLElement)

    await (w.vm as any).doExport()
    await flushPromises()
    expect((w.vm as any).exporting).toBe(false)
  })

  it('doExport sets exporting to false even when exportState throws', async () => {
    mockExportState.mockRejectedValueOnce(new Error('Export failed'))
    const w = mount(ExportImportView)
    try {
      await (w.vm as any).doExport()
    } catch { /* expected */ }
    await flushPromises()
    expect((w.vm as any).exporting).toBe(false)
  })

  it('triggerImport clicks the file input', async () => {
    const w = mount(ExportImportView)
    const mockClick = vi.fn()
    ;(w.vm as any).fileInput = { click: mockClick }
    ;(w.vm as any).triggerImport()
    expect(mockClick).toHaveBeenCalled()
  })

  it('triggerImport does nothing when fileInput is null', async () => {
    const w = mount(ExportImportView)
    ;(w.vm as any).fileInput = null
    // Should not throw
    expect(() => (w.vm as any).triggerImport()).not.toThrow()
  })

  it('onFileSelected does nothing when no file selected', async () => {
    const w = mount(ExportImportView)
    const mockEvent = {
      target: { files: null, value: '' },
    } as unknown as Event
    await (w.vm as any).onFileSelected(mockEvent)
    expect(mockImportState).not.toHaveBeenCalled()
  })

  it('onFileSelected does nothing with empty FileList', async () => {
    const w = mount(ExportImportView)
    const mockEvent = {
      target: { files: [], value: '' },
    } as unknown as Event
    await (w.vm as any).onFileSelected(mockEvent)
    expect(mockImportState).not.toHaveBeenCalled()
  })

  it('onFileSelected calls systemApi.importState with parsed JSON', async () => {
    const w = mount(ExportImportView)
    const snapshotData = { agents: [{ id: 'a1' }] }
    const mockFile = {
      name: 'snapshot.json',
      text: vi.fn().mockResolvedValue(JSON.stringify(snapshotData)),
    }
    const mockEvent = {
      target: { files: [mockFile], value: '' },
    } as unknown as Event

    await (w.vm as any).onFileSelected(mockEvent)
    await flushPromises()
    expect(mockImportState).toHaveBeenCalledWith(snapshotData)
  })

  it('onFileSelected sets importStatus to success on successful import', async () => {
    const w = mount(ExportImportView)
    const mockFile = {
      name: 'snapshot.json',
      text: vi.fn().mockResolvedValue('{"agents":[]}'),
    }
    const mockEvent = {
      target: { files: [mockFile], value: '' },
    } as unknown as Event

    await (w.vm as any).onFileSelected(mockEvent)
    await flushPromises()
    expect((w.vm as any).importStatus).toBe('success')
    expect((w.vm as any).importMessage).toContain('snapshot.json')
  })

  it('onFileSelected sets importStatus to error on JSON parse failure', async () => {
    const w = mount(ExportImportView)
    const mockFile = {
      name: 'bad.json',
      text: vi.fn().mockResolvedValue('not valid json {{{'),
    }
    const mockEvent = {
      target: { files: [mockFile], value: '' },
    } as unknown as Event

    await (w.vm as any).onFileSelected(mockEvent)
    await flushPromises()
    expect((w.vm as any).importStatus).toBe('error')
  })

  it('onFileSelected sets importStatus to error when importState throws', async () => {
    mockImportState.mockRejectedValueOnce(new Error('Server rejected snapshot'))
    const w = mount(ExportImportView)
    const mockFile = {
      name: 'snapshot.json',
      text: vi.fn().mockResolvedValue('{"agents":[]}'),
    }
    const mockEvent = {
      target: { files: [mockFile], value: '' },
    } as unknown as Event

    await (w.vm as any).onFileSelected(mockEvent)
    await flushPromises()
    expect((w.vm as any).importStatus).toBe('error')
    expect((w.vm as any).importMessage).toBe('Server rejected snapshot')
  })

  it('onFileSelected sets generic error message for non-Error throws', async () => {
    mockImportState.mockRejectedValueOnce('string error')
    const w = mount(ExportImportView)
    const mockFile = {
      name: 'snapshot.json',
      text: vi.fn().mockResolvedValue('{"agents":[]}'),
    }
    const mockEvent = {
      target: { files: [mockFile], value: '' },
    } as unknown as Event

    await (w.vm as any).onFileSelected(mockEvent)
    await flushPromises()
    expect((w.vm as any).importStatus).toBe('error')
    expect((w.vm as any).importMessage).toContain('invalid snapshot format')
  })

  it('onFileSelected sets importing to false after completion', async () => {
    const w = mount(ExportImportView)
    const mockFile = {
      name: 'snapshot.json',
      text: vi.fn().mockResolvedValue('{"agents":[]}'),
    }
    const mockEvent = {
      target: { files: [mockFile], value: '' },
    } as unknown as Event

    await (w.vm as any).onFileSelected(mockEvent)
    await flushPromises()
    expect((w.vm as any).importing).toBe(false)
  })

  it('shows success message after successful import', async () => {
    const w = mount(ExportImportView)
    ;(w.vm as any).importStatus = 'success'
    ;(w.vm as any).importMessage = 'Snapshot imported successfully.'
    await w.vm.$nextTick()
    expect(w.text()).toContain('Snapshot imported successfully.')
  })

  it('shows error message after failed import', async () => {
    const w = mount(ExportImportView)
    ;(w.vm as any).importStatus = 'error'
    ;(w.vm as any).importMessage = 'Import failed — invalid snapshot format'
    await w.vm.$nextTick()
    expect(w.text()).toContain('Import failed')
  })

  it('does not show status message when importStatus is idle', async () => {
    const w = mount(ExportImportView)
    expect((w.vm as any).importStatus).toBe('idle')
    expect(w.find('.bg-s1-success\\/10').exists() || w.find('.bg-s1-danger\\/10').exists()).toBe(false)
  })
})

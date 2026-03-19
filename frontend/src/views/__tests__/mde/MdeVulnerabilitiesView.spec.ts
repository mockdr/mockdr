import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createRouter, createWebHistory } from 'vue-router'

vi.mock('../../../api/defender', () => ({
  ensureMdeAuth: vi.fn().mockResolvedValue(undefined),
  mdeVulnerabilitiesApi: {
    list: vi.fn().mockResolvedValue({
      '@odata.context': 'https://api.securitycenter.microsoft.com/api/$metadata#Vulnerabilities',
      value: [
        {
          vulnerabilityId: 'CVE-2025-001',
          name: 'Remote Code Execution in Foo',
          severity: 'Critical',
          cvssV3: 9.8,
          exposedMachines: 5,
          publicExploit: true,
        },
        {
          vulnerabilityId: 'CVE-2025-002',
          name: 'Privilege Escalation in Bar',
          severity: 'High',
          cvssV3: 7.5,
          exposedMachines: 2,
          publicExploit: false,
        },
        {
          vulnerabilityId: 'CVE-2025-003',
          name: 'Information Disclosure in Baz',
          severity: 'Medium',
          cvssV3: 5.0,
          exposedMachines: 1,
          publicExploit: false,
        },
        {
          vulnerabilityId: 'CVE-2025-004',
          name: 'Denial of Service in Qux',
          severity: 'Low',
          cvssV3: 3.1,
          exposedMachines: 0,
          publicExploit: false,
        },
      ],
    }),
  },
  mdeSoftwareApi: {
    list: vi.fn().mockResolvedValue({
      '@odata.context': 'https://api.securitycenter.microsoft.com/api/$metadata#Software',
      value: [
        {
          softwareId: 'sw-1',
          name: 'Adobe Flash Player',
          vendor: 'Adobe',
          weaknesses: 3,
          exposedMachines: 2,
          impactScore: 8.5,
          publicExploit: true,
          activeAlert: true,
          version: '32.0',
        },
        {
          softwareId: 'sw-2',
          name: 'qBittorrent',
          vendor: 'qBittorrent',
          weaknesses: 1,
          exposedMachines: 1,
          impactScore: 5.5,
          publicExploit: false,
          activeAlert: false,
          version: '4.5.0',
        },
        {
          softwareId: 'sw-3',
          name: 'Mimikatz',
          vendor: 'N/A',
          weaknesses: 0,
          exposedMachines: 1,
          impactScore: 9.0,
          publicExploit: true,
          activeAlert: true,
          version: '2.2.0',
        },
        {
          softwareId: 'sw-4',
          name: 'SentinelOne',
          vendor: 'SentinelOne',
          weaknesses: 0,
          exposedMachines: 10,
          impactScore: 2.0,
          publicExploit: false,
          activeAlert: false,
          version: '22.1',
        },
        {
          softwareId: 'sw-5',
          name: 'Chrome (outdated)',
          vendor: 'Google',
          weaknesses: 2,
          exposedMachines: 4,
          impactScore: 4.0,
          publicExploit: false,
          activeAlert: false,
          version: '110.0',
        },
        {
          softwareId: 'sw-6',
          name: 'Notepad++',
          vendor: 'Don Ho',
          weaknesses: 0,
          exposedMachines: 8,
          impactScore: 1.0,
          publicExploit: false,
          activeAlert: false,
          version: '8.5.0',
        },
      ],
    }),
  },
}))

import MdeVulnerabilitiesView from '@/views/mde/MdeVulnerabilitiesView.vue'
import { ensureMdeAuth, mdeVulnerabilitiesApi, mdeSoftwareApi } from '@/api/defender'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', component: { template: '<div />' } },
    { path: '/mde/vulnerabilities/:id', component: { template: '<div />' } },
  ],
})

const STUBS = {
  LoadingSkeleton: true,
  EmptyState: true,
  RouterLink: { template: '<a><slot /></a>' },
}

describe('MdeVulnerabilitiesView', () => {
  beforeEach(async () => {
    vi.clearAllMocks()
    await router.push('/')
    await router.isReady()
  })

  it('renders the page header', async () => {
    const wrapper = mount(MdeVulnerabilitiesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('Vulnerabilities')
  })

  it('calls ensureMdeAuth, mdeVulnerabilitiesApi.list, and mdeSoftwareApi.list on mount', async () => {
    mount(MdeVulnerabilitiesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(ensureMdeAuth).toHaveBeenCalled()
    expect(mdeVulnerabilitiesApi.list).toHaveBeenCalledWith({ $top: 100 })
    expect(mdeSoftwareApi.list).toHaveBeenCalledWith({ $top: 100 })
  })

  it('displays loaded vulnerability IDs', async () => {
    const wrapper = mount(MdeVulnerabilitiesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('CVE-2025-001')
    expect(wrapper.text()).toContain('CVE-2025-002')
  })

  it('displays vulnerability names', async () => {
    const wrapper = mount(MdeVulnerabilitiesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.text()).toContain('Remote Code Execution in Foo')
  })

  it('sets loading to false after fetchData completes', async () => {
    const wrapper = mount(MdeVulnerabilitiesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    const vm = wrapper.vm as any
    expect(vm.loading).toBe(false)
  })

  // fetchData explicit call
  it('fetchData can be called explicitly and refreshes data', async () => {
    const wrapper = mount(MdeVulnerabilitiesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    vi.mocked(mdeVulnerabilitiesApi.list).mockClear()
    vi.mocked(mdeSoftwareApi.list).mockClear()
    await (wrapper.vm as any).fetchData()
    await flushPromises()
    expect(mdeVulnerabilitiesApi.list).toHaveBeenCalledWith({ $top: 100 })
    expect(mdeSoftwareApi.list).toHaveBeenCalledWith({ $top: 100 })
  })

  it('fetchData sets loading to false even when API throws', async () => {
    const wrapper = mount(MdeVulnerabilitiesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    vi.mocked(mdeVulnerabilitiesApi.list).mockRejectedValueOnce(new Error('Network error'))
    try {
      await (wrapper.vm as any).fetchData()
    } catch {
      // expected
    }
    await flushPromises()
    expect((wrapper.vm as any).loading).toBe(false)
  })

  it('fetchData populates vulnerabilities from response value', async () => {
    const wrapper = mount(MdeVulnerabilitiesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).vulnerabilities).toHaveLength(4)
  })

  it('fetchData falls back to empty array when value is null', async () => {
    vi.mocked(mdeVulnerabilitiesApi.list).mockResolvedValueOnce({ '@odata.context': '', value: null } as unknown as ReturnType<typeof mdeVulnerabilitiesApi.list> extends Promise<infer T> ? T : never)
    vi.mocked(mdeSoftwareApi.list).mockResolvedValueOnce({ '@odata.context': '', value: null } as unknown as ReturnType<typeof mdeSoftwareApi.list> extends Promise<infer T> ? T : never)
    const wrapper = mount(MdeVulnerabilitiesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).vulnerabilities).toEqual([])
    expect((wrapper.vm as any).software).toEqual([])
  })

  // severityBadgeClass – all branches
  it('severityBadgeClass returns correct class for Critical', async () => {
    const wrapper = mount(MdeVulnerabilitiesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).severityBadgeClass('Critical')).toBe('bg-red-500/15 text-red-400')
  })

  it('severityBadgeClass returns correct class for High', async () => {
    const wrapper = mount(MdeVulnerabilitiesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).severityBadgeClass('High')).toBe('bg-orange-500/15 text-orange-400')
  })

  it('severityBadgeClass returns correct class for Medium', async () => {
    const wrapper = mount(MdeVulnerabilitiesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).severityBadgeClass('Medium')).toBe('bg-yellow-500/15 text-yellow-400')
  })

  it('severityBadgeClass returns correct class for Low', async () => {
    const wrapper = mount(MdeVulnerabilitiesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).severityBadgeClass('Low')).toBe('bg-blue-500/15 text-blue-400')
  })

  it('severityBadgeClass returns default class for unknown severity', async () => {
    const wrapper = mount(MdeVulnerabilitiesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).severityBadgeClass('Unknown')).toBe('bg-gray-500/15 text-gray-400')
  })

  // isEol – positive and negative
  it('isEol returns true for a known EOL product name', async () => {
    const wrapper = mount(MdeVulnerabilitiesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).isEol('Adobe Flash Player 32')).toBe(true)
    expect((wrapper.vm as any).isEol('Microsoft Silverlight 5')).toBe(true)
    expect((wrapper.vm as any).isEol('Windows 7 SP1')).toBe(true)
    expect((wrapper.vm as any).isEol('Internet Explorer 11')).toBe(true)
    expect((wrapper.vm as any).isEol('Python 2.7.18')).toBe(true)
  })

  it('isEol returns false for a non-EOL product name', async () => {
    const wrapper = mount(MdeVulnerabilitiesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).isEol('Google Chrome')).toBe(false)
    expect((wrapper.vm as any).isEol('Visual Studio Code')).toBe(false)
  })

  it('isEol returns false for undefined/null name', async () => {
    const wrapper = mount(MdeVulnerabilitiesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).isEol(undefined)).toBe(false)
    expect((wrapper.vm as any).isEol(null)).toBe(false)
  })

  // isTorrent – positive and negative
  it('isTorrent returns true for known torrent client names', async () => {
    const wrapper = mount(MdeVulnerabilitiesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).isTorrent('qBittorrent 4.5')).toBe(true)
    expect((wrapper.vm as any).isTorrent('uTorrent 3.6')).toBe(true)
    expect((wrapper.vm as any).isTorrent('BitTorrent client')).toBe(true)
  })

  it('isTorrent returns false for non-torrent software', async () => {
    const wrapper = mount(MdeVulnerabilitiesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).isTorrent('VLC Media Player')).toBe(false)
    expect((wrapper.vm as any).isTorrent(undefined)).toBe(false)
  })

  // isDualUse – positive and negative
  it('isDualUse returns true for known dual-use tool names', async () => {
    const wrapper = mount(MdeVulnerabilitiesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).isDualUse('Mimikatz 2.2')).toBe(true)
    expect((wrapper.vm as any).isDualUse('Nmap 7.93')).toBe(true)
    expect((wrapper.vm as any).isDualUse('PsExec v2.4')).toBe(true)
    expect((wrapper.vm as any).isDualUse('Cobalt Strike 4.5')).toBe(true)
    expect((wrapper.vm as any).isDualUse('Wireshark 4.0')).toBe(true)
  })

  it('isDualUse returns false for benign software', async () => {
    const wrapper = mount(MdeVulnerabilitiesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).isDualUse('Microsoft Office')).toBe(false)
    expect((wrapper.vm as any).isDualUse(undefined)).toBe(false)
  })

  // isEdr – positive and negative
  it('isEdr returns true for known EDR product names', async () => {
    const wrapper = mount(MdeVulnerabilitiesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).isEdr('SentinelOne Agent')).toBe(true)
    expect((wrapper.vm as any).isEdr('CrowdStrike Falcon')).toBe(true)
    expect((wrapper.vm as any).isEdr('Defender for Endpoint 10')).toBe(true)
    expect((wrapper.vm as any).isEdr('Cortex XDR 3')).toBe(true)
    expect((wrapper.vm as any).isEdr('Elastic Endpoint 8.x')).toBe(true)
  })

  it('isEdr returns false for non-EDR software', async () => {
    const wrapper = mount(MdeVulnerabilitiesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).isEdr('Notepad++')).toBe(false)
    expect((wrapper.vm as any).isEdr(undefined)).toBe(false)
  })

  // isOutdated – positive and negative
  it('isOutdated returns true when name contains (outdated)', async () => {
    const wrapper = mount(MdeVulnerabilitiesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).isOutdated('Chrome (outdated)')).toBe(true)
    expect((wrapper.vm as any).isOutdated('Firefox (outdated)')).toBe(true)
  })

  it('isOutdated returns false when name does not contain (outdated)', async () => {
    const wrapper = mount(MdeVulnerabilitiesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).isOutdated('Chrome')).toBe(false)
    expect((wrapper.vm as any).isOutdated(undefined)).toBe(false)
    expect((wrapper.vm as any).isOutdated(null)).toBe(false)
  })

  // Tab switching
  it('switches to software tab and shows software data', async () => {
    const wrapper = mount(MdeVulnerabilitiesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect((wrapper.vm as any).activeTab).toBe('vulnerabilities')
    ;(wrapper.vm as any).activeTab = 'software'
    await wrapper.vm.$nextTick()
    expect((wrapper.vm as any).activeTab).toBe('software')
    expect(wrapper.text()).toContain('Adobe Flash Player')
    expect(wrapper.text()).toContain('qBittorrent')
    expect(wrapper.text()).toContain('SentinelOne')
  })

  it('shows compliance summary bar when on software tab with data', async () => {
    const wrapper = mount(MdeVulnerabilitiesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    ;(wrapper.vm as any).activeTab = 'software'
    await wrapper.vm.$nextTick()
    // EOL count: Adobe Flash Player = 1
    expect(wrapper.text()).toContain('EOL')
    // P2P/Torrent count: qBittorrent = 1
    expect(wrapper.text()).toContain('P2P/Torrent')
    // Dual-Use: Mimikatz = 1
    expect(wrapper.text()).toContain('Dual-Use')
    // EDR: SentinelOne = 1
    expect(wrapper.text()).toContain('EDR Agents')
  })

  it('shows empty state when no vulnerabilities returned', async () => {
    vi.mocked(mdeVulnerabilitiesApi.list).mockResolvedValueOnce({ '@odata.context': '', value: [] })
    vi.mocked(mdeSoftwareApi.list).mockResolvedValueOnce({ '@odata.context': '', value: [] })
    const wrapper = mount(MdeVulnerabilitiesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    expect(wrapper.html()).toContain('empty-state-stub')
  })

  it('Refresh button triggers fetchData', async () => {
    const wrapper = mount(MdeVulnerabilitiesView, {
      global: { plugins: [router], stubs: STUBS },
    })
    await flushPromises()
    vi.mocked(mdeVulnerabilitiesApi.list).mockClear()
    const refreshBtn = wrapper.findAll('button').find(b => b.text().includes('Refresh'))
    expect(refreshBtn).toBeDefined()
    await refreshBtn!.trigger('click')
    await flushPromises()
    expect(mdeVulnerabilitiesApi.list).toHaveBeenCalled()
  })
})

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import Dashboard from '@/presentation/views/Dashboard.vue'
import vulnService from '@/application/services/vulnService'
import wazuhService from '@/application/services/wazuhService'

const startSync = vi.fn()
const resumeIfActive = vi.fn()
const onDone = vi.fn()

vi.mock('@/presentation/composables/useSyncJob', () => ({
  useSyncJob: () => ({
    isSyncing: false,
    progressPct: 0,
    phaseLabel: 'Sincronizando...',
    startSync,
    resumeIfActive,
    onDone
  })
}))

vi.mock('@/application/services/vulnService', () => ({
  default: {
    getVulns: vi.fn(),
    getFilterOptions: vi.fn(),
    getEvolutionSummary: vi.fn(),
    getWeeklyTrend: vi.fn(),
    getTopAssets: vi.fn(),
    getTraceabilitySummary: vi.fn()
  }
}))

vi.mock('@/application/services/wazuhService', () => ({
  default: {
    getConnections: vi.fn()
  }
}))

describe('Dashboard.vue', () => {
  const mockItems = [
    {
      id: 1,
      connection_id: 'conn-1',
      connection_name: 'Conn A',
      severity: 'critical',
      cve_id: 'CVE-2023-1234',
      first_seen: new Date().toISOString(),
      last_seen: new Date().toISOString(),
      agent_name: 'Agent-1',
      package_name: 'bash',
      package_version: '5.0',
      score_base: 9.8
    },
    {
      id: 2,
      connection_id: 'conn-2',
      connection_name: 'Conn B',
      severity: 'low',
      cve_id: 'CVE-2022-0001',
      first_seen: new Date(Date.now() - 1000 * 60 * 60 * 48).toISOString(),
      last_seen: new Date(Date.now() - 1000 * 60 * 60).toISOString(),
      agent_name: 'Agent-2',
      package_name: 'curl',
      package_version: '7.0',
      score_base: 4.2
    }
  ]

  beforeEach(() => {
    vi.clearAllMocks()
    startSync.mockReset()
    resumeIfActive.mockReset()
    onDone.mockImplementation(() => {})

    wazuhService.getConnections.mockResolvedValue({
      data: [{ id: 'conn-1', name: 'Conn A' }]
    })
    vulnService.getVulns.mockResolvedValue({ data: { items: mockItems, total: mockItems.length } })
    vulnService.getFilterOptions.mockResolvedValue({
      data: {
        agents: ['Agent-1', 'Agent-2'],
        cves: ['CVE-2023-1234', 'CVE-2022-0001'],
        packages: ['bash', 'curl'],
        severities: ['low', 'critical']
      }
    })
    vulnService.getEvolutionSummary.mockResolvedValue({
      data: {
        active_vulnerabilities: 2,
        resolved_vulnerabilities: 1,
        assets: 2,
        detection_events: 3,
        last_sync_at: null
      }
    })
    vulnService.getWeeklyTrend.mockResolvedValue({
      data: [{ semana: new Date().toISOString(), total_vulnerabilidades: 2 }]
    })
    vulnService.getTopAssets.mockResolvedValue({ data: [{ hostname: 'Agent-1', total: 1 }] })
    vulnService.getTraceabilitySummary.mockResolvedValue({
      data: { nuevas: 1, persistentes: 1, remediadas: 1 }
    })
  })

  it('loads paginated vulnerabilities, filter options, connections and metrics', async () => {
    const wrapper = mount(Dashboard)
    await flushPromises()

    expect(wrapper.vm.loading).toBe(false)
    expect(vulnService.getVulns).toHaveBeenCalledWith(expect.objectContaining({
      page: 1,
      pageSize: 50,
      sortBy: 'last_seen',
      sortOrder: 'desc'
    }))
    expect(wrapper.vm.vulns).toHaveLength(2)
    expect(wrapper.vm.totalItems).toBe(2)
    expect(wrapper.findAll('tbody tr')).toHaveLength(2)
    expect(wrapper.text()).toContain('Conn A')
    expect(wrapper.vm.connections).toEqual([{ id: 'conn-1', name: 'Conn A' }])
    expect(wrapper.vm.agentOptions).toEqual(['Agent-1', 'Agent-2'])
    expect(wrapper.vm.severityOptions).toEqual(['critical', 'low'])
    expect(wrapper.vm.traceability).toEqual({ nuevas: 1, persistentes: 1, remediadas: 1 })
  })

  it('renders an error state when the vulnerability request fails', async () => {
    vulnService.getVulns.mockRejectedValueOnce(new Error('Network error'))

    const wrapper = mount(Dashboard)
    await flushPromises()

    expect(wrapper.vm.loading).toBe(false)
    expect(wrapper.vm.error).toBe('No se pudieron cargar las vulnerabilidades.')
    expect(wrapper.vm.vulns).toEqual([])
    expect(wrapper.vm.totalItems).toBe(0)
  })

  it('toggles and clears advanced filters', async () => {
    const wrapper = mount(Dashboard)
    await flushPromises()

    const filterBtn = wrapper.find('.btn-filter-toggle')
    await filterBtn.trigger('click')
    expect(wrapper.vm.showFilters).toBe(true)

    wrapper.vm.selectedConnection = 'conn-1'
    wrapper.vm.selectedAgents = ['Agent-1']
    wrapper.vm.selectedVulns = ['CVE-2023-1234']
    wrapper.vm.selectedPackages = ['bash']
    wrapper.vm.selectedSeverities = ['critical']
    wrapper.vm.scoreMin = 1
    wrapper.vm.scoreMax = 9

    wrapper.vm.clearFilters()
    await flushPromises()

    expect(wrapper.vm.selectedConnection).toBe('')
    expect(wrapper.vm.selectedAgents).toEqual([])
    expect(wrapper.vm.selectedVulns).toEqual([])
    expect(wrapper.vm.selectedPackages).toEqual([])
    expect(wrapper.vm.selectedSeverities).toEqual([])
    expect(wrapper.vm.scoreMin).toBe('')
    expect(wrapper.vm.scoreMax).toBe('')
    expect(vulnService.getFilterOptions).toHaveBeenCalled()
  })

  it('resets dependent filters and fetches connection scoped data', async () => {
    const wrapper = mount(Dashboard)
    await flushPromises()

    wrapper.vm.selectedConnection = 'conn-1'
    wrapper.vm.selectedAgents = ['Agent-1']
    wrapper.vm.selectedVulns = ['CVE-2023-1234']
    wrapper.vm.selectedPackages = ['bash']
    wrapper.vm.selectedSeverities = ['critical']
    wrapper.vm.scoreMin = 2
    wrapper.vm.scoreMax = 9

    wrapper.vm.onConnectionChange()
    await flushPromises()

    expect(wrapper.vm.selectedAgents).toEqual([])
    expect(wrapper.vm.selectedVulns).toEqual([])
    expect(wrapper.vm.selectedPackages).toEqual([])
    expect(wrapper.vm.selectedSeverities).toEqual([])
    expect(vulnService.getFilterOptions).toHaveBeenLastCalledWith('conn-1')
    expect(vulnService.getEvolutionSummary).toHaveBeenLastCalledWith({ connection_id: 'conn-1' })
  })

  it('sorts server-side and paginates through result pages', async () => {
    vulnService.getVulns.mockResolvedValue({ data: { items: mockItems, total: 500 } })
    const wrapper = mount(Dashboard)
    await flushPromises()

    expect(wrapper.vm.totalPages).toBe(10)
    expect(wrapper.vm.visiblePages).toEqual([1, 2, 3, 4, 5, 6, 'right-ellipsis', 10])

    wrapper.vm.sortBy('severity')
    await flushPromises()
    expect(wrapper.vm.sortKey).toBe('severity')
    expect(wrapper.vm.sortOrder).toBe('asc')

    wrapper.vm.sortBy('severity')
    await flushPromises()
    expect(wrapper.vm.sortOrder).toBe('desc')

    wrapper.vm.sortBy('severity')
    await flushPromises()
    expect(wrapper.vm.sortKey).toBe('last_seen')
    expect(wrapper.vm.sortOrder).toBe('desc')

    wrapper.vm.nextPage()
    await flushPromises()
    expect(wrapper.vm.currentPage).toBe(2)

    wrapper.vm.currentPage = 5
    await flushPromises()
    expect(wrapper.vm.visiblePages).toEqual([
      1,
      'left-ellipsis',
      3,
      4,
      5,
      6,
      7,
      'right-ellipsis',
      10
    ])

    wrapper.vm.jumpForward()
    await flushPromises()
    expect(wrapper.vm.currentPage).toBe(10)

    wrapper.vm.prevPage()
    await flushPromises()
    expect(wrapper.vm.currentPage).toBe(9)
  })

  it('starts the background sync job from the action button', async () => {
    const wrapper = mount(Dashboard)
    await flushPromises()

    await wrapper.find('.btn-primary').trigger('click')
    expect(startSync).toHaveBeenCalledTimes(1)
    expect(resumeIfActive).toHaveBeenCalledTimes(1)
    expect(onDone).toHaveBeenCalledTimes(1)
  })

  it('formats dates, severity labels and timeline helpers', async () => {
    const wrapper = mount(Dashboard)
    await flushPromises()

    expect(wrapper.vm.formatDate(null)).toBe('N/A')
    expect(wrapper.vm.timeAgo(null)).toBe('N/A')
    expect(wrapper.vm.timeAgo(new Date())).toBe('Justo ahora')
    expect(wrapper.vm.isNew(null)).toBe(false)
    expect(wrapper.vm.isNew(new Date().toISOString())).toBe(true)
    expect(wrapper.vm.isRecentlySeen(new Date().toISOString())).toBe(true)
    expect(wrapper.vm.getSeverityLevel('critical')).toBe(4)
    expect(wrapper.vm.getSeverityLevel('alta')).toBe(3)
    expect(wrapper.vm.getSeverityLevel('media')).toBe(2)
    expect(wrapper.vm.getSeverityLevel('low')).toBe(1)
    expect(wrapper.vm.getSeverityClass('high')).toBe('badge badge-critical')
    expect(wrapper.vm.getSeverityBadgeClass('critical')).toBe('badge-critical')
    expect(wrapper.vm.getSeverityBadgeClass('high')).toBe('badge-high')
    expect(wrapper.vm.getTimelineProgress({})).toBe(0)
    expect(wrapper.vm.getWeeklyBarWidth(1)).toBeGreaterThan(0)
  })
})

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import Timeline from '@/presentation/views/Timeline.vue'
import wazuhService from '@/application/services/wazuhService'
import vulnService from '@/application/services/vulnService'
import TimelineFilters from '@/presentation/views/timeline/components/TimelineFilters.vue'
import TimelineDetailModal from '@/presentation/views/timeline/components/TimelineDetailModal.vue'

vi.mock('@/application/services/wazuhService', () => ({
  default: { getConnections: vi.fn() }
}))

vi.mock('@/application/services/vulnService', () => ({
  default: {
    getFilterOptions: vi.fn(),
    getThreatSpans: vi.fn(),
    getVulnHistory: vi.fn()
  }
}))

const threatResponse = {
  data: {
    range: { start: '2026-03-01T00:00:00Z', end: '2026-03-31T00:00:00Z' },
    total: 1,
    active: 1,
    resolved: 0,
    returned: 1,
    items: [
      {
        id: 7,
        cve_id: 'CVE-2023-1234',
        agent_name: 'srv-01',
        package_name: 'openssl',
        package_version: '1.1.1',
        severity: 'High',
        status: 'ACTIVE',
        start: '2026-03-05T00:00:00Z',
        end: null,
        last_seen: '2026-03-30T00:00:00Z'
      }
    ]
  }
}

describe('Timeline.vue', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    wazuhService.getConnections.mockResolvedValue({
      data: [
        { id: 1, name: 'Connection 1' },
        { id: 2, name: 'Connection 2' }
      ]
    })
    vulnService.getFilterOptions.mockResolvedValue({
      data: {
        agents: ['srv-01', 'srv-02'],
        cves: ['CVE-2023-1234'],
        severities: ['CRITICAL', 'HIGH']
      }
    })
    vulnService.getThreatSpans.mockResolvedValue(threatResponse)
    vulnService.getVulnHistory.mockResolvedValue({
      data: {
        id: 7,
        history: [
          { id: 1, action: 'DETECTED', details: 'x', timestamp: '2026-03-05T00:00:00Z' }
        ]
      }
    })
  })

  it('renders the timeline structure and loads connections on mount', async () => {
    const wrapper = mount(Timeline)
    await flushPromises()

    expect(wrapper.find('.timeline-view').exists()).toBe(true)
    expect(wrapper.text()).toContain('Linea del tiempo')
    expect(wazuhService.getConnections).toHaveBeenCalledTimes(1)
    expect(wrapper.vm.connections).toHaveLength(2)
  })

  it('shows the initial empty state', () => {
    const wrapper = mount(Timeline)

    expect(wrapper.find('.empty-card').exists()).toBe(true)
    expect(wrapper.vm.selectedConnection).toBe('')
    expect(wrapper.vm.selectedAgents).toEqual([])
    expect(wrapper.vm.selectedVulns).toEqual([])
    expect(wrapper.vm.selectedSeverities).toEqual([])
    expect(typeof wrapper.vm.startDate).toBe('string')
    expect(typeof wrapper.vm.endDate).toBe('string')
    expect(wrapper.vm.modalOpen).toBe(false)
  })

  it('loads filter options and clears dependent filters when connection changes', async () => {
    const wrapper = mount(Timeline)
    await flushPromises()

    wrapper.vm.selectedConnection = '1'
    wrapper.vm.selectedAgents = ['old-agent']
    wrapper.vm.selectedVulns = ['old-cve']
    wrapper.vm.selectedSeverities = ['LOW']
    await wrapper.vm.onConnectionChange()
    await flushPromises()

    expect(vulnService.getFilterOptions).toHaveBeenCalledWith('1')
    expect(wrapper.vm.selectedAgents).toEqual([])
    expect(wrapper.vm.selectedVulns).toEqual([])
    expect(wrapper.vm.selectedSeverities).toEqual([])
    expect(wrapper.vm.agentOpts).toEqual(['srv-01', 'srv-02'])
    expect(wrapper.vm.vulnOpts).toEqual(['CVE-2023-1234'])
    expect(wrapper.vm.severityOpts).toEqual(['CRITICAL', 'HIGH'])
  })

  it('handles connection and filter option errors gracefully', async () => {
    wazuhService.getConnections.mockRejectedValueOnce(new Error('Network error'))
    const wrapper = mount(Timeline)
    await flushPromises()

    expect(wrapper.vm.connections).toEqual([])
    expect(wrapper.vm.statusError).toBe('No se pudieron cargar las conexiones Wazuh.')

    wrapper.vm.errorBanner = ''
    wrapper.vm.selectedConnection = '1'
    vulnService.getFilterOptions.mockRejectedValueOnce(new Error('Filter error'))
    await wrapper.vm.onConnectionChange()
    await flushPromises()

    expect(wrapper.vm.statusError).toContain('No se pudieron cargar agentes y CVEs')
  })

  it('builds the timeline with threat spans', async () => {
    const wrapper = mount(Timeline)
    await flushPromises()

    wrapper.vm.selectedConnection = '1'
    await wrapper.vm.buildTimeline()
    await flushPromises()

    expect(vulnService.getThreatSpans).toHaveBeenCalled()
    expect(wrapper.vm.hasBuilt).toBe(true)
    expect(wrapper.vm.bars).toHaveLength(1)
    expect(wrapper.vm.counts.total).toBe(1)
  })

  it('shows build errors through statusError', async () => {
    vulnService.getThreatSpans.mockRejectedValueOnce(new Error('Build failed'))
    const wrapper = mount(Timeline)
    await flushPromises()

    wrapper.vm.selectedConnection = '1'
    await wrapper.vm.buildTimeline()
    await flushPromises()

    expect(wrapper.vm.hasBuilt).toBe(false)
    expect(wrapper.vm.statusError).toContain('linea de tiempo')
  })

  it('opens the detail modal and loads the threat history', async () => {
    const wrapper = mount(Timeline)
    await flushPromises()

    await wrapper.vm.openThreat({ id: 7, cve_id: 'CVE-2023-1234' })
    await flushPromises()

    expect(wrapper.vm.modalOpen).toBe(true)
    expect(vulnService.getVulnHistory).toHaveBeenCalledWith(7)
    expect(wrapper.vm.selectedEvent.history).toHaveLength(1)
    expect(wrapper.vm.modalLoading).toBe(false)
  })

  it('keeps the modal open with empty history when threat history fails', async () => {
    vulnService.getVulnHistory.mockRejectedValueOnce(new Error('History error'))
    const wrapper = mount(Timeline)
    await flushPromises()

    await wrapper.vm.openThreat({ id: 7, cve_id: 'CVE-2023-1234' })
    await flushPromises()

    expect(wrapper.vm.modalOpen).toBe(true)
    expect(wrapper.vm.selectedEvent.history).toEqual([])
    expect(wrapper.vm.modalLoading).toBe(false)
  })

  it('updates state when filters emit updates', async () => {
    const wrapper = mount(Timeline)
    await flushPromises()

    const filters = wrapper.findComponent(TimelineFilters)
    await filters.vm.$emit('update:selectedConnection', '2')
    await filters.vm.$emit('update:selectedAgents', ['srv-X'])
    await filters.vm.$emit('update:selectedVulns', ['CVE-Y'])
    await filters.vm.$emit('update:selectedSeverities', ['HIGH'])
    await filters.vm.$emit('update:startDate', '2026-05-05')
    await filters.vm.$emit('update:endDate', '2026-05-10')

    expect(wrapper.vm.selectedConnection).toBe('2')
    expect(wrapper.vm.selectedAgents).toEqual(['srv-X'])
    expect(wrapper.vm.selectedVulns).toEqual(['CVE-Y'])
    expect(wrapper.vm.selectedSeverities).toEqual(['HIGH'])
    expect(wrapper.vm.startDate).toBe('2026-05-05')
    expect(wrapper.vm.endDate).toBe('2026-05-10')
  })

  it('closes the detail modal when it emits close', async () => {
    const wrapper = mount(Timeline)
    wrapper.vm.modalOpen = true
    await wrapper.vm.$nextTick()

    const modal = wrapper.findComponent(TimelineDetailModal)
    await modal.vm.$emit('close')

    expect(wrapper.vm.modalOpen).toBe(false)
  })
})

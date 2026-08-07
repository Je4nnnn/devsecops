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
      data: { agents: ['srv-01', 'srv-02'], cves: ['CVE-2023-1234'], severities: ['CRITICAL', 'HIGH'] }
    })
    vulnService.getThreatSpans.mockResolvedValue(threatResponse)
    vulnService.getVulnHistory.mockResolvedValue({
      data: { id: 7, history: [{ id: 1, action: 'DETECTED', details: 'x', timestamp: '2026-03-05T00:00:00Z' }] }
    })
  })

  it('renders the timeline structure', async () => {
    const wrapper = mount(Timeline)
    await flushPromises()
    expect(wrapper.find('.timeline-view').exists()).toBe(true)
    expect(wrapper.text()).toContain('Linea del tiempo')
  })

  it('loads connections on mount', async () => {
    mount(Timeline)
    await flushPromises()
    expect(wazuhService.getConnections).toHaveBeenCalled()
  })

  it('displays the empty card initially', () => {
    const wrapper = mount(Timeline)
    expect(wrapper.find('.empty-card').exists()).toBe(true)
  })

  it('initializes with the expected state', () => {
    const wrapper = mount(Timeline)
    expect(wrapper.vm.connections).toEqual([])
    expect(wrapper.vm.selectedConnection).toBe('')
    expect(wrapper.vm.selectedAgents).toEqual([])
    expect(wrapper.vm.selectedVulns).toEqual([])
    expect(wrapper.vm.modalOpen).toBe(false)
    expect(typeof wrapper.vm.startDate).toBe('string')
  })

  it('loads agent and CVE options when connection changes', async () => {
    const wrapper = mount(Timeline)
    await flushPromises()

    wrapper.vm.selectedConnection = '1'
    await wrapper.vm.onConnectionChange()
    await flushPromises()

    expect(vulnService.getFilterOptions).toHaveBeenCalledWith('1')
    expect(wrapper.vm.agentOpts).toEqual(['srv-01', 'srv-02'])
    expect(wrapper.vm.vulnOpts).toEqual(['CVE-2023-1234'])
    expect(wrapper.vm.severityOpts).toEqual(['CRITICAL', 'HIGH'])
  })

  it('clears agent and vuln selection when connection changes', async () => {
    const wrapper = mount(Timeline)
    await flushPromises()

    wrapper.vm.selectedConnection = '1'
    wrapper.vm.selectedAgents = ['srv-01']
    wrapper.vm.selectedVulns = ['CVE-123']
    await wrapper.vm.onConnectionChange()

    expect(wrapper.vm.selectedAgents).toEqual([])
    expect(wrapper.vm.selectedVulns).toEqual([])
  })

  it('builds the timeline when buildTimeline is called', async () => {
    const wrapper = mount(Timeline)
    await flushPromises()

    wrapper.vm.selectedConnection = '1'
    await wrapper.vm.buildTimeline()
    await flushPromises()

    expect(vulnService.getThreatSpans).toHaveBeenCalled()
    expect(wrapper.vm.hasBuilt).toBe(true)
  })

  it('opens the detail modal and loads the threat history', async () => {
    const wrapper = mount(Timeline)
    await flushPromises()

    await wrapper.vm.openThreat({ id: 7, cve_id: 'CVE-2023-1234' })
    await flushPromises()

    expect(wrapper.vm.modalOpen).toBe(true)
    expect(vulnService.getVulnHistory).toHaveBeenCalledWith(7)
    expect(wrapper.vm.selectedEvent.history).toHaveLength(1)
  })

  it('handles a connection load error gracefully', async () => {
    wazuhService.getConnections.mockRejectedValueOnce(new Error('Network error'))
    const wrapper = mount(Timeline)
    await flushPromises()
    expect(wrapper.vm.connections).toEqual([])
  })

  it('sets an error banner when loading filter options fails', async () => {
    const wrapper = mount(Timeline)
    await flushPromises()

    wrapper.vm.selectedConnection = '1'
    vulnService.getFilterOptions.mockRejectedValueOnce(new Error('Fetch failed'))
    await wrapper.vm.onConnectionChange()
    await flushPromises()

    expect(wrapper.vm.errorBanner).toContain('No se pudieron cargar los filtros')
  })

  it('updates state when filters emit updates', async () => {
    const wrapper = mount(Timeline)
    await flushPromises()

    const filters = wrapper.findComponent(TimelineFilters)
    await filters.vm.$emit('update:selectedConnection', '2')
    expect(wrapper.vm.selectedConnection).toBe('2')

    await filters.vm.$emit('update:selectedAgents', ['srv-X'])
    expect(wrapper.vm.selectedAgents).toEqual(['srv-X'])

    await filters.vm.$emit('update:startDate', '2026-05-05')
    expect(wrapper.vm.startDate).toBe('2026-05-05')
  })

  it('closes the modal when the detail modal emits close', async () => {
    const wrapper = mount(Timeline)
    wrapper.vm.modalOpen = true
    await wrapper.vm.$nextTick()

    const modal = wrapper.findComponent(TimelineDetailModal)
    await modal.vm.$emit('close')
    expect(wrapper.vm.modalOpen).toBe(false)
  })
})

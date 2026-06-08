import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import Timeline from '@/presentation/views/Timeline.vue'
import wazuhService from '@/application/services/wazuhService'
import vulnService from '@/application/services/vulnService'
import TimelineFilters from '@/presentation/views/timeline/components/TimelineFilters.vue'
import TimelineDetailModal from '@/presentation/views/timeline/components/TimelineDetailModal.vue'

vi.mock('@/application/services/wazuhService', () => ({
  default: {
    getConnections: vi.fn()
  }
}))

vi.mock('@/application/services/vulnService', () => ({
  default: {
    getFilterOptions: vi.fn(),
    getTraceabilityTimeline: vi.fn(),
    getTimelineDetails: vi.fn()
  }
}))

describe('Timeline.vue', () => {
  const points = [
    { bucket: '2026-03-07T00:00:00Z', nuevas: 2, reemergidas: 0, remediadas: 0 },
    { bucket: '2026-03-08T00:00:00Z', nuevas: 0, reemergidas: 1, remediadas: 1 }
  ]

  beforeEach(() => {
    vi.clearAllMocks()
    wazuhService.getConnections.mockResolvedValue({
      data: [
        { id: '1', name: 'Connection 1', api_url: 'http://test1' },
        { id: '2', name: 'Connection 2', api_url: 'http://test2' }
      ]
    })
    vulnService.getFilterOptions.mockResolvedValue({
      data: { agents: ['Agent 1', 'Agent 2'], cves: ['CVE-001', 'CVE-002'] }
    })
    vulnService.getTraceabilityTimeline.mockResolvedValue({
      data: { bucket: '1 day', points }
    })
    vulnService.getTimelineDetails.mockResolvedValue({
      data: [{ cve_id: 'CVE-001', agent_name: 'Agent 1' }]
    })
  })

  it('renders main timeline structure and loads connections on mount', async () => {
    const wrapper = mount(Timeline)
    await flushPromises()

    expect(wrapper.find('.timeline-view').exists()).toBe(true)
    expect(wrapper.text()).toContain('Linea del tiempo')
    expect(wazuhService.getConnections).toHaveBeenCalledTimes(1)
    expect(wrapper.vm.connections).toHaveLength(2)
  })

  it('shows an empty card before building the timeline', () => {
    const wrapper = mount(Timeline)

    expect(wrapper.find('.empty-card').exists()).toBe(true)
    expect(wrapper.vm.selectedConnection).toBe('')
    expect(wrapper.vm.selectedAgents).toEqual([])
    expect(wrapper.vm.selectedVulns).toEqual([])
    expect(wrapper.vm.period).toBe('30d')
    expect(wrapper.vm.modalOpen).toBe(false)
  })

  it('loads filter options and clears dependent filters on connection change', async () => {
    const wrapper = mount(Timeline)
    await flushPromises()

    wrapper.vm.selectedAgents = ['old-agent']
    wrapper.vm.selectedVulns = ['old-cve']
    wrapper.vm.selectedConnection = '1'

    await wrapper.vm.onConnectionChange()
    await flushPromises()

    expect(wrapper.vm.selectedAgents).toEqual([])
    expect(wrapper.vm.selectedVulns).toEqual([])
    expect(wrapper.vm.agentOpts).toEqual(['Agent 1', 'Agent 2'])
    expect(wrapper.vm.vulnOpts).toEqual(['CVE-001', 'CVE-002'])
    expect(vulnService.getFilterOptions).toHaveBeenCalledWith('1')
  })

  it('handles connection and filter option errors gracefully', async () => {
    wazuhService.getConnections.mockRejectedValueOnce(new Error('Network error'))
    const wrapper = mount(Timeline)
    await flushPromises()

    expect(wrapper.vm.connections).toEqual([])
    expect(wrapper.vm.errorBanner).toBe('No se pudieron cargar las conexiones Wazuh.')

    wrapper.vm.errorBanner = ''
    wrapper.vm.selectedConnection = '1'
    vulnService.getFilterOptions.mockRejectedValueOnce(new Error('Filter error'))
    await wrapper.vm.onConnectionChange()

    expect(wrapper.vm.errorBanner).toBe('No se pudieron cargar agentes y CVEs para la conexion seleccionada.')
  })

  it('builds the timeline, sets zoom and exposes a year label', async () => {
    const wrapper = mount(Timeline)
    await flushPromises()

    wrapper.vm.selectedConnection = '1'
    wrapper.vm.period = '7d'
    await wrapper.vm.buildTimeline()
    await flushPromises()

    expect(wrapper.vm.hasBuilt).toBe(true)
    expect(wrapper.vm.allSlots.length).toBe(2)
    expect(wrapper.vm.visibleSlots.length).toBeGreaterThan(0)
    expect(wrapper.vm.yearLabel).toBe('2026')
    expect(vulnService.getTraceabilityTimeline).toHaveBeenCalledWith({
      params: { period: '7d', connection_id: '1' }
    })
  })

  it('shows build errors through statusError', async () => {
    vulnService.getTraceabilityTimeline.mockRejectedValueOnce(new Error('Build failed'))
    const wrapper = mount(Timeline)
    await flushPromises()

    wrapper.vm.selectedConnection = '1'
    await wrapper.vm.buildTimeline()
    await flushPromises()

    expect(wrapper.vm.hasBuilt).toBe(false)
    expect(wrapper.vm.statusError).toContain('linea de tiempo')
  })

  it('opens a slot modal and loads bucket details', async () => {
    const wrapper = mount(Timeline)
    await flushPromises()

    wrapper.vm.selectedConnection = '1'
    await wrapper.vm.buildTimeline()
    await flushPromises()

    const slot = wrapper.vm.allSlots[0]
    await wrapper.vm.openModal(slot)
    await flushPromises()

    expect(wrapper.vm.modalOpen).toBe(true)
    expect(wrapper.vm.selectedEvent.details).toEqual([{ cve_id: 'CVE-001', agent_name: 'Agent 1' }])
    expect(vulnService.getTimelineDetails).toHaveBeenCalled()
  })

  it('updates period and state through child component events', async () => {
    const wrapper = mount(Timeline)
    await flushPromises()

    wrapper.vm.setPeriod('7d')
    expect(wrapper.vm.period).toBe('7d')

    const filters = wrapper.findComponent(TimelineFilters)
    await filters.vm.$emit('update:selectedConnection', '2')
    await filters.vm.$emit('update:selectedAgents', ['Agent X'])
    await filters.vm.$emit('update:selectedVulns', ['CVE-Y'])
    await filters.vm.$emit('update:customDate', '2026-05-05')

    expect(wrapper.vm.selectedConnection).toBe('2')
    expect(wrapper.vm.selectedAgents).toEqual(['Agent X'])
    expect(wrapper.vm.selectedVulns).toEqual(['CVE-Y'])
    expect(wrapper.vm.customDate).toBe('2026-05-05')
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

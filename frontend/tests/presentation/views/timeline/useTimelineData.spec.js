import { describe, it, expect, vi, beforeEach } from 'vitest'
import { ref } from 'vue'
import useTimelineData from '@/presentation/views/timeline/useTimelineData'
import vulnService from '@/application/services/vulnService'

vi.mock('@/application/services/vulnService', () => ({
  default: {
    getTraceabilityTimeline: vi.fn(),
    getTimelineDetails: vi.fn()
  }
}))

describe('useTimelineData', () => {
  let props
  let timeline

  const points = [
    {
      bucket: '2026-03-07T00:00:00Z',
      nuevas: 2,
      reemergidas: 0,
      remediadas: 0
    },
    {
      bucket: '2026-03-08T00:00:00Z',
      nuevas: 1,
      reemergidas: 1,
      remediadas: 2
    },
    {
      bucket: '2026-03-09T00:00:00Z',
      nuevas: 0,
      reemergidas: 0,
      remediadas: 1
    },
    {
      bucket: '2026-03-10T00:00:00Z',
      nuevas: 0,
      reemergidas: 0,
      remediadas: 0
    }
  ]

  beforeEach(() => {
    vi.clearAllMocks()
    props = {
      selectedConnection: ref('1'),
      selectedAgents: ref([]),
      selectedVulns: ref([]),
      period: ref('7d')
    }
    timeline = useTimelineData(props)
    vulnService.getTraceabilityTimeline.mockResolvedValue({
      data: { bucket: '1 day', points }
    })
    vulnService.getTimelineDetails.mockResolvedValue({
      data: [{ cve_id: 'CVE-2023-1234', agent_name: 'srv-01' }]
    })
  })

  it('builds traceability slots and totals from backend timeline points', async () => {
    const result = await timeline.build()

    expect(result.initialZoom).toBe(2)
    expect(timeline.hasBuilt.value).toBe(true)
    expect(timeline.loading.value).toBe(false)
    expect(timeline.latestSnap.value).toEqual({ total: 7, pending: 4, resolved: 3 })
    expect(timeline.allSlots.value).toHaveLength(3)
    expect(timeline.allSlots.value.map(slot => slot.type)).toEqual(['detection', 'mixed', 'resolution'])
    expect(timeline.paintedCount.value).toBe(3)
    expect(vulnService.getTraceabilityTimeline).toHaveBeenCalledWith({
      params: { period: '7d', connection_id: '1' }
    })
  })

  it('returns empty state when no connection is selected', async () => {
    const emptyTimeline = useTimelineData({
      ...props,
      selectedConnection: ref('')
    })

    const result = await emptyTimeline.build()

    expect(result.initialZoom).toBe(0)
    expect(emptyTimeline.hasBuilt.value).toBe(false)
    expect(vulnService.getTraceabilityTimeline).not.toHaveBeenCalled()
  })

  it('maps period and filters to backend params', async () => {
    props.period.value = '24h'
    props.selectedAgents.value = ['srv-01', 'srv-02']
    props.selectedVulns.value = ['CVE-1']

    const result = await timeline.build()

    expect(result.initialZoom).toBe(4)
    expect(vulnService.getTraceabilityTimeline).toHaveBeenCalledWith({
      params: {
        period: '24h',
        connection_id: '1',
        agent_name: 'srv-01,srv-02',
        cve_id: 'CVE-1'
      }
    })
  })

  it('uses fallback zoom for long periods', async () => {
    props.period.value = '30d'
    expect((await timeline.build()).initialZoom).toBe(0)

    props.period.value = 'all'
    expect((await timeline.build()).initialZoom).toBe(0)
  })

  it('sets a warning when the selected period has no traceability points', async () => {
    vulnService.getTraceabilityTimeline.mockResolvedValueOnce({ data: { bucket: '1 day', points: [] } })

    await timeline.build()

    expect(timeline.hasBuilt.value).toBe(true)
    expect(timeline.allSlots.value).toEqual([])
    expect(timeline.warningMessage.value).toContain('No hay eventos')
  })

  it('propagates backend errors while setting a user-facing message', async () => {
    vulnService.getTraceabilityTimeline.mockRejectedValueOnce(new Error('API Error'))

    await expect(timeline.build()).rejects.toThrow('API Error')
    expect(timeline.loading.value).toBe(false)
    expect(timeline.errorMessage.value).toContain('linea de tiempo')
  })

  it('loads bucket drill-down details with selected filters', async () => {
    props.selectedAgents.value = ['srv-01']
    props.selectedVulns.value = ['CVE-2023-1234']
    await timeline.build()

    const slot = timeline.allSlots.value[0]
    const details = await timeline.fetchSlotDetails(slot)

    expect(details).toEqual([{ cve_id: 'CVE-2023-1234', agent_name: 'srv-01' }])
    expect(vulnService.getTimelineDetails).toHaveBeenCalledWith({
      params: expect.objectContaining({
        connection_id: '1',
        agent_name: 'srv-01',
        cve_id: 'CVE-2023-1234'
      })
    })
  })
})

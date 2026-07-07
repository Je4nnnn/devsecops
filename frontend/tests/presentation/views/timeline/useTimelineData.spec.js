import { describe, it, expect, vi, beforeEach } from 'vitest'
import { ref } from 'vue'
import useTimelineData from '@/presentation/views/timeline/useTimelineData'
import vulnService from '@/application/services/vulnService'

vi.mock('@/application/services/vulnService', () => ({
  default: {
    getThreatSpans: vi.fn()
  }
}))

const makeResponse = (overrides = {}) => ({
  data: {
    range: { start: '2026-03-01T00:00:00Z', end: '2026-03-31T00:00:00Z' },
    total: 2,
    active: 1,
    resolved: 1,
    returned: 2,
    items: [
      {
        id: 1,
        cve_id: 'CVE-2023-1234',
        agent_name: 'srv-01',
        package_name: 'openssl',
        package_version: '1.1.1',
        severity: 'High',
        status: 'RESOLVED',
        start: '2026-03-06T00:00:00Z',
        end: '2026-03-16T00:00:00Z',
        last_seen: '2026-03-16T00:00:00Z'
      },
      {
        id: 2,
        cve_id: 'CVE-2023-5678',
        agent_name: 'srv-02',
        package_name: 'curl',
        package_version: '7.81',
        severity: 'Critical',
        status: 'ACTIVE',
        start: '2026-02-20T00:00:00Z', // antes del rango -> clip left
        end: null,
        last_seen: '2026-03-30T00:00:00Z'
      }
    ],
    ...overrides
  }
})

describe('useTimelineData', () => {
  let props

  beforeEach(() => {
    vi.clearAllMocks()
    props = {
      selectedConnection: ref('1'),
      selectedAgents: ref([]),
      selectedVulns: ref([]),
      selectedSeverities: ref([]),
      startDate: ref('2026-03-01'),
      endDate: ref('2026-03-31')
    }
  })

  it('builds the threat list and distinct counts', async () => {
    vulnService.getThreatSpans.mockResolvedValueOnce(makeResponse())
    const tl = useTimelineData(props)

    await tl.build()

    expect(tl.hasBuilt.value).toBe(true)
    expect(tl.bars.value).toHaveLength(2)
    expect(tl.counts.value.total).toBe(2)
    expect(tl.counts.value.active).toBe(1)
    expect(tl.counts.value.resolved).toBe(1)
  })

  it('does nothing without a selected connection', async () => {
    const tl = useTimelineData({ ...props, selectedConnection: ref('') })
    await tl.build()
    expect(tl.hasBuilt.value).toBe(false)
    expect(vulnService.getThreatSpans).not.toHaveBeenCalled()
  })

  it('clamps bar geometry to the visible range', async () => {
    vulnService.getThreatSpans.mockResolvedValueOnce(makeResponse())
    const tl = useTimelineData(props)
    await tl.build()

    const resolved = tl.bars.value.find(b => b.id === 1)
    // 5 días desde el inicio sobre 30 días de rango
    expect(resolved.leftPct).toBeCloseTo((5 / 30) * 100, 1)
    expect(resolved.ongoing).toBe(false)
    expect(resolved.clippedRight).toBe(false)

    const ongoing = tl.bars.value.find(b => b.id === 2)
    // detectada antes del rango -> recortada a la izquierda (left 0)
    expect(ongoing.clippedLeft).toBe(true)
    expect(ongoing.leftPct).toBe(0)
    expect(ongoing.ongoing).toBe(true)
    expect(ongoing.clippedRight).toBe(true)
  })

  it('warns when there are more threats than returned', async () => {
    vulnService.getThreatSpans.mockResolvedValueOnce(makeResponse({ total: 500, returned: 2 }))
    const tl = useTimelineData(props)
    await tl.build()
    expect(tl.warningMessage.value).toContain('500')
  })

  it('warns when the range has no threats', async () => {
    vulnService.getThreatSpans.mockResolvedValueOnce(
      makeResponse({ total: 0, active: 0, resolved: 0, returned: 0, items: [] })
    )
    const tl = useTimelineData(props)
    await tl.build()
    expect(tl.warningMessage.value).toContain('No hay amenazas')
  })

  it('surfaces API errors', async () => {
    vulnService.getThreatSpans.mockRejectedValueOnce(new Error('API Error'))
    const tl = useTimelineData(props)
    await expect(tl.build()).rejects.toThrow('API Error')
    expect(tl.errorMessage.value).toContain('generar la linea de tiempo')
  })

  it('passes filters as query params', async () => {
    vulnService.getThreatSpans.mockResolvedValueOnce(makeResponse())
    const tl = useTimelineData({
      ...props,
      selectedAgents: ref(['srv-01']),
      selectedVulns: ref(['CVE-2023-1234']),
      selectedSeverities: ref(['CRITICAL', 'HIGH'])
    })
    await tl.build()

    const params = vulnService.getThreatSpans.mock.calls[0][0]
    expect(params.connection_id).toBe('1')
    expect(params.agent_name).toBe('srv-01')
    expect(params.cve_id).toBe('CVE-2023-1234')
    expect(params.severity).toBe('CRITICAL,HIGH')
    expect(params.start).toBeTruthy()
    expect(params.end).toBeTruthy()
  })
})

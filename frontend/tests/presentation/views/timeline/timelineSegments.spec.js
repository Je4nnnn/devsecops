import { describe, it, expect, vi, beforeEach } from 'vitest'
import { ref } from 'vue'
import useTimelineData, { buildSegments } from '@/presentation/views/timeline/useTimelineData'
import vulnService from '@/application/services/vulnService'

vi.mock('@/application/services/vulnService', () => ({
  default: { getThreatSpans: vi.fn() }
}))

const START = new Date('2026-03-01T00:00:00Z').getTime()
const END = new Date('2026-03-31T00:00:00Z').getTime()
const day = n => new Date(`2026-03-${String(n).padStart(2, '0')}T00:00:00Z`).getTime()

// Igual que en el composable: % recortado al rango visible.
const pct = ms => ((Math.min(Math.max(ms, START), END) - START) / (END - START)) * 100

const kinds = segments => segments.map(s => s.kind)

describe('buildSegments', () => {
  it('pinta blanco entre el inicio de la cobertura y la detección', () => {
    const segments = buildSegments({
      startMs: START, endMs: END,
      since: day(5),        // hay datos desde el día 5
      detected: day(11),    // la amenaza aparece el día 11
      resolvedMs: null, ongoing: true, pct
    })

    expect(kinds(segments)).toEqual(['unknown', 'absent', 'active'])

    const absent = segments.find(s => s.kind === 'absent')
    expect(absent.leftPct).toBeCloseTo(pct(day(5)), 5)
    expect(absent.widthPct).toBeCloseTo(pct(day(11)) - pct(day(5)), 5)
  })

  it('NO pinta blanco cuando no consta que hubiera sincronización previa', () => {
    const segments = buildSegments({
      startMs: START, endMs: END,
      since: null,          // sin cobertura conocida
      detected: day(11), resolvedMs: null, ongoing: true, pct
    })

    expect(kinds(segments)).toEqual(['active'])
    expect(segments[0].leftPct).toBeCloseTo(pct(day(11)), 5)
  })

  it('marca como desconocido el tramo anterior a la primera sincronización', () => {
    const segments = buildSegments({
      startMs: START, endMs: END,
      since: day(10), detected: day(20), resolvedMs: null, ongoing: true, pct
    })

    const unknown = segments.find(s => s.kind === 'unknown')
    expect(unknown.leftPct).toBe(0)
    expect(unknown.widthPct).toBeCloseTo(pct(day(10)), 5)
  })

  it('pinta verde desde la resolución hasta el fin del rango', () => {
    const segments = buildSegments({
      startMs: START, endMs: END,
      since: day(1), detected: day(6), resolvedMs: day(16), ongoing: false, pct
    })

    expect(kinds(segments)).toContain('resolved')
    const resolved = segments.find(s => s.kind === 'resolved')
    expect(resolved.leftPct).toBeCloseTo(pct(day(16)), 5)
    expect(resolved.widthPct).toBeCloseTo(100 - pct(day(16)), 5)
  })

  it('no agrega tramo verde si la amenaza sigue activa', () => {
    const segments = buildSegments({
      startMs: START, endMs: END,
      since: day(1), detected: day(6), resolvedMs: null, ongoing: true, pct
    })
    expect(kinds(segments)).not.toContain('resolved')
    expect(segments.find(s => s.kind === 'active').widthPct).toBeCloseTo(100 - pct(day(6)), 5)
  })

  it('omite tramos de ancho despreciable', () => {
    // Detectada justo cuando arranca la cobertura: no hay periodo "no existía".
    const segments = buildSegments({
      startMs: START, endMs: END,
      since: day(5), detected: day(5), resolvedMs: null, ongoing: true, pct
    })
    expect(kinds(segments)).toEqual(['unknown', 'active'])
  })

  it('recorta una amenaza detectada antes del rango visible', () => {
    const segments = buildSegments({
      startMs: START, endMs: END,
      since: new Date('2026-01-01T00:00:00Z').getTime(),
      detected: new Date('2026-02-10T00:00:00Z').getTime(),
      resolvedMs: null, ongoing: true, pct
    })

    expect(kinds(segments)).toEqual(['active'])
    expect(segments[0].leftPct).toBe(0)
    expect(segments[0].widthPct).toBe(100)
  })
})

describe('useTimelineData · segmentos y filtros nuevos', () => {
  const props = () => ({
    selectedConnection: ref('1'),
    selectedAgents: ref([]),
    selectedVulns: ref([]),
    selectedSeverities: ref([]),
    selectedGroups: ref([]),
    selectedOsPlatforms: ref([]),
    selectedStatus: ref(''),
    startDate: ref('2026-03-01'),
    endDate: ref('2026-03-31')
  })

  const response = (items, coverage = { since: '2026-03-05T00:00:00Z' }) => ({
    data: {
      range: { start: '2026-03-01T00:00:00Z', end: '2026-03-31T00:00:00Z' },
      coverage,
      total: items.length,
      active: items.filter(i => i.status === 'ACTIVE').length,
      resolved: items.filter(i => i.status === 'RESOLVED').length,
      returned: items.length,
      items
    }
  })

  beforeEach(() => vi.clearAllMocks())

  it('deriva los tramos de cada amenaza a partir de la cobertura', async () => {
    vulnService.getThreatSpans.mockResolvedValueOnce(response([
      {
        id: 1, cve_id: 'CVE-1', agent_name: 'srv-01', package_name: 'openssl',
        severity: 'High', status: 'RESOLVED',
        start: '2026-03-11T00:00:00Z', resolved_at: '2026-03-21T00:00:00Z',
        end: '2026-03-21T00:00:00Z', last_seen: '2026-03-21T00:00:00Z'
      }
    ]))

    const tl = useTimelineData(props())
    await tl.build()

    const bar = tl.bars.value[0]
    expect(kinds(bar.segments)).toEqual(['unknown', 'absent', 'active', 'resolved'])
    expect(bar.ongoing).toBe(false)
    expect(tl.coverageSinceMs.value).toBe(new Date('2026-03-05T00:00:00Z').getTime())
  })

  it('usa resolved_at con prioridad sobre end', async () => {
    vulnService.getThreatSpans.mockResolvedValueOnce(response([
      {
        id: 2, cve_id: 'CVE-2', agent_name: 'srv-02', package_name: 'curl',
        severity: 'Critical', status: 'RESOLVED',
        start: '2026-03-06T00:00:00Z', resolved_at: '2026-03-10T00:00:00Z',
        end: '2026-03-25T00:00:00Z', last_seen: '2026-03-25T00:00:00Z'
      }
    ]))

    const tl = useTimelineData(props())
    await tl.build()

    expect(tl.bars.value[0].resolvedMs).toBe(new Date('2026-03-10T00:00:00Z').getTime())
  })

  it('sin cobertura no inventa periodos en blanco', async () => {
    vulnService.getThreatSpans.mockResolvedValueOnce(response([
      {
        id: 3, cve_id: 'CVE-3', agent_name: 'srv-03', package_name: 'nginx',
        severity: 'Low', status: 'ACTIVE',
        start: '2026-03-12T00:00:00Z', resolved_at: null, end: null,
        last_seen: '2026-03-30T00:00:00Z'
      }
    ], { since: null }))

    const tl = useTimelineData(props())
    await tl.build()

    expect(kinds(tl.bars.value[0].segments)).toEqual(['active'])
  })

  it('envía grupo, S.O. y estado como parámetros de consulta', async () => {
    vulnService.getThreatSpans.mockResolvedValueOnce(response([]))

    const tl = useTimelineData({
      ...props(),
      selectedGroups: ref(['web', 'db']),
      selectedOsPlatforms: ref(['ubuntu']),
      selectedStatus: ref('resuelta')
    })
    await tl.build()

    const params = vulnService.getThreatSpans.mock.calls[0][0]
    expect(params.group).toBe('web,db')
    expect(params.os_platform).toBe('ubuntu')
    expect(params.status).toBe('resuelta')
  })
})

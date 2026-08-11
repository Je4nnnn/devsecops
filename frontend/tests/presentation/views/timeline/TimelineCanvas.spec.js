import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import TimelineCanvas from '@/presentation/views/timeline/components/TimelineCanvas.vue'

const startMs = new Date('2026-03-01T00:00:00Z').getTime()
const endMs = new Date('2026-03-31T00:00:00Z').getTime()

const bars = [
  {
    id: 1,
    cve_id: 'CVE-2023-1234',
    agent_name: 'srv-01',
    package_name: 'openssl',
    package_version: '1.1.1',
    severity: 'High',
    status: 'RESOLVED',
    ongoing: false,
    clippedLeft: false,
    clippedRight: false,
    leftPct: 16.6,
    widthPct: 33.3,
    segments: [
      { kind: 'unknown', leftPct: 0, widthPct: 10 },
      { kind: 'absent', leftPct: 10, widthPct: 6.6 },
      { kind: 'active', leftPct: 16.6, widthPct: 33.3 },
      { kind: 'resolved', leftPct: 49.9, widthPct: 50.1 }
    ]
  },
  {
    id: 2,
    cve_id: 'CVE-2023-5678',
    agent_name: 'srv-02',
    package_name: 'curl',
    package_version: '7.81',
    severity: 'Critical',
    status: 'ACTIVE',
    ongoing: true,
    clippedLeft: true,
    clippedRight: true,
    leftPct: 0,
    widthPct: 100,
    segments: [{ kind: 'active', leftPct: 0, widthPct: 100 }]
  }
]

const mountCanvas = () =>
  mount(TimelineCanvas, {
    props: { bars, range: { startMs, endMs }, spanMs: endMs - startMs }
  })

describe('TimelineCanvas.vue', () => {
  it('renders one bar per threat', () => {
    const wrapper = mountCanvas()
    expect(wrapper.findAll('.gantt-bar')).toHaveLength(2)
    expect(wrapper.findAll('.gantt-row')).toHaveLength(2)
  })

  it('renders one calendar cell per visible month', () => {
    const wrapper = mountCanvas()
    expect(wrapper.findAll('.axis-month')).toHaveLength(1)
  })

  it('marks the ongoing threat with the ongoing class', () => {
    const wrapper = mountCanvas()
    const ongoingBar = wrapper.findAll('.gantt-bar')[1]
    expect(ongoingBar.classes()).toContain('ongoing')
    expect(ongoingBar.classes()).toContain('clip-left')
  })

  it('positions bars using leftPct / widthPct', () => {
    const wrapper = mountCanvas()
    const style = wrapper.findAll('.gantt-bar')[0].attributes('style')
    expect(style).toContain('left: 16.6%')
    expect(style).toContain('width: 33.3%')
  })

  it('renders the resolved period in its own green segment', () => {
    const wrapper = mountCanvas()
    const resolved = wrapper.findAll('.seg-resolved')
    expect(resolved).toHaveLength(1)
    expect(resolved[0].attributes('style')).toContain('left: 49.9%')
  })

  it('renders the "did not exist" gap and the unknown period', () => {
    const wrapper = mountCanvas()
    expect(wrapper.findAll('.seg-absent')).toHaveLength(1)
    expect(wrapper.findAll('.seg-unknown')).toHaveLength(1)
    expect(wrapper.find('.seg-absent').attributes('title')).toContain('no existía')
  })

  it('does not render context segments for an always-active threat', () => {
    const wrapper = mountCanvas()
    // Solo la amenaza resuelta aporta tramos de contexto.
    expect(wrapper.findAll('.gantt-seg')).toHaveLength(3)
  })

  it('survives bars without segment data', () => {
    const wrapper = mount(TimelineCanvas, {
      props: {
        bars: [{ id: 9, cve_id: 'CVE-X', agent_name: 'srv', package_name: 'pkg', severity: 'Low', leftPct: 0, widthPct: 10 }],
        range: { startMs, endMs },
        spanMs: endMs - startMs
      }
    })
    expect(wrapper.findAll('.gantt-seg')).toHaveLength(0)
    expect(wrapper.findAll('.gantt-bar')).toHaveLength(1)
  })

  it('emits open-threat with the bar when clicked', async () => {
    const wrapper = mountCanvas()
    await wrapper.findAll('.gantt-bar')[0].trigger('click')
    expect(wrapper.emitted('open-threat')).toBeTruthy()
    expect(wrapper.emitted('open-threat')[0][0].id).toBe(1)
  })
})

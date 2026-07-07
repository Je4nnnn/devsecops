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
    widthPct: 33.3
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
    widthPct: 100
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

  it('renders date axis ticks', () => {
    const wrapper = mountCanvas()
    // TICK_COUNT (7) + 1 boundary tick
    expect(wrapper.findAll('.axis-tick')).toHaveLength(8)
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

  it('emits open-threat with the bar when clicked', async () => {
    const wrapper = mountCanvas()
    await wrapper.findAll('.gantt-bar')[0].trigger('click')
    expect(wrapper.emitted('open-threat')).toBeTruthy()
    expect(wrapper.emitted('open-threat')[0][0].id).toBe(1)
  })
})

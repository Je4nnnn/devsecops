import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import TimelineKpiStrip from '@/presentation/views/timeline/components/TimelineKpiStrip.vue'

describe('TimelineKpiStrip.vue', () => {
  const counts = { total: 20, active: 8, resolved: 12, returned: 15 }

  it('renders all KPI cards with distinct-threat values', () => {
    const wrapper = mount(TimelineKpiStrip, { props: { hasBuilt: true, counts } })

    expect(wrapper.text()).toContain('Amenazas (distintas)')
    expect(wrapper.text()).toContain('20')
    expect(wrapper.text()).toContain('Activas')
    expect(wrapper.text()).toContain('8')
    expect(wrapper.text()).toContain('Resueltas')
    expect(wrapper.text()).toContain('12')
    expect(wrapper.text()).toContain('En vista')
    expect(wrapper.text()).toContain('15')
  })

  it('does not render until built', () => {
    const wrapper = mount(TimelineKpiStrip, { props: { hasBuilt: false, counts } })
    expect(wrapper.findAll('.kpi-card')).toHaveLength(0)
  })

  it('displays zero values correctly', () => {
    const wrapper = mount(TimelineKpiStrip, {
      props: { hasBuilt: true, counts: { total: 0, active: 0, resolved: 0, returned: 0 } }
    })
    const values = wrapper.findAll('.kpi-val')
    expect(values).toHaveLength(4)
    values.forEach(v => expect(v.text()).toBe('0'))
  })

  it('maintains correct order of KPI cards', () => {
    const wrapper = mount(TimelineKpiStrip, { props: { hasBuilt: true, counts } })
    const labels = wrapper.findAll('.kpi-label')
    expect(labels[0].text()).toBe('Amenazas (distintas)')
    expect(labels[1].text()).toBe('Activas')
    expect(labels[2].text()).toBe('Resueltas')
    expect(labels[3].text()).toBe('En vista')
  })
})

import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import DonutChart from '@/presentation/components/charts/DonutChart.vue'

const segments = [
  { label: 'Activas', value: 75, color: '#dc2626' },
  { label: 'Resueltas', value: 25, color: '#16a34a' }
]

const mountChart = (props = {}) =>
  mount(DonutChart, {
    props: { segments, centerValue: 100, centerLabel: 'Amenazas', ...props }
  })

describe('DonutChart.vue', () => {
  it('renders one arc per segment plus the background track', () => {
    const wrapper = mountChart()
    expect(wrapper.findAll('circle')).toHaveLength(3)
    expect(wrapper.find('.donut-track').exists()).toBe(true)
  })

  it('renders the center value and label', () => {
    const wrapper = mountChart()
    expect(wrapper.find('.donut-value').text()).toBe('100')
    expect(wrapper.find('.donut-caption').text()).toBe('Amenazas')
  })

  it('computes percentages per segment', () => {
    const wrapper = mountChart()
    expect(wrapper.vm.arcs.map(a => a.pct)).toEqual([75, 25])
  })

  it('lays arcs end to end so they do not overlap', () => {
    const wrapper = mountChart()
    const [first, second] = wrapper.vm.arcs
    expect(first.offset).toBe(0)
    expect(second.offset).toBeCloseTo(first.length, 5)
  })

  it('renders a legend row per segment with its value', () => {
    const wrapper = mountChart()
    const rows = wrapper.findAll('.donut-legend li')
    expect(rows).toHaveLength(2)
    expect(rows[0].text()).toContain('Activas')
    expect(rows[0].text()).toContain('75')
  })

  it('does not divide by zero when every segment is empty', () => {
    const wrapper = mountChart({
      segments: [
        { label: 'Activas', value: 0, color: '#dc2626' },
        { label: 'Resueltas', value: 0, color: '#16a34a' }
      ]
    })
    expect(wrapper.vm.arcs.every(a => a.pct === 0 && a.length === 0)).toBe(true)
  })

  it('treats non numeric values as zero', () => {
    const wrapper = mountChart({
      segments: [
        { label: 'Activas', value: null, color: '#dc2626' },
        { label: 'Resueltas', value: 10, color: '#16a34a' }
      ]
    })
    expect(wrapper.vm.arcs[0].value).toBe(0)
    expect(wrapper.vm.arcs[1].pct).toBe(100)
  })

  it('exposes an accessible label', () => {
    const wrapper = mountChart({ ariaLabel: 'Resueltas vs activas' })
    expect(wrapper.find('svg').attributes('aria-label')).toBe('Resueltas vs activas')
  })
})

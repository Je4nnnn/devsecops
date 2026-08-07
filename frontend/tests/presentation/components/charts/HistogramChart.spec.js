import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import HistogramChart from '@/presentation/components/charts/HistogramChart.vue'

const items = [
  { key: 1, label: 'srv-01', value: 10 },
  { key: 2, label: 'srv-02', value: 5 },
  { key: 3, label: 'srv-03', value: 0 }
]

const mountChart = (props = {}) => mount(HistogramChart, { props: { items, ...props } })

describe('HistogramChart.vue', () => {
  it('renders one row per item', () => {
    const wrapper = mountChart()
    expect(wrapper.findAll('.hist-row')).toHaveLength(3)
  })

  it('scales bar widths against the largest value', () => {
    const wrapper = mountChart()
    const widths = wrapper.vm.bars.map(b => Math.round(b.widthPct))
    expect(widths[0]).toBe(100)
    expect(widths[1]).toBe(50)
  })

  it('keeps a minimum visible width for tiny values', () => {
    const wrapper = mountChart({ items: [{ key: 1, label: 'a', value: 1000 }, { key: 2, label: 'b', value: 1 }] })
    expect(wrapper.vm.bars[1].widthPct).toBe(3)
  })

  it('renders the empty message when there are no items', () => {
    const wrapper = mountChart({ items: [], emptyText: 'Nada que mostrar' })
    expect(wrapper.find('.hist-empty').text()).toBe('Nada que mostrar')
    expect(wrapper.findAll('.hist-row')).toHaveLength(0)
  })

  it('builds axis ticks from the maximum value', () => {
    const wrapper = mountChart()
    expect(wrapper.vm.ticks).toEqual([0, 5, 10])
  })

  it('does not build ticks when every value is zero', () => {
    const wrapper = mountChart({ items: [{ key: 1, label: 'a', value: 0 }] })
    expect(wrapper.vm.ticks).toEqual([])
    expect(wrapper.vm.bars[0].widthPct).toBe(0)
  })

  it('applies the per item color and falls back to the default', () => {
    const wrapper = mountChart({
      items: [{ key: 1, label: 'a', value: 5, color: '#123456' }, { key: 2, label: 'b', value: 5 }],
      defaultColor: '#abcdef'
    })
    const fills = wrapper.findAll('.hist-fill')
    expect(fills[0].attributes('style')).toContain('rgb(18, 52, 86)')
    expect(fills[1].attributes('style')).toContain('rgb(171, 205, 239)')
  })

  it('uses the tooltip when provided', () => {
    const wrapper = mountChart({ items: [{ key: 1, label: 'srv', value: 1, tooltip: 'srv · grupo web' }] })
    expect(wrapper.find('.hist-label').attributes('title')).toBe('srv · grupo web')
  })
})

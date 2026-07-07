import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import TimelineFilters from '@/presentation/views/timeline/components/TimelineFilters.vue'

const defaultProps = {
  connections: [
    { id: 1, name: 'Conn 1' },
    { id: 2, name: 'Conn 2' }
  ],
  agentOptions: ['Agent 1', 'Agent 2', 'Agent 3'],
  vulnOptions: ['CVE-2023-001', 'CVE-2023-002'],
  severityOptions: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
  selectedConnection: '',
  selectedAgents: [],
  selectedVulns: [],
  selectedSeverities: [],
  startDate: '2026-03-01',
  endDate: '2026-03-31',
  loading: false
}

describe('TimelineFilters.vue', () => {
  it('renders connection selector and emits update', async () => {
    const wrapper = mount(TimelineFilters, { props: defaultProps })
    const select = wrapper.find('select')
    expect(select.exists()).toBe(true)

    await select.setValue('1')
    expect(wrapper.emitted('update:selectedConnection')).toBeTruthy()
    expect(wrapper.emitted('update:selectedConnection')[0]).toEqual([1])
  })

  it('renders the "Desde" date input bound to startDate', () => {
    const wrapper = mount(TimelineFilters, { props: defaultProps })
    const dateInput = wrapper.find('input[type="date"]')
    expect(dateInput.exists()).toBe(true)
    expect(dateInput.element.value).toBe('2026-03-01')
  })

  it('emits update:startDate when the date changes', async () => {
    const wrapper = mount(TimelineFilters, { props: defaultProps })
    const dateInput = wrapper.find('input[type="date"]')
    await dateInput.setValue('2026-04-10')
    expect(wrapper.emitted('update:startDate')).toBeTruthy()
    expect(wrapper.emitted('update:startDate')[0]).toEqual(['2026-04-10'])
  })

  it('renders the "Hasta" date input and emits update:endDate', async () => {
    const wrapper = mount(TimelineFilters, { props: defaultProps })
    const dateInputs = wrapper.findAll('input[type="date"]')
    expect(dateInputs).toHaveLength(2)
    expect(dateInputs[1].element.value).toBe('2026-03-31')

    await dateInputs[1].setValue('2026-03-20')
    expect(wrapper.emitted('update:endDate')).toBeTruthy()
    expect(wrapper.emitted('update:endDate')[0]).toEqual(['2026-03-20'])
  })

  it('opens the agent dropdown when clicked', async () => {
    const wrapper = mount(TimelineFilters, { props: { ...defaultProps, selectedConnection: '1' } })
    const ddButtons = wrapper.findAll('.dd-btn')
    await ddButtons[0].trigger('click')
    await wrapper.vm.$nextTick()
    expect(wrapper.find('.dd-panel').exists()).toBe(true)
  })

  it('selects all agents when "Todos" is clicked', async () => {
    const wrapper = mount(TimelineFilters, { props: { ...defaultProps, selectedConnection: '1' } })
    await wrapper.findAll('.dd-btn')[0].trigger('click')
    await wrapper.vm.$nextTick()
    const todos = wrapper.find('.dd-actions').findAll('span')[0]
    await todos.trigger('click')
    expect(wrapper.emitted('update:selectedAgents')[0][0]).toHaveLength(3)
  })

  it('filters vulnerabilities by search query', async () => {
    const wrapper = mount(TimelineFilters, { props: { ...defaultProps, selectedConnection: '1' } })
    await wrapper.findAll('.dd-btn')[1].trigger('click')
    const searchInput = wrapper.find('.dd-search')
    await searchInput.setValue('CVE-2023-002')
    expect(wrapper.vm.filteredVulns).toEqual(['CVE-2023-002'])
  })

  it('selects all severities when "Todas" is clicked', async () => {
    const wrapper = mount(TimelineFilters, { props: { ...defaultProps, selectedConnection: '1' } })
    // dd-btn index 2 = criticidad (0 agentes, 1 vulns, 2 criticidad)
    await wrapper.findAll('.dd-btn')[2].trigger('click')
    await wrapper.vm.$nextTick()
    const todas = wrapper.find('.dd-actions').findAll('span')[0]
    await todas.trigger('click')
    expect(wrapper.emitted('update:selectedSeverities')[0][0]).toEqual(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])
  })

  it('emits build event when button is clicked', async () => {
    const wrapper = mount(TimelineFilters, { props: { ...defaultProps, selectedConnection: '1' } })
    await wrapper.find('.btn-primary').trigger('click')
    expect(wrapper.emitted('build')).toBeTruthy()
  })

  it('disables build button when no connection selected', () => {
    const wrapper = mount(TimelineFilters, { props: defaultProps })
    expect(wrapper.find('.btn-primary').attributes('disabled')).toBeDefined()
  })

  it('disables build button when loading', () => {
    const wrapper = mount(TimelineFilters, {
      props: { ...defaultProps, selectedConnection: '1', loading: true }
    })
    const buildButton = wrapper.find('.btn-primary')
    expect(buildButton.attributes('disabled')).toBeDefined()
    expect(buildButton.text()).toContain('Analizando...')
  })
})

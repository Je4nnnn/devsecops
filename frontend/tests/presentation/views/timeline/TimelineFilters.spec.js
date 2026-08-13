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
  groupOptions: [{ name: 'default' }, { name: 'web' }, { name: 'db' }],
  osOptions: [
    { platform: 'ubuntu', version: '22.04' },
    { platform: 'ubuntu', version: '20.04' },
    { platform: 'windows', version: '2019' }
  ],
  selectedConnection: '',
  selectedAgents: [],
  selectedVulns: [],
  selectedSeverities: [],
  selectedGroups: [],
  selectedOsPlatforms: [],
  selectedStatus: '',
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

  it('renders the "Desde" month selector bound to startDate', () => {
    const wrapper = mount(TimelineFilters, { props: defaultProps })
    const monthSelect = wrapper.find('[data-testid="start-month"]')
    expect(monthSelect.exists()).toBe(true)
    expect(monthSelect.element.value).toBe('2026-03')
  })

  it('emits the first day when the start month changes', async () => {
    const wrapper = mount(TimelineFilters, { props: defaultProps })
    const monthSelect = wrapper.find('[data-testid="start-month"]')
    await monthSelect.setValue('2026-04')
    expect(wrapper.emitted('update:startDate')).toBeTruthy()
    expect(wrapper.emitted('update:startDate')[0]).toEqual(['2026-04-01'])
  })

  it('renders the end month and emits its last calendar day', async () => {
    const wrapper = mount(TimelineFilters, { props: defaultProps })
    const endMonth = wrapper.find('[data-testid="end-month"]')
    expect(endMonth.exists()).toBe(true)
    expect(endMonth.element.value).toBe('2026-03')

    await endMonth.setValue('2026-04')
    expect(wrapper.emitted('update:endDate')).toBeTruthy()
    expect(wrapper.emitted('update:endDate')[0]).toEqual(['2026-04-30'])
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
    await wrapper.findAll('.dd-btn')[3].trigger('click')
    const searchInput = wrapper.find('.dd-search')
    await searchInput.setValue('CVE-2023-002')
    expect(wrapper.vm.filteredVulns).toEqual(['CVE-2023-002'])
  })

  it('selects all severities when "Todas" is clicked', async () => {
    const wrapper = mount(TimelineFilters, { props: { ...defaultProps, selectedConnection: '1' } })
    // dd-btn: 0 agentes · 1 grupos · 2 S.O. · 3 CVEs · 4 criticidad
    await wrapper.findAll('.dd-btn')[4].trigger('click')
    await wrapper.vm.$nextTick()
    const todas = wrapper.find('.dd-actions').findAll('span')[0]
    await todas.trigger('click')
    expect(wrapper.emitted('update:selectedSeverities')[0][0]).toEqual(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])
  })

  it('selects all groups when "Todos" is clicked', async () => {
    const wrapper = mount(TimelineFilters, { props: { ...defaultProps, selectedConnection: '1' } })
    await wrapper.findAll('.dd-btn')[1].trigger('click')
    await wrapper.vm.$nextTick()
    await wrapper.find('.dd-actions').findAll('span')[0].trigger('click')
    expect(wrapper.emitted('update:selectedGroups')[0][0]).toEqual(['default', 'web', 'db'])
  })

  it('filters groups by search query', async () => {
    const wrapper = mount(TimelineFilters, { props: { ...defaultProps, selectedConnection: '1' } })
    await wrapper.findAll('.dd-btn')[1].trigger('click')
    await wrapper.find('.dd-search').setValue('we')
    expect(wrapper.vm.filteredGroups.map(g => g.name)).toEqual(['web'])
  })

  it('deduplicates operating system platforms', async () => {
    const wrapper = mount(TimelineFilters, { props: { ...defaultProps, selectedConnection: '1' } })
    expect(wrapper.vm.osPlatformOptions).toEqual(['ubuntu', 'windows'])
  })

  it('emits update:selectedStatus from the status selector', async () => {
    const wrapper = mount(TimelineFilters, { props: { ...defaultProps, selectedConnection: '1' } })
    const statusSelect = wrapper.findAll('select')[1]
    await statusSelect.setValue('resuelta')
    expect(wrapper.emitted('update:selectedStatus')[0]).toEqual(['resuelta'])
  })

  it('emits build event when button is clicked', async () => {
    const wrapper = mount(TimelineFilters, { props: { ...defaultProps, selectedConnection: '1' } })
    await wrapper.find('.btn-primary').trigger('click')
    expect(wrapper.emitted('build')).toBeTruthy()
  })

  it('allows building a consolidated timeline without selecting a connection', () => {
    const wrapper = mount(TimelineFilters, { props: defaultProps })
    expect(wrapper.find('.btn-primary').attributes('disabled')).toBeUndefined()
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

import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import TimelineDetailModal from '@/presentation/views/timeline/components/TimelineDetailModal.vue'

const eventData = {
  cve_id: 'CVE-2023-001',
  severity: 'High',
  agent_name: 'srv-01',
  package_name: 'openssl',
  package_version: '1.1.1',
  status: 'RESOLVED',
  score_base: 7.5,
  connection_name: 'Conn 1',
  start: '2026-03-06T10:00:00Z',
  first_seen: '2026-03-06T10:00:00Z',
  last_seen: '2026-03-08T13:00:00Z',
  history: [
    { id: 1, action: 'DETECTED', details: 'Identificada por primera vez', timestamp: '2026-03-06T10:00:00Z' },
    { id: 2, action: 'RESOLVED', details: 'Ya no es reportada', timestamp: '2026-03-08T13:00:00Z' }
  ]
}

describe('TimelineDetailModal.vue', () => {
  it('does not render when show is false', () => {
    const wrapper = mount(TimelineDetailModal, { props: { show: false, eventData: null } })
    expect(wrapper.find('.modal-overlay').exists()).toBe(false)
  })

  it('renders the threat header and metadata', () => {
    const wrapper = mount(TimelineDetailModal, { props: { show: true, eventData } })
    expect(wrapper.find('.modal-overlay').exists()).toBe(true)
    expect(wrapper.text()).toContain('CVE-2023-001')
    expect(wrapper.text()).toContain('srv-01')
    expect(wrapper.text()).toContain('openssl')
    expect(wrapper.text()).toContain('RESUELTA')
    expect(wrapper.text()).toContain('7.5')
  })

  it('lists the threat history events', () => {
    const wrapper = mount(TimelineDetailModal, { props: { show: true, eventData } })
    const items = wrapper.findAll('.hist-item')
    expect(items).toHaveLength(2)
    expect(wrapper.text()).toContain('Detectada')
    expect(wrapper.text()).toContain('Resuelta')
    expect(wrapper.text()).toContain('Identificada por primera vez')
  })

  it('shows a loading state', () => {
    const wrapper = mount(TimelineDetailModal, {
      props: { show: true, eventData: { ...eventData, history: [] }, loading: true }
    })
    expect(wrapper.find('.hist-loading').exists()).toBe(true)
  })

  it('shows an empty state when there is no history', () => {
    const wrapper = mount(TimelineDetailModal, {
      props: { show: true, eventData: { ...eventData, history: [] }, loading: false }
    })
    expect(wrapper.find('.hist-empty').exists()).toBe(true)
  })

  it('emits close when the close button is clicked', async () => {
    const wrapper = mount(TimelineDetailModal, { props: { show: true, eventData } })
    await wrapper.find('.modal-close').trigger('click')
    expect(wrapper.emitted('close')).toBeTruthy()
  })

  it('emits close when clicking the overlay', async () => {
    const wrapper = mount(TimelineDetailModal, { props: { show: true, eventData } })
    await wrapper.find('.modal-overlay').trigger('click')
    expect(wrapper.emitted('close')).toBeTruthy()
  })

  it('formats history timestamps (not raw ISO)', () => {
    const wrapper = mount(TimelineDetailModal, { props: { show: true, eventData } })
    expect(wrapper.text()).not.toContain('2026-03-06T10:00:00Z')
  })
})

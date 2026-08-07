import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import Dashboard from '@/presentation/views/Dashboard.vue'
import vulnService from '@/application/services/vulnService'
import wazuhService from '@/application/services/wazuhService'

vi.mock('@/application/services/vulnService', () => ({
    default: {
        getVulns: vi.fn(),
        getFilterOptions: vi.fn(),
        syncVulns: vi.fn(),
        getSyncStatus: vi.fn(),
        getEvolutionSummary: vi.fn(),
        getMonthlyTrend: vi.fn(),
        getTopAssets: vi.fn(),
        getTraceabilitySummary: vi.fn(),
        getStatusBreakdown: vi.fn(),
        getNewUnresolved: vi.fn(),
        getCriticalCoverage: vi.fn(),
        getCriticalHistogram: vi.fn(),
        getGroupRisk: vi.fn()
    }
}))

vi.mock('@/application/services/wazuhService', () => ({
    default: {
        getConnections: vi.fn()
    }
}))

const mockVulns = [
    {
        id: 1,
        connection_name: 'Conn A',
        severity: 'Critical',
        severity_rank: 4,
        score_base: 9.8,
        cve_id: 'CVE-2023-1234',
        status: 'ACTIVE',
        first_seen: new Date().toISOString(),
        last_seen: new Date().toISOString(),
        resolved_at: null,
        agent_name: 'Agent-1',
        groups: ['default', 'web'],
        os_platform: 'ubuntu',
        package_name: 'bash',
        package_version: '5.0'
    },
    {
        id: 2,
        connection_name: 'Conn B',
        severity: 'Low',
        severity_rank: 1,
        score_base: 2.1,
        cve_id: 'CVE-2022-0001',
        status: 'RESOLVED',
        first_seen: new Date(Date.now() - 1000 * 60 * 60 * 48).toISOString(),
        last_seen: new Date(Date.now() - 1000 * 60 * 60).toISOString(),
        resolved_at: new Date(Date.now() - 1000 * 60 * 60).toISOString(),
        agent_name: 'Agent-2',
        groups: ['db'],
        os_platform: 'windows',
        package_name: 'curl',
        package_version: '7.0'
    }
]

const paginated = (items = mockVulns, total = items.length) => ({
    data: { items, total, page: 1, page_size: 50, total_pages: 1 }
})

describe('Dashboard.vue', () => {
    beforeEach(() => {
        vi.clearAllMocks()

        wazuhService.getConnections.mockResolvedValue({ data: [{ id: 1, name: 'Conn A' }] })
        vulnService.getVulns.mockResolvedValue(paginated())
        vulnService.getSyncStatus.mockResolvedValue({ data: { status: 'idle' } })
        vulnService.getFilterOptions.mockResolvedValue({
            data: {
                agents: ['Agent-1', 'Agent-2'],
                cves: ['CVE-2023-1234'],
                packages: ['bash', 'curl'],
                severities: ['Critical', 'Low'],
                groups: [
                    { id: 1, name: 'default', assets: 2 },
                    { id: 2, name: 'web', assets: 1 },
                    { id: 3, name: 'db', assets: 1 }
                ],
                operating_systems: [
                    { id: 1, platform: 'ubuntu', version: '22.04' },
                    { id: 2, platform: 'ubuntu', version: '20.04' },
                    { id: 3, platform: 'windows', version: '2019' }
                ]
            }
        })
        vulnService.getEvolutionSummary.mockResolvedValue({
            data: {
                active_vulnerabilities: 2,
                resolved_vulnerabilities: 1,
                assets: 2,
                groups: 3,
                packages: 2,
                detection_events: 3,
                last_sync_at: new Date().toISOString()
            }
        })
        vulnService.getMonthlyTrend.mockResolvedValue({
            data: [
                { mes: '2026-06-01T00:00:00Z', total_vulnerabilidades: 4 },
                { mes: '2026-07-01T00:00:00Z', total_vulnerabilidades: 2 }
            ]
        })
        vulnService.getTopAssets.mockResolvedValue({ data: [{ hostname: 'Agent-1', total: 1 }] })
        vulnService.getTraceabilitySummary.mockResolvedValue({
            data: { nuevas: 1, persistentes: 1, remediadas: 1, total_activas: 2 }
        })
        vulnService.getStatusBreakdown.mockResolvedValue({
            data: { activas: 8, resueltas: 2, total: 10, pct_activas: 80, pct_resueltas: 20 }
        })
        vulnService.getNewUnresolved.mockResolvedValue({
            data: { anio: 2026, nuevas: 10, sin_corregir: 7, corregidas: 3, pct_sin_corregir: 70 }
        })
        vulnService.getCriticalCoverage.mockResolvedValue({
            data: {
                total_agentes: 4, agentes_criticos: 1, pct_agentes: 25,
                total_grupos: 3, grupos_criticos: 2, pct_grupos: 66.7
            }
        })
        vulnService.getCriticalHistogram.mockResolvedValue({
            data: [
                { asset_id: 1, hostname: 'Agent-1', grupos: 'default, web', criticas: 5, activas: 9 },
                { asset_id: 2, hostname: 'Agent-3', grupos: 'db', criticas: 2, activas: 4 }
            ]
        })
        vulnService.getGroupRisk.mockResolvedValue({
            data: [{ group_id: 1, name: 'web', agentes: 2, agentes_criticos: 1, criticas: 5, activas: 9 }]
        })
    })

    const mountDashboard = async () => {
        const wrapper = mount(Dashboard)
        await flushPromises()
        return wrapper
    }

    // --- listado ---

    it('carga la página de vulnerabilidades y la renderiza', async () => {
        const wrapper = await mountDashboard()

        expect(wrapper.vm.loading).toBe(false)
        expect(wrapper.vm.vulns).toHaveLength(2)
        expect(wrapper.vm.totalItems).toBe(2)

        const rows = wrapper.findAll('tbody tr')
        expect(rows).toHaveLength(2)
        expect(rows[0].text()).toContain('Conn A')
        expect(rows[1].text()).toContain('Conn B')
    })

    it('muestra un error cuando falla la carga', async () => {
        vulnService.getVulns.mockRejectedValueOnce(new Error('Network error'))
        const wrapper = await mountDashboard()

        expect(wrapper.vm.error).toContain('No se pudieron cargar')
        expect(wrapper.vm.vulns).toEqual([])
    })

    // --- filtros nuevos ---

    it('carga grupos y sistemas operativos como opciones de filtro', async () => {
        const wrapper = await mountDashboard()

        expect(wrapper.vm.groupOptions.map(g => g.name)).toEqual(['default', 'web', 'db'])
        expect(wrapper.vm.osPlatformOptions).toEqual(['ubuntu', 'windows'])
    })

    it('envía grupo, S.O., estado y puntaje al backend', async () => {
        const wrapper = await mountDashboard()

        wrapper.vm.selectedGroups = ['web']
        wrapper.vm.selectedOsPlatforms = ['ubuntu']
        wrapper.vm.selectedStatus = 'resuelta'
        wrapper.vm.scoreMin = 7
        wrapper.vm.scoreMax = 10

        const params = wrapper.vm.buildParams()
        expect(params.groups).toEqual(['web'])
        expect(params.osPlatforms).toEqual(['ubuntu'])
        expect(params.status).toBe('resuelta')
        expect(params.scoreMin).toBe(7)
        expect(params.scoreMax).toBe(10)
    })

    it('limpia todos los filtros, incluidos los nuevos', async () => {
        const wrapper = await mountDashboard()

        wrapper.vm.selectedGroups = ['web']
        wrapper.vm.selectedOsPlatforms = ['ubuntu']
        wrapper.vm.selectedStatus = 'resuelta'
        wrapper.vm.clearFilters()

        expect(wrapper.vm.selectedGroups).toEqual([])
        expect(wrapper.vm.selectedOsPlatforms).toEqual([])
        expect(wrapper.vm.selectedStatus).toBe('')
    })

    it('renderiza el selector de estado resuelta / no resuelta', async () => {
        const wrapper = await mountDashboard()
        wrapper.vm.showFilters = true
        await wrapper.vm.$nextTick()

        const options = wrapper.findAll('.filter-panel option').map(o => o.attributes('value'))
        expect(options).toContain('resuelta')
        expect(options).toContain('no_resuelta')
    })

    // --- gráficos ---

    it('pide los datos de los gráficos al montar', async () => {
        await mountDashboard()

        expect(vulnService.getStatusBreakdown).toHaveBeenCalled()
        expect(vulnService.getNewUnresolved).toHaveBeenCalled()
        expect(vulnService.getCriticalCoverage).toHaveBeenCalled()
        expect(vulnService.getCriticalHistogram).toHaveBeenCalled()
        expect(vulnService.getGroupRisk).toHaveBeenCalled()
    })

    it('arma la torta de activas vs. resueltas', async () => {
        const wrapper = await mountDashboard()

        expect(wrapper.vm.statusSegments).toEqual([
            { label: 'Activas', value: 8, color: '#dc2626' },
            { label: 'Resueltas', value: 2, color: '#16a34a' }
        ])
    })

    it('arma la torta de nuevas del año sin corregir', async () => {
        const wrapper = await mountDashboard()

        expect(wrapper.vm.newUnresolvedSegments.map(s => s.value)).toEqual([7, 3])
        expect(wrapper.vm.newUnresolved.pct_sin_corregir).toBe(70)
    })

    it('arma las tortas de cobertura crítica de agentes y grupos', async () => {
        const wrapper = await mountDashboard()

        expect(wrapper.vm.criticalAgentSegments.map(s => s.value)).toEqual([1, 3])
        expect(wrapper.vm.criticalGroupSegments.map(s => s.value)).toEqual([2, 1])
    })

    it('arma el histograma de agentes con vulnerabilidades críticas', async () => {
        const wrapper = await mountDashboard()

        expect(wrapper.vm.criticalHistogramBars).toEqual([
            { key: 1, label: 'Agent-1', value: 5, tooltip: 'Agent-1 · default, web' },
            { key: 2, label: 'Agent-3', value: 2, tooltip: 'Agent-3 · db' }
        ])
    })

    it('renderiza las barras del histograma en el DOM', async () => {
        const wrapper = await mountDashboard()
        // 2 agentes críticos + 1 grupo de riesgo
        expect(wrapper.findAll('.hist-row').length).toBe(3)
    })

    it('renderiza un donut por cada métrica de torta', async () => {
        const wrapper = await mountDashboard()
        // activas/resueltas + nuevas sin corregir + agentes + grupos
        expect(wrapper.findAll('.donut-svg')).toHaveLength(4)
    })

    it('recarga la torta del año al cambiar el año seleccionado', async () => {
        const wrapper = await mountDashboard()
        vulnService.getNewUnresolved.mockClear()

        wrapper.vm.selectedYear = 2025
        await wrapper.vm.fetchDashboardCharts()

        expect(vulnService.getNewUnresolved).toHaveBeenCalledWith(
            expect.objectContaining({ year: 2025 })
        )
    })

    // --- tendencia mensual ---

    it('usa la tendencia mensual en lugar de la semanal', async () => {
        const wrapper = await mountDashboard()

        expect(vulnService.getMonthlyTrend).toHaveBeenCalledWith(
            expect.objectContaining({ period: '12m' })
        )
        expect(wrapper.vm.monthlyTrend).toHaveLength(2)
        expect(wrapper.vm.getMonthlyBarWidth(4)).toBe(100)
        expect(wrapper.vm.getMonthlyBarWidth(2)).toBe(50)
    })

    it('formatea el bucket mensual', async () => {
        const wrapper = await mountDashboard()
        expect(wrapper.vm.formatMonth('2026-07-01T00:00:00Z')).toMatch(/26/)
        expect(wrapper.vm.formatMonth(null)).toBe('-')
    })

    // --- estado resuelto en verde ---

    it('marca en verde el tramo de las vulnerabilidades resueltas', async () => {
        const wrapper = await mountDashboard()

        expect(wrapper.vm.isResolved(mockVulns[0])).toBe(false)
        expect(wrapper.vm.isResolved(mockVulns[1])).toBe(true)

        const resolvedTracks = wrapper.findAll('.timeline-track.resolved')
        expect(resolvedTracks).toHaveLength(1)
        expect(wrapper.findAll('.timeline-point.end.resolved')).toHaveLength(1)
    })

    it('rotula el punto final como "Resuelta" solo si lo está', async () => {
        const wrapper = await mountDashboard()
        const rows = wrapper.findAll('tbody tr')

        expect(rows[0].text()).toContain('Última actividad')
        expect(rows[1].text()).toContain('Resuelta')
    })

    // --- orden y paginación ---

    it('alterna el orden al pulsar una columna', async () => {
        const wrapper = await mountDashboard()

        wrapper.vm.sortBy('cve_id')
        expect(wrapper.vm.sortKey).toBe('cve_id')
        expect(wrapper.vm.sortOrder).toBe('asc')

        wrapper.vm.sortBy('cve_id')
        expect(wrapper.vm.sortOrder).toBe('desc')

        wrapper.vm.sortBy('cve_id')
        expect(wrapper.vm.sortKey).toBe('last_seen')
    })

    it('calcula el total de páginas desde el total del servidor', async () => {
        vulnService.getVulns.mockResolvedValue(paginated(mockVulns, 120))
        const wrapper = await mountDashboard()

        expect(wrapper.vm.totalPages).toBe(3)
        wrapper.vm.nextPage()
        expect(wrapper.vm.currentPage).toBe(2)
        wrapper.vm.prevPage()
        expect(wrapper.vm.currentPage).toBe(1)
    })

    // --- utilidades de severidad ---

    it('mapea severidad a la clase del badge', async () => {
        const wrapper = await mountDashboard()

        expect(wrapper.vm.getSeverityClass('Critical')).toContain('badge-critical')
        expect(wrapper.vm.getSeverityClass('Medium')).toContain('badge-medium')
        expect(wrapper.vm.getSeverityClass(null)).toContain('badge-low')
        expect(wrapper.vm.getSeverityBadgeClass('High')).toBe('badge-high')
    })

    it('ordena las severidades de mayor a menor criticidad', async () => {
        const wrapper = await mountDashboard()
        expect(wrapper.vm.severityOptions).toEqual(['Critical', 'Low'])
    })
})

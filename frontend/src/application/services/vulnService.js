import apiClient from '../../infrastructure/http/apiClient';

const buildVulnParams = (params = {}) => {
  const q = {}

  // Paginación
  if (params.page != null) q.page = params.page
  if (params.pageSize != null) q.page_size = params.pageSize
  if (params.limit != null) q.limit = params.limit

  // Filtros server-side
  if (params.connectionId != null && params.connectionId !== '') q.connection_id = params.connectionId
  if (params.agents?.length) q.agent_name = params.agents.join(',')
  if (params.groups?.length) q.group = params.groups.join(',')
  if (params.groupIds?.length) q.group_id = params.groupIds.join(',')
  if (params.cves?.length) q.cve_id = params.cves.join(',')
  if (params.packages?.length) q.package_name = params.packages.join(',')
  if (params.severities?.length) q.severity = params.severities.join(',')
  if (params.osPlatforms?.length) q.os_platform = params.osPlatforms.join(',')
  if (params.osVersions?.length) q.os_version = params.osVersions.join(',')
  if (params.rankMin !== '' && params.rankMin != null) q.rank_min = params.rankMin
  if (params.status) q.status = params.status
  if (params.scoreMin !== '' && params.scoreMin != null) q.score_min = params.scoreMin
  if (params.scoreMax !== '' && params.scoreMax != null) q.score_max = params.scoreMax
  if (params.search) q.search = params.search

  // Orden
  if (params.sortBy) q.sort_by = params.sortBy
  if (params.sortOrder) q.sort_order = params.sortOrder

  return q
}

export default {
  buildVulnParams,

  // Lista paginada y filtrada en el servidor
  getVulns: async (params = {}) => {
    return apiClient.get('/vulns', { params: buildVulnParams(params) })
  },

  // Opciones de filtro precalculadas (agentes, grupos, S.O., CVEs, paquetes, severidades)
  getFilterOptions: async (connectionId) => {
    const params = {}
    if (connectionId != null && connectionId !== '') params.connection_id = connectionId
    return apiClient.get('/vulns/filter-options', { params })
  },

  // Inventario de paquetes vulnerables (tabla paquetes)
  getPackages: async (params = {}) => {
    return apiClient.get('/vulns/packages', { params })
  },

  // Historial detallado de una vulnerabilidad puntual
  getVulnHistory: async (id) => {
    return apiClient.get(`/vulns/${id}/history`)
  },

  // Sincronización en segundo plano -> devuelve { job_id }
  syncVulns: async () => {
    return apiClient.post('/vulns/sync-all')
  },

  syncConnection: async (connId) => {
    return apiClient.post(`/wazuh-connections/${connId}/sync`)
  },

  // Estado/progreso de un job de sincronización
  getSyncStatus: async (jobId) => {
    const params = {}
    if (jobId) params.job_id = jobId
    return apiClient.get('/sync/status', { params })
  },

  getEvolutionSummary: async (params = {}) => {
    return apiClient.get('/vulns/evolution/summary', { params })
  },

  // Tendencia por MES (reemplaza la tendencia semanal)
  getMonthlyTrend: async (params = {}) => {
    return apiClient.get('/vulns/evolution/monthly', { params })
  },

  getTopAssets: async (params = {}) => {
    return apiClient.get('/vulns/evolution/top-assets', { params })
  },

  // Línea de trazabilidad (nuevas / reemergidas / remediadas por bucket)
  getTraceabilityTimeline: async (params = {}) => {
    return apiClient.get('/vulns/evolution/timeline', { params })
  },

  // Detalle (drill-down) de un bucket de la línea de tiempo
  getTimelineDetails: async (params = {}) => {
    return apiClient.get('/vulns/evolution/timeline-details', { params })
  },

  // Línea de tiempo tipo Gantt: una barra por amenaza (vulnerabilidad única)
  getThreatSpans: async (params = {}) => {
    return apiClient.get('/vulns/evolution/threats', { params })
  },

  // Resumen de trazabilidad (cards)
  getTraceabilitySummary: async (params = {}) => {
    return apiClient.get('/vulns/evolution/traceability-summary', { params })
  },

  // --- Dashboard: gráficos ---
  getStatusBreakdown: async (params = {}) => {
    return apiClient.get('/vulns/dashboard/status-breakdown', { params })
  },

  getNewUnresolved: async (params = {}) => {
    return apiClient.get('/vulns/dashboard/new-unresolved', { params })
  },

  getCriticalCoverage: async (params = {}) => {
    return apiClient.get('/vulns/dashboard/critical-coverage', { params })
  },

  getCriticalHistogram: async (params = {}) => {
    return apiClient.get('/vulns/dashboard/critical-histogram', { params })
  },

  getGroupRisk: async (params = {}) => {
    return apiClient.get('/vulns/dashboard/group-risk', { params })
  },
}

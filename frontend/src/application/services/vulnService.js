import apiClient from '../../infrastructure/http/apiClient';

export default {
    getVulns: async (params = {}) => {
    const queryParams = {}

    if (params.limit !== undefined && params.limit !== null) {
      queryParams.limit = params.limit
    }

    if (params.connectionId !== undefined && params.connectionId !== null) {
      queryParams.connection_id = params.connectionId
    }

        return apiClient.get('/vulns', {
      params: queryParams,
        })
    },

  syncVulns: async () => {
    return apiClient.post('/vulns/sync-all')
  },

  getEvolutionSummary: async (params = {}) => {
    return apiClient.get('/vulns/evolution/summary', {
      params,
    })
  },

  getWeeklyTrend: async (params = {}) => {
    return apiClient.get('/vulns/evolution/weekly', {
      params,
    })
  },

  getTopAssets: async (params = {}) => {
    return apiClient.get('/vulns/evolution/top-assets', {
      params,
    })
  },
}

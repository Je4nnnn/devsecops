import { describe, it, expect, vi } from 'vitest'
import vulnService from '@/application/services/vulnService'
import apiClient from '@/infrastructure/http/apiClient'

// Mock the apiClient module
vi.mock('@/infrastructure/http/apiClient', () => {
    return {
        default: {
            get: vi.fn(),
            post: vi.fn(),
        }
    }
})

describe('vulnService.js', () => {

    it('getVulns calls apiClient.get with default params when empty', async () => {
        const mockResponse = { data: [] }
        apiClient.get.mockResolvedValueOnce(mockResponse)

        const result = await vulnService.getVulns()

        expect(apiClient.get).toHaveBeenCalledWith('/vulns', {
            params: {}
        })
        expect(result).toEqual(mockResponse)
    })

    it('getVulns calls apiClient.get with specific params', async () => {
        const mockResponse = { data: [] }
        apiClient.get.mockResolvedValueOnce(mockResponse)

        const result = await vulnService.getVulns({ limit: 50, connectionId: 2 })

        expect(apiClient.get).toHaveBeenCalledWith('/vulns', {
            params: {
                limit: 50,
                connection_id: 2,
            }
        })
        expect(result).toEqual(mockResponse)
    })

    it('syncVulns calls apiClient.post on /vulns/sync-all', async () => {
        const mockResponse = { data: { synced: 10 } }

        apiClient.post.mockResolvedValueOnce(mockResponse)

        const result = await vulnService.syncVulns()

        expect(apiClient.post).toHaveBeenCalledWith('/vulns/sync-all')
        expect(result).toEqual(mockResponse)
    })

    it('getEvolutionSummary calls summary endpoint', async () => {
        const mockResponse = { data: { active_vulnerabilities: 1 } }
        apiClient.get.mockResolvedValueOnce(mockResponse)

        const result = await vulnService.getEvolutionSummary({ connection_id: 2 })

        expect(apiClient.get).toHaveBeenCalledWith('/vulns/evolution/summary', {
            params: { connection_id: 2 }
        })
        expect(result).toEqual(mockResponse)
    })

    it('getMonthlyTrend calls the monthly evolution endpoint', async () => {
        const mockResponse = { data: [] }
        apiClient.get.mockResolvedValueOnce(mockResponse)

        const result = await vulnService.getMonthlyTrend({ period: '12m' })

        expect(apiClient.get).toHaveBeenCalledWith('/vulns/evolution/monthly', {
            params: { period: '12m' }
        })
        expect(result).toEqual(mockResponse)
    })

    it('maps the new filters (grupos, S.O., estado, criticidad) to query params', () => {
        const params = vulnService.buildVulnParams({
            connectionId: 3,
            groups: ['default', 'web'],
            osPlatforms: ['ubuntu'],
            osVersions: ['22.04'],
            status: 'resuelta',
            rankMin: 4,
            scoreMin: 7,
            scoreMax: 10
        })

        expect(params).toEqual({
            connection_id: 3,
            group: 'default,web',
            os_platform: 'ubuntu',
            os_version: '22.04',
            status: 'resuelta',
            rank_min: 4,
            score_min: 7,
            score_max: 10
        })
    })

    it('omits filters that are empty', () => {
        expect(vulnService.buildVulnParams({ groups: [], status: '', scoreMin: '' })).toEqual({})
    })

    it('getPackages calls the package inventory endpoint', async () => {
        const mockResponse = { data: { items: [], total: 0 } }
        apiClient.get.mockResolvedValueOnce(mockResponse)

        await vulnService.getPackages({ search: 'openssl' })

        expect(apiClient.get).toHaveBeenCalledWith('/vulns/packages', {
            params: { search: 'openssl' }
        })
    })

    it.each([
        ['getStatusBreakdown', '/vulns/dashboard/status-breakdown'],
        ['getNewUnresolved', '/vulns/dashboard/new-unresolved'],
        ['getCriticalCoverage', '/vulns/dashboard/critical-coverage'],
        ['getCriticalHistogram', '/vulns/dashboard/critical-histogram'],
        ['getGroupRisk', '/vulns/dashboard/group-risk']
    ])('%s calls %s', async (method, url) => {
        apiClient.get.mockResolvedValueOnce({ data: {} })
        await vulnService[method]({ connection_id: 1 })
        expect(apiClient.get).toHaveBeenCalledWith(url, { params: { connection_id: 1 } })
    })

    it('getTopAssets calls top assets endpoint', async () => {
        const mockResponse = { data: [] }
        apiClient.get.mockResolvedValueOnce(mockResponse)

        const result = await vulnService.getTopAssets({ days: 7, limit: 5 })

        expect(apiClient.get).toHaveBeenCalledWith('/vulns/evolution/top-assets', {
            params: { days: 7, limit: 5 }
        })
        expect(result).toEqual(mockResponse)
    })
})

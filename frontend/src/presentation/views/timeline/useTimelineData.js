import { computed, ref } from 'vue'
import vulnService from '../../../application/services/vulnService'
import { HOUR_MS, fmtDDMM, fmtHour, fmtYear } from './timelineFormatters'

// Mapea el periodo de la UI al periodo/bucket del backend
const PERIOD_MAP = {
  '24h': '24h',
  '7d': '7d',
  '30d': '30d',
  'day': '24h',
  'all': 'all',
}

const initialZoomForPeriod = period => {
  if (period === '7d') return 2
  if (period === '24h' || period === 'day') return 4
  return 0
}

const bucketToSlotHours = bucket => {
  if (!bucket) return 24
  if (bucket.includes('hour')) return 1
  return 24
}

export default function useTimelineData({
  selectedConnection,
  selectedAgents,
  selectedVulns,
  period,
}) {
  const loading = ref(false)
  const hasBuilt = ref(false)
  const errorMessage = ref('')
  const warningMessage = ref('')
  const points = ref([])
  const bucketLabel = ref('1 day')
  const latestSnap = ref({ total: 0, pending: 0, resolved: 0 })

  // Determina el "tipo" visual del slot a partir de los conteos del bucket
  const slotType = (p) => {
    const detections = (p.nuevas || 0) + (p.reemergidas || 0)
    const resolutions = p.remediadas || 0
    if (detections > 0 && resolutions > 0) return 'mixed'
    if (detections > 0) return 'detection'
    if (resolutions > 0) return 'resolution'
    return 'none'
  }

  const allSlots = computed(() => {
    const slotHours = bucketToSlotHours(bucketLabel.value)
    return points.value
      .map(p => {
        const startMs = new Date(p.bucket).getTime()
        const detections = (p.nuevas || 0) + (p.reemergidas || 0)
        const resolved = p.remediadas || 0
        const type = slotType(p)
        return {
          startMs,
          bucket: p.bucket,
          painted: type !== 'none',
          type,
          total: detections + resolved,
          pending: detections,
          resolved,
          nuevas: p.nuevas || 0,
          reemergidas: p.reemergidas || 0,
          remediadas: p.remediadas || 0,
          slotHours,
          tickLabel: slotHours >= 24 ? fmtDDMM(startMs) : fmtHour(startMs),
          cardLabel: slotHours >= 24
            ? `${fmtDDMM(startMs)} ${fmtYear(startMs)}`
            : `${fmtDDMM(startMs)} ${fmtHour(startMs)}`,
          // details se cargan bajo demanda al abrir el slot
          details: [],
        }
      })
      .filter(slot => slot.painted)
  })

  const paintedCount = computed(() => allSlots.value.length)

  const build = async () => {
    if (!selectedConnection.value) return { initialZoom: 0 }

    loading.value = true
    hasBuilt.value = false
    errorMessage.value = ''
    warningMessage.value = ''

    try {
      const params = {
        period: PERIOD_MAP[period.value] || '30d',
        connection_id: selectedConnection.value,
      }
      if (selectedAgents.value?.length) params.agent_name = selectedAgents.value.join(',')
      if (selectedVulns.value?.length) params.cve_id = selectedVulns.value.join(',')

      const res = await vulnService.getTraceabilityTimeline({ params })
      const data = res.data || {}
      points.value = Array.isArray(data.points) ? data.points : []
      bucketLabel.value = data.bucket || '1 day'

      const totals = points.value.reduce(
        (acc, p) => {
          acc.pending += (p.nuevas || 0) + (p.reemergidas || 0)
          acc.resolved += p.remediadas || 0
          return acc
        },
        { pending: 0, resolved: 0 }
      )
      latestSnap.value = {
        total: totals.pending + totals.resolved,
        pending: totals.pending,
        resolved: totals.resolved,
      }

      if (!points.value.length) {
        warningMessage.value = 'No hay eventos de trazabilidad en el periodo seleccionado.'
      }

      hasBuilt.value = true
      return { initialZoom: initialZoomForPeriod(period.value) }
    } catch (error) {
      console.error(error)
      errorMessage.value = 'No se pudo generar la linea de tiempo. Intenta nuevamente.'
      throw error
    } finally {
      loading.value = false
    }
  }

  // Carga los registros de un bucket puntual (drill-down del modal)
  const fetchSlotDetails = async (slot) => {
    const slotMs = (slot.slotHours || 24) * HOUR_MS
    const start = new Date(slot.startMs).toISOString()
    const end = new Date(slot.startMs + slotMs - 1).toISOString()

    const params = {
      bucket_start: start,
      bucket_end: end,
      connection_id: selectedConnection.value,
    }
    if (selectedAgents.value?.length) params.agent_name = selectedAgents.value.join(',')
    if (selectedVulns.value?.length) params.cve_id = selectedVulns.value.join(',')

    const res = await vulnService.getTimelineDetails({ params })
    return Array.isArray(res.data) ? res.data : []
  }

  return {
    loading,
    hasBuilt,
    allSlots,
    paintedCount,
    latestSnap,
    errorMessage,
    warningMessage,
    build,
    fetchSlotDetails,
  }
}

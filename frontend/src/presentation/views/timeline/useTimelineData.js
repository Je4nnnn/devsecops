import { computed, ref } from 'vue'
import vulnService from '../../../application/services/vulnService'

// Tope de barras a renderizar (las amenazas pueden ser miles).
const MAX_THREATS = 300

export default function useTimelineData({
  selectedConnection,
  selectedAgents,
  selectedVulns,
  startDate,
}) {
  const loading = ref(false)
  const hasBuilt = ref(false)
  const errorMessage = ref('')
  const warningMessage = ref('')

  const items = ref([])
  const range = ref({ startMs: 0, endMs: 0 })
  const counts = ref({ total: 0, active: 0, resolved: 0, returned: 0 })

  const spanMs = computed(() => Math.max(1, range.value.endMs - range.value.startMs))

  // Geometría de cada barra recortada (clamp) al rango visible [start, end].
  const bars = computed(() => {
    const { startMs, endMs } = range.value
    const span = spanMs.value
    return items.value.map(it => {
      const detected = new Date(it.start).getTime()
      const ongoing = it.status === 'ACTIVE' || !it.end
      const finished = ongoing ? endMs : new Date(it.end).getTime()

      const barStart = Math.max(detected, startMs)
      const barEnd = Math.min(finished, endMs)
      const leftPct = ((barStart - startMs) / span) * 100
      const widthPct = Math.max(0.8, ((barEnd - barStart) / span) * 100)

      return {
        ...it,
        ongoing,
        detectedMs: detected,
        finishedMs: finished,
        // Recorte fuera de rango por la izquierda/derecha (para indicar "viene de antes")
        clippedLeft: detected < startMs,
        clippedRight: ongoing || finished > endMs,
        leftPct,
        widthPct: Math.min(widthPct, 100 - leftPct),
      }
    })
  })

  const visibleCount = computed(() => bars.value.length)

  const toIsoStart = dateStr => {
    // dateStr = "yyyy-mm-dd" -> inicio del día local en ISO
    if (!dateStr) return undefined
    return new Date(`${dateStr}T00:00:00`).toISOString()
  }

  const build = async () => {
    if (!selectedConnection.value) return

    loading.value = true
    hasBuilt.value = false
    errorMessage.value = ''
    warningMessage.value = ''

    try {
      const params = {
        connection_id: selectedConnection.value,
        limit: MAX_THREATS,
      }
      const isoStart = toIsoStart(startDate.value)
      if (isoStart) params.start = isoStart
      if (selectedAgents.value?.length) params.agent_name = selectedAgents.value.join(',')
      if (selectedVulns.value?.length) params.cve_id = selectedVulns.value.join(',')

      const res = await vulnService.getThreatSpans({ params })
      const data = res.data || {}

      items.value = Array.isArray(data.items) ? data.items : []
      range.value = {
        startMs: new Date(data.range?.start).getTime(),
        endMs: new Date(data.range?.end).getTime(),
      }
      counts.value = {
        total: data.total || 0,
        active: data.active || 0,
        resolved: data.resolved || 0,
        returned: data.returned || items.value.length,
      }

      if (!items.value.length) {
        warningMessage.value = 'No hay amenazas en el rango seleccionado.'
      } else if (counts.value.total > counts.value.returned) {
        warningMessage.value =
          `Mostrando ${counts.value.returned} de ${counts.value.total} amenazas ` +
          `(las más severas/antiguas). Acota con filtros para ver el resto.`
      }

      hasBuilt.value = true
    } catch (error) {
      console.error(error)
      errorMessage.value = 'No se pudo generar la linea de tiempo. Intenta nuevamente.'
      throw error
    } finally {
      loading.value = false
    }
  }

  return {
    loading,
    hasBuilt,
    bars,
    range,
    spanMs,
    counts,
    visibleCount,
    errorMessage,
    warningMessage,
    build,
  }
}

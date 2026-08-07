import { computed, ref } from 'vue'
import vulnService from '../../../application/services/vulnService'

// Tope de barras a renderizar (las amenazas pueden ser miles).
const MAX_THREATS = 300

/**
 * Tramos que puede tener la vida de una amenaza dentro del rango visible:
 *
 *   unknown  gris  → todavía no había sincronizaciones: no sabemos nada.
 *   absent   blanco→ hubo sincronización y la amenaza NO existía.
 *   active   color → detectada y sin remediar (color por severidad).
 *   resolved verde → ya remediada.
 */
export const SEGMENT_KINDS = ['unknown', 'absent', 'active', 'resolved']

export default function useTimelineData({
  selectedConnection,
  selectedAgents,
  selectedVulns,
  selectedSeverities,
  selectedGroups,
  selectedOsPlatforms,
  selectedStatus,
  startDate,
  endDate,
}) {
  const loading = ref(false)
  const hasBuilt = ref(false)
  const errorMessage = ref('')
  const warningMessage = ref('')

  const items = ref([])
  const range = ref({ startMs: 0, endMs: 0 })
  const coverageSinceMs = ref(null)
  const counts = ref({ total: 0, active: 0, resolved: 0, returned: 0 })

  const spanMs = computed(() => Math.max(1, range.value.endMs - range.value.startMs))

  const bars = computed(() => {
    const { startMs, endMs } = range.value
    const span = spanMs.value
    const since = coverageSinceMs.value

    // Posición en % de un instante, recortada al rango visible.
    const pct = ms => ((Math.min(Math.max(ms, startMs), endMs) - startMs) / span) * 100

    return items.value.map(it => {
      const detected = new Date(it.start).getTime()
      const resolvedRaw = it.resolved_at || it.end
      const resolvedMs = resolvedRaw ? new Date(resolvedRaw).getTime() : null
      const ongoing = it.status === 'ACTIVE' || !resolvedMs
      const finished = ongoing ? endMs : resolvedMs

      // Geometría del tramo activo (compatibilidad con la vista anterior).
      const barStart = Math.max(detected, startMs)
      const barEnd = Math.min(finished, endMs)
      const leftPct = ((barStart - startMs) / span) * 100
      const widthPct = Math.max(0.8, ((barEnd - barStart) / span) * 100)

      return {
        ...it,
        ongoing,
        detectedMs: detected,
        resolvedMs,
        finishedMs: finished,
        clippedLeft: detected < startMs,
        clippedRight: ongoing || finished > endMs,
        leftPct,
        widthPct: Math.min(widthPct, 100 - leftPct),
        segments: buildSegments({ startMs, endMs, since, detected, resolvedMs, ongoing, pct }),
      }
    })
  })

  const visibleCount = computed(() => bars.value.length)

  const toIsoStart = dateStr => {
    if (!dateStr) return undefined
    return new Date(`${dateStr}T00:00:00`).toISOString()
  }

  const toIsoEnd = dateStr => {
    if (!dateStr) return undefined
    return new Date(`${dateStr}T23:59:59.999`).toISOString()
  }

  const buildParams = () => {
    const params = {
      connection_id: selectedConnection.value,
      limit: MAX_THREATS,
    }
    const isoStart = toIsoStart(startDate.value)
    if (isoStart) params.start = isoStart
    const isoEnd = toIsoEnd(endDate?.value)
    if (isoEnd) params.end = isoEnd
    if (selectedAgents.value?.length) params.agent_name = selectedAgents.value.join(',')
    if (selectedVulns.value?.length) params.cve_id = selectedVulns.value.join(',')
    if (selectedSeverities?.value?.length) params.severity = selectedSeverities.value.join(',')
    if (selectedGroups?.value?.length) params.group = selectedGroups.value.join(',')
    if (selectedOsPlatforms?.value?.length) {
      params.os_platform = selectedOsPlatforms.value.join(',')
    }
    if (selectedStatus?.value) params.status = selectedStatus.value
    return params
  }

  const build = async () => {
    if (!selectedConnection.value) return

    loading.value = true
    hasBuilt.value = false
    errorMessage.value = ''
    warningMessage.value = ''

    try {
      const res = await vulnService.getThreatSpans(buildParams())
      const data = res.data || {}

      items.value = Array.isArray(data.items) ? data.items : []
      range.value = {
        startMs: new Date(data.range?.start).getTime(),
        endMs: new Date(data.range?.end).getTime(),
      }
      coverageSinceMs.value = data.coverage?.since
        ? new Date(data.coverage.since).getTime()
        : null
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
    coverageSinceMs,
    visibleCount,
    errorMessage,
    warningMessage,
    build,
  }
}

/**
 * Divide el rango visible en los tramos de la vida de una amenaza.
 *
 * El espacio en blanco ("no existía") solo se pinta cuando consta que hubo
 * sincronización antes de la detección; si no hay datos previos el tramo se
 * marca como desconocido en vez de afirmar que la amenaza no existía.
 */
export function buildSegments({ startMs, endMs, since, detected, resolvedMs, ongoing, pct }) {
  const segments = []
  const push = (kind, fromMs, toMs) => {
    const left = pct(fromMs)
    const width = pct(toMs) - left
    if (width > 0.01) segments.push({ kind, leftPct: left, widthPct: width })
  }

  // Sin cobertura conocida no se afirma nada antes de la detección.
  const knownFrom = since != null ? Math.min(Math.max(since, startMs), endMs) : null

  if (knownFrom != null && knownFrom > startMs) {
    push('unknown', startMs, Math.min(knownFrom, detected))
  }
  if (knownFrom != null && detected > knownFrom) {
    push('absent', knownFrom, detected)
  }

  const activeEnd = ongoing ? endMs : Math.min(resolvedMs ?? endMs, endMs)
  push('active', Math.max(detected, startMs), activeEnd)

  if (!ongoing && resolvedMs != null && resolvedMs < endMs) {
    push('resolved', resolvedMs, endMs)
  }

  return segments
}

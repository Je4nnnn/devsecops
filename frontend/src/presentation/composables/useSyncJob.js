import { ref, computed } from 'vue'
import vulnService from '../../application/services/vulnService'
import { useToast } from './useToast'

// Estado global de sincronización (compartido entre vistas).
const job = ref(null)
const polling = ref(false)
let pollTimer = null
let onDoneCallbacks = []

const { success, error: toastError, info } = useToast()

const isSyncing = computed(() =>
  !!job.value && ['pending', 'running'].includes(job.value.status)
)

const progressPct = computed(() => {
  if (!job.value) return 0
  const { total, processed, connections_total, connections_done } = job.value
  if (total > 0) {
    // Progreso combinado: conexiones completas + avance de la actual
    const perConn = connections_total > 0 ? 100 / connections_total : 100
    const base = (connections_done || 0) * perConn
    const within = (processed / total) * perConn
    return Math.min(99, Math.round(base + within))
  }
  if (connections_total > 0) {
    return Math.round((connections_done / connections_total) * 100)
  }
  return 5
})

const phaseLabel = computed(() => job.value?.phase || 'Sincronizando...')

const stopPolling = () => {
  if (pollTimer) {
    clearInterval(pollTimer)
    pollTimer = null
  }
  polling.value = false
}

const handleCompletion = (finished) => {
  const failed = (finished.results || []).filter(r => r.ok === false)
  if (finished.status === 'error' || failed.length) {
    toastError(
      finished.error || `Falló la sincronización de ${failed.length} conexión(es).`,
      { title: 'Sincronización con errores', timeout: 7000 }
    )
  } else {
    success(
      `${finished.synced ?? 0} vulnerabilidades sincronizadas.`,
      { title: 'Sincronización completada', timeout: 6000 }
    )
  }
  onDoneCallbacks.forEach(cb => {
    try { cb(finished) } catch (e) { console.error(e) }
  })
}

const poll = async (jobId) => {
  try {
    const res = await vulnService.getSyncStatus(jobId)
    job.value = res.data

    if (['completed', 'error', 'idle'].includes(res.data.status)) {
      stopPolling()
      if (res.data.status !== 'idle') handleCompletion(res.data)
    }
  } catch (e) {
    console.error('Error consultando estado de sync:', e)
    stopPolling()
  }
}

const startPollingExisting = (jobId) => {
  if (polling.value) return
  polling.value = true
  poll(jobId)
  pollTimer = setInterval(() => poll(jobId), 1500)
}

export function useSyncJob() {
  const startSync = async () => {
    if (isSyncing.value) {
      info('Ya hay una sincronización en curso.', { title: 'En progreso' })
      return
    }
    try {
      const res = await vulnService.syncVulns()
      job.value = { ...res.data, status: 'running', phase: 'Iniciando' }
      startPollingExisting(res.data.job_id)
    } catch (e) {
      const msg = e?.response?.data?.detail || 'No se pudo iniciar la sincronización.'
      toastError(msg, { title: 'Error' })
    }
  }

  // Reanuda la barra si ya había un job activo (p.ej. al recargar la página)
  const resumeIfActive = async () => {
    try {
      const res = await vulnService.getSyncStatus()
      if (res.data && ['pending', 'running'].includes(res.data.status)) {
        job.value = res.data
        startPollingExisting(res.data.job_id)
      }
    } catch (e) {
      // silencioso
    }
  }

  const onDone = (cb) => {
    onDoneCallbacks.push(cb)
    return () => {
      onDoneCallbacks = onDoneCallbacks.filter(c => c !== cb)
    }
  }

  return {
    job,
    isSyncing,
    progressPct,
    phaseLabel,
    startSync,
    resumeIfActive,
    onDone,
  }
}

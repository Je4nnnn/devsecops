<template>
  <div class="fade-in timeline-view">
    <div class="header-actions">
      <div>
        <h1 class="title">Linea del tiempo</h1>
        <p class="subtitle">Línea de vida de cada amenaza: desde su detección hasta su resolución.</p>
      </div>
    </div>

    <div v-if="statusError" class="status-banner status-error">{{ statusError }}</div>
    <div v-if="statusWarning" class="status-banner status-warning">{{ statusWarning }}</div>

    <div v-if="loading" class="tl-loading-bar"><div class="tl-loading-fill"></div></div>

    <TimelineFilters
      :connections="connections"
      :agent-options="agentOpts"
      :vuln-options="vulnOpts"
      :severity-options="severityOpts"
      :group-options="groupOpts"
      :os-options="osOpts"
      :selected-connection="selectedConnection"
      :selected-agents="selectedAgents"
      :selected-vulns="selectedVulns"
      :selected-severities="selectedSeverities"
      :selected-groups="selectedGroups"
      :selected-os-platforms="selectedOsPlatforms"
      :selected-status="selectedStatus"
      :start-date="startDate"
      :end-date="endDate"
      :loading="loading"
      @update:selected-connection="selectedConnection = $event"
      @update:selected-agents="selectedAgents = $event"
      @update:selected-vulns="selectedVulns = $event"
      @update:selected-severities="selectedSeverities = $event"
      @update:selected-groups="selectedGroups = $event"
      @update:selected-os-platforms="selectedOsPlatforms = $event"
      @update:selected-status="selectedStatus = $event"
      @update:start-date="startDate = $event"
      @update:end-date="endDate = $event"
      @connection-change="onConnectionChange"
      @build="buildTimeline"
    />

    <TimelineKpiStrip
      :has-built="hasBuilt"
      :counts="counts"
    />

    <TimelineCanvas
      v-if="hasBuilt && bars.length > 0"
      :bars="bars"
      :range="range"
      :span-ms="spanMs"
      @open-threat="openThreat"
    />

    <div v-else class="card empty-card">
      <div v-if="loading" class="empty-center"><p>Escaneando historial...</p></div>
      <div v-else class="empty-center">
        <h3>Sin datos para mostrar</h3>
        <p>Selecciona una conexión y una fecha de inicio, luego presiona "Generar Vista".</p>
      </div>
    </div>

    <TimelineDetailModal
      :show="modalOpen"
      :event-data="selectedEvent"
      :loading="modalLoading"
      @close="modalOpen = false"
    />
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import wazuhService from '../../application/services/wazuhService'
import vulnService from '../../application/services/vulnService'
import useTimelineData from './timeline/useTimelineData'
import TimelineCanvas from './timeline/components/TimelineCanvas.vue'
import TimelineDetailModal from './timeline/components/TimelineDetailModal.vue'
import TimelineFilters from './timeline/components/TimelineFilters.vue'
import TimelineKpiStrip from './timeline/components/TimelineKpiStrip.vue'

const connections = ref([])
const agentOpts = ref([])
const vulnOpts = ref([])
const severityOpts = ref([])
const groupOpts = ref([])
const osOpts = ref([])
const selectedConnection = ref('')
const selectedAgents = ref([])
const selectedVulns = ref([])
const selectedSeverities = ref([])
const selectedGroups = ref([])
const selectedOsPlatforms = ref([])
const selectedStatus = ref('')
const errorBanner = ref('')

// Fecha de inicio por defecto: hace un mes (el periodo de trabajo es mensual).
const defaultStart = () => {
  const d = new Date()
  d.setMonth(d.getMonth() - 1)
  return d.toISOString().split('T')[0]
}
const startDate = ref(defaultStart())
const endDate = ref(new Date().toISOString().split('T')[0]) // hoy; editable, sin futuro

const modalOpen = ref(false)
const modalLoading = ref(false)
const selectedEvent = ref(null)

const {
  loading,
  hasBuilt,
  bars,
  range,
  spanMs,
  counts,
  errorMessage,
  warningMessage,
  build,
} = useTimelineData({
  selectedConnection,
  selectedAgents,
  selectedVulns,
  selectedSeverities,
  selectedGroups,
  selectedOsPlatforms,
  selectedStatus,
  startDate,
  endDate,
})

const onConnectionChange = async () => {
  selectedAgents.value = []
  selectedVulns.value = []
  selectedSeverities.value = []
  selectedGroups.value = []
  selectedOsPlatforms.value = []
  selectedStatus.value = ''
  agentOpts.value = []
  vulnOpts.value = []
  severityOpts.value = []
  groupOpts.value = []
  osOpts.value = []
  errorBanner.value = ''

  if (!selectedConnection.value) return

  try {
    const res = await vulnService.getFilterOptions(selectedConnection.value)
    agentOpts.value = res.data?.agents || []
    vulnOpts.value = res.data?.cves || []
    severityOpts.value = res.data?.severities || []
    groupOpts.value = res.data?.groups || []
    osOpts.value = res.data?.operating_systems || []
  } catch (error) {
    console.error(error)
    errorBanner.value = 'No se pudieron cargar los filtros para la conexion seleccionada.'
  }
}

const buildTimeline = async () => {
  errorBanner.value = ''
  try {
    await build()
  } catch (error) {
    console.error(error)
  }
}

const openThreat = async threat => {
  // Abre el modal y carga el historial puntual de la amenaza desde la BD.
  selectedEvent.value = { ...threat, history: [] }
  modalOpen.value = true
  modalLoading.value = true
  try {
    const res = await vulnService.getVulnHistory(threat.id)
    selectedEvent.value = { ...threat, ...(res.data || {}) }
  } catch (error) {
    console.error(error)
    selectedEvent.value = { ...threat, history: [] }
  } finally {
    modalLoading.value = false
  }
}

onMounted(async () => {
  try {
    const response = await wazuhService.getConnections()
    connections.value = Array.isArray(response.data) ? response.data : []
  } catch (error) {
    console.error(error)
    errorBanner.value = 'No se pudieron cargar las conexiones Wazuh.'
  }
})

const statusError = computed(() => errorBanner.value || errorMessage.value)
const statusWarning = computed(() => warningMessage.value)
</script>

<style scoped>
.timeline-view {
  display: flex;
  flex-direction: column;
  gap: 0.85rem;
}

.status-banner {
  border-radius: var(--radius-sm);
  padding: 0.7rem 0.9rem;
  border: 1px solid var(--border);
  font-size: 0.85rem;
  font-weight: 600;
}

.status-error {
  color: var(--danger);
  background: var(--danger-bg);
  border-color: rgba(220, 38, 38, 0.3);
}

.status-warning {
  color: var(--warning);
  background: var(--warning-bg);
  border-color: rgba(217, 119, 6, 0.25);
}

.empty-card {
  min-height: 240px;
  display: flex;
  justify-content: center;
  align-items: center;
  text-align: center;
}

.empty-center p {
  color: var(--text-muted);
}

/* Barra de carga indeterminada de la línea de tiempo */
.tl-loading-bar {
  height: 4px;
  width: 100%;
  background: var(--bg-hover);
  border-radius: 999px;
  overflow: hidden;
}
.tl-loading-fill {
  height: 100%;
  width: 35%;
  background: var(--primary);
  border-radius: 999px;
  animation: tl-indeterminate 1.1s ease-in-out infinite;
}
@keyframes tl-indeterminate {
  0% { margin-left: -35%; }
  100% { margin-left: 100%; }
}
</style>

<template>
  <div class="card filter-panel">
    <div class="filter-row">
      <div class="f-group">
        <label>Conexion Wazuh</label>
        <select v-model="connectionModel" @change="emit('connection-change')" class="filter-input">
          <option value="" disabled>Selecciona servidor...</option>
          <option v-for="conn in connections" :key="conn.id" :value="conn.id">{{ conn.name }}</option>
        </select>
      </div>

      <div class="f-group popover-wrap" v-click-outside="() => (dropdowns.agents = false)">
        <label>Equipos / Agentes</label>
        <button class="filter-input dd-btn" @click="dropdowns.agents = !dropdowns.agents">
          <span>{{ selectedAgentsModel.length ? selectedAgentsModel.length + ' sel.' : 'Todos' }}</span>
          <span>▼</span>
        </button>
        <div v-if="dropdowns.agents" class="dd-panel fade-in">
          <input type="text" v-model="search.agent" placeholder="Buscar agente..." class="dd-search">
          <div class="dd-actions">
            <span @click="selectedAgentsModel = [...agentOptions]">Todos</span>
            <span @click="selectedAgentsModel = []">Limpiar</span>
          </div>
          <div class="dd-list custom-scroll">
            <label v-for="agent in filteredAgents" :key="agent" class="dd-item">
              <input type="checkbox" :value="agent" v-model="selectedAgentsModel"> {{ agent }}
            </label>
          </div>
        </div>
      </div>

      <div class="f-group popover-wrap" v-click-outside="() => (dropdowns.vulns = false)">
        <label>Vulnerabilidad</label>
        <button class="filter-input dd-btn" @click="dropdowns.vulns = !dropdowns.vulns">
          <span>{{ selectedVulnsModel.length ? selectedVulnsModel.length + ' sel.' : 'Todas' }}</span>
          <span>▼</span>
        </button>
        <div v-if="dropdowns.vulns" class="dd-panel fade-in">
          <input type="text" v-model="search.vuln" placeholder="Buscar CVE..." class="dd-search">
          <div class="dd-actions">
            <span @click="selectedVulnsModel = [...vulnOptions]">Todas</span>
            <span @click="selectedVulnsModel = []">Limpiar</span>
          </div>
          <div class="dd-list custom-scroll">
            <label v-for="vuln in filteredVulns" :key="vuln" class="dd-item">
              <input type="checkbox" :value="vuln" v-model="selectedVulnsModel"> {{ vuln }}
            </label>
          </div>
        </div>
      </div>

      <div class="f-group popover-wrap" v-click-outside="() => (dropdowns.severity = false)">
        <label>Criticidad</label>
        <button class="filter-input dd-btn" @click="dropdowns.severity = !dropdowns.severity">
          <span>{{ selectedSeveritiesModel.length ? selectedSeveritiesModel.length + ' sel.' : 'Todas' }}</span>
          <span>▼</span>
        </button>
        <div v-if="dropdowns.severity" class="dd-panel fade-in">
          <div class="dd-actions">
            <span @click="selectedSeveritiesModel = [...severityOptions]">Todas</span>
            <span @click="selectedSeveritiesModel = []">Limpiar</span>
          </div>
          <div class="dd-list custom-scroll">
            <label v-for="sev in severityOptions" :key="sev" class="dd-item">
              <input type="checkbox" :value="sev" v-model="selectedSeveritiesModel">
              <span class="sev-badge" :style="{ background: severityColor(sev) }">{{ sev }}</span>
            </label>
          </div>
        </div>
      </div>

      <div class="f-group">
        <label>Desde</label>
        <input type="date" v-model="startDateModel" :max="endDate || today" class="filter-input">
      </div>

      <div class="f-group">
        <label>Hasta</label>
        <input type="date" v-model="endDateModel" :min="startDate" :max="today" class="filter-input">
      </div>

      <div class="f-group f-action">
        <button class="btn btn-primary" @click="emit('build')" :disabled="!selectedConnection || loading">
          {{ loading ? 'Analizando...' : 'Generar Vista' }}
        </button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, reactive } from 'vue'
import { severityColor } from '../timelineFormatters'

const props = defineProps({
  connections: { type: Array, required: true },
  agentOptions: { type: Array, required: true },
  vulnOptions: { type: Array, required: true },
  severityOptions: { type: Array, default: () => [] },
  selectedConnection: { type: [String, Number], default: '' },
  selectedAgents: { type: Array, required: true },
  selectedVulns: { type: Array, required: true },
  selectedSeverities: { type: Array, default: () => [] },
  startDate: { type: String, required: true },
  endDate: { type: String, required: true },
  loading: { type: Boolean, default: false }
})

const emit = defineEmits([
  'update:selectedConnection',
  'update:selectedAgents',
  'update:selectedVulns',
  'update:selectedSeverities',
  'update:startDate',
  'update:endDate',
  'connection-change',
  'build'
])

const today = new Date().toISOString().split('T')[0]

const connectionModel = computed({
  get: () => props.selectedConnection,
  set: value => emit('update:selectedConnection', value)
})

const selectedAgentsModel = computed({
  get: () => props.selectedAgents,
  set: value => emit('update:selectedAgents', value)
})

const selectedVulnsModel = computed({
  get: () => props.selectedVulns,
  set: value => emit('update:selectedVulns', value)
})

const startDateModel = computed({
  get: () => props.startDate,
  set: value => emit('update:startDate', value)
})

const endDateModel = computed({
  get: () => props.endDate,
  set: value => emit('update:endDate', value)
})

const selectedSeveritiesModel = computed({
  get: () => props.selectedSeverities,
  set: value => emit('update:selectedSeverities', value)
})

const search = reactive({ agent: '', vuln: '' })
const dropdowns = reactive({ agents: false, vulns: false, severity: false })

const filteredAgents = computed(() =>
  props.agentOptions.filter(agent => agent.toLowerCase().includes(search.agent.toLowerCase()))
)

const filteredVulns = computed(() =>
  props.vulnOptions.filter(vuln => vuln.toLowerCase().includes(search.vuln.toLowerCase()))
)
</script>

<style scoped>
.filter-panel { padding: 0; margin-bottom: 1.5rem; overflow: visible; }
.filter-row { display: grid; grid-template-columns: 1.1fr 0.9fr 0.9fr 0.85fr 0.75fr 0.65fr auto; align-items: stretch; }
.f-group { display: flex; flex-direction: column; padding: 1rem 1.2rem; border-right: 1px solid var(--border); }
.f-group:last-child { border-right: none; }
.f-group label { font-size: 0.7rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 0.5rem; }
.filter-input, .dd-btn { width: 100%; padding: 0.55rem 0.8rem; border: 1px solid var(--border); background: var(--bg-dark); border-radius: var(--radius-sm); color: var(--text-main); cursor: pointer; }
.f-action { justify-content: end; background: var(--bg-hover); }
.popover-wrap { position: relative; }
.dd-btn { display: flex; justify-content: space-between; }
.dd-panel { position: absolute; top: calc(100% + 6px); left: 0; width: 280px; border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--bg-panel); z-index: 20; overflow: hidden; }
.dd-search { width: 100%; border: none; border-bottom: 1px solid var(--border); padding: 0.65rem 0.9rem; background: var(--bg-hover); color: var(--text-main); }
.dd-actions { display: flex; justify-content: space-between; padding: 0.5rem 0.9rem; border-bottom: 1px solid var(--border); font-size: 0.75rem; color: var(--primary); }
.dd-actions span { cursor: pointer; }
.dd-list { max-height: 220px; overflow-y: auto; }
.dd-item { display: flex; gap: 0.6rem; padding: 0.4rem 0.9rem; font-size: 0.82rem; align-items: center; }
.sev-badge { color: #fff; font-size: 0.66rem; font-weight: 800; padding: 0.1rem 0.45rem; border-radius: 999px; text-transform: uppercase; }
.chip-row { display: flex; flex-wrap: wrap; gap: 0.35rem; }
.chip { padding: 0.4rem 0.8rem; border: 1px solid var(--border); border-radius: 6px; background: var(--bg-dark); font-size: 0.72rem; font-weight: 700; color: var(--text-muted); cursor: pointer; }
.chip.on { background: var(--primary); border-color: var(--primary); color: #fff; }

@media (max-width: 1100px) {
  .filter-row { grid-template-columns: 1fr 1fr; }
  .f-group { border-right: none; border-bottom: 1px solid var(--border); }
}
</style>

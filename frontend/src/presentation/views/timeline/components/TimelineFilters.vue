<template>
  <div class="card filter-panel">
    <div class="filter-row">
      <div class="f-group">
        <label>Conexion Wazuh</label>
        <select v-model="connectionModel" @change="emit('connection-change')" class="filter-input">
          <option value="">Todos los servidores</option>
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

      <div class="f-group popover-wrap" v-click-outside="() => (dropdowns.groups = false)">
        <label>Grupos</label>
        <button class="filter-input dd-btn" @click="dropdowns.groups = !dropdowns.groups">
          <span>{{ selectedGroupsModel.length ? selectedGroupsModel.length + ' sel.' : 'Todos' }}</span>
          <span>▼</span>
        </button>
        <div v-if="dropdowns.groups" class="dd-panel fade-in">
          <input type="text" v-model="search.group" placeholder="Buscar grupo..." class="dd-search">
          <div class="dd-actions">
            <span @click="selectedGroupsModel = groupOptions.map(g => g.name)">Todos</span>
            <span @click="selectedGroupsModel = []">Limpiar</span>
          </div>
          <div class="dd-list custom-scroll">
            <label v-for="grp in filteredGroups" :key="grp.name" class="dd-item">
              <input type="checkbox" :value="grp.name" v-model="selectedGroupsModel"> {{ grp.name }}
            </label>
          </div>
        </div>
      </div>

      <div class="f-group popover-wrap" v-click-outside="() => (dropdowns.os = false)">
        <label>S.O.</label>
        <button class="filter-input dd-btn" @click="dropdowns.os = !dropdowns.os">
          <span>{{ selectedOsModel.length ? selectedOsModel.length + ' sel.' : 'Todos' }}</span>
          <span>▼</span>
        </button>
        <div v-if="dropdowns.os" class="dd-panel fade-in">
          <div class="dd-actions">
            <span @click="selectedOsModel = [...osPlatformOptions]">Todos</span>
            <span @click="selectedOsModel = []">Limpiar</span>
          </div>
          <div class="dd-list custom-scroll">
            <label v-for="platform in osPlatformOptions" :key="platform" class="dd-item">
              <input type="checkbox" :value="platform" v-model="selectedOsModel"> {{ platform }}
            </label>
          </div>
        </div>
      </div>

      <div class="f-group">
        <label>Estado</label>
        <select v-model="selectedStatusModel" class="filter-input">
          <option value="">Todas</option>
          <option value="no_resuelta">No resueltas</option>
          <option value="resuelta">Resueltas</option>
        </select>
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
        <select v-model="startMonthModel" class="filter-input" data-testid="start-month">
          <option v-for="month in monthOptions" :key="month.value" :value="month.value">
            {{ month.label }}
          </option>
        </select>
      </div>

      <div class="f-group">
        <label>Hasta</label>
        <select v-model="endMonthModel" class="filter-input" data-testid="end-month">
          <option v-for="month in endMonthOptions" :key="month.value" :value="month.value">
            {{ month.label }}
          </option>
        </select>
      </div>

      <div class="f-group f-action">
        <button class="btn btn-primary" @click="emit('build')" :disabled="loading">
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
  groupOptions: { type: Array, default: () => [] },
  osOptions: { type: Array, default: () => [] },
  selectedConnection: { type: [String, Number], default: '' },
  selectedAgents: { type: Array, required: true },
  selectedVulns: { type: Array, required: true },
  selectedSeverities: { type: Array, default: () => [] },
  selectedGroups: { type: Array, default: () => [] },
  selectedOsPlatforms: { type: Array, default: () => [] },
  selectedStatus: { type: String, default: '' },
  startDate: { type: String, required: true },
  endDate: { type: String, required: true },
  loading: { type: Boolean, default: false }
})

const emit = defineEmits([
  'update:selectedConnection',
  'update:selectedAgents',
  'update:selectedVulns',
  'update:selectedSeverities',
  'update:selectedGroups',
  'update:selectedOsPlatforms',
  'update:selectedStatus',
  'update:startDate',
  'update:endDate',
  'connection-change',
  'build'
])

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

const monthEndDate = value => {
  const [year, month] = value.split('-').map(Number)
  const lastDay = new Date(Date.UTC(year, month, 0)).getUTCDate()
  return `${value}-${String(lastDay).padStart(2, '0')}`
}

// Desde = primer día del mes elegido.
const startMonthModel = computed({
  get: () => (props.startDate || '').slice(0, 7),
  set: value => {
    emit('update:startDate', value ? `${value}-01` : '')
    if (value && endMonthModel.value && endMonthModel.value < value) {
      emit('update:endDate', monthEndDate(value))
    }
  }
})

// Hasta = último día del mes elegido.
const endMonthModel = computed({
  get: () => (props.endDate || '').slice(0, 7),
  set: value => emit('update:endDate', value ? monthEndDate(value) : '')
})

// Selectores explícitos: input[type=month] no es consistente entre navegadores.
const monthOptions = computed(() => {
  const options = []
  const now = new Date()
  for (let offset = 0; offset < 120; offset += 1) {
    const date = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - offset, 1))
    const value = `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, '0')}`
    options.push({
      value,
      label: date.toLocaleDateString('es-CL', {
        month: 'long',
        year: 'numeric',
        timeZone: 'UTC'
      })
    })
  }
  return options
})

const endMonthOptions = computed(() =>
  monthOptions.value.filter(month => !startMonthModel.value || month.value >= startMonthModel.value)
)

const selectedSeveritiesModel = computed({
  get: () => props.selectedSeverities,
  set: value => emit('update:selectedSeverities', value)
})

const selectedGroupsModel = computed({
  get: () => props.selectedGroups,
  set: value => emit('update:selectedGroups', value)
})

const selectedOsModel = computed({
  get: () => props.selectedOsPlatforms,
  set: value => emit('update:selectedOsPlatforms', value)
})

const selectedStatusModel = computed({
  get: () => props.selectedStatus,
  set: value => emit('update:selectedStatus', value)
})

const search = reactive({ agent: '', vuln: '', group: '' })
const dropdowns = reactive({
  agents: false, vulns: false, severity: false, groups: false, os: false
})

const filteredAgents = computed(() =>
  props.agentOptions.filter(agent => agent.toLowerCase().includes(search.agent.toLowerCase()))
)

const filteredVulns = computed(() =>
  props.vulnOptions.filter(vuln => vuln.toLowerCase().includes(search.vuln.toLowerCase()))
)

const filteredGroups = computed(() =>
  props.groupOptions.filter(grp =>
    (grp.name || '').toLowerCase().includes(search.group.toLowerCase())
  )
)

const osPlatformOptions = computed(() =>
  [...new Set(props.osOptions.map(os => os.platform).filter(Boolean))].sort()
)
</script>

<style scoped>
.filter-panel { padding: 0; margin-bottom: 1.5rem; overflow: visible; }
.filter-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); align-items: stretch; }
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

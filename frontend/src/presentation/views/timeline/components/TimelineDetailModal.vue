<template>
  <div v-if="show && eventData" class="modal-overlay" @click.self="emit('close')">
    <div class="modal-box fade-in">
      <div class="modal-top">
        <div>
          <h2>
            <code>{{ eventData.cve_id }}</code>
            <span class="sev-tag" :style="{ background: color(eventData.severity) }">
              {{ (eventData.severity || 'N/A').toUpperCase() }}
            </span>
          </h2>
          <p class="text-muted">{{ eventData.agent_name }} · {{ eventData.package_name }} v{{ eventData.package_version }}</p>
        </div>
        <button class="modal-close" @click="emit('close')">&times;</button>
      </div>

      <div class="modal-content custom-scroll">
        <!-- Resumen de la amenaza (estado actual, desde BD) -->
        <div class="meta-grid">
          <div class="meta-tile">
            <span class="meta-label">Estado</span>
            <strong :class="eventData.status === 'ACTIVE' ? 'st-active' : 'st-resolved'">
              {{ eventData.status === 'ACTIVE' ? 'ACTIVA' : 'RESUELTA' }}
            </strong>
          </div>
          <div class="meta-tile">
            <span class="meta-label">Score CVSS</span>
            <strong>{{ eventData.score_base != null ? eventData.score_base.toFixed(1) : 'N/A' }}</strong>
          </div>
          <div class="meta-tile">
            <span class="meta-label">Detectada</span>
            <strong>{{ fmtDateTime(eventData.start || eventData.first_seen) }}</strong>
          </div>
          <div class="meta-tile">
            <span class="meta-label">{{ eventData.status === 'ACTIVE' ? 'Última vista' : 'Resuelta' }}</span>
            <strong>{{ eventData.last_seen ? fmtDateTime(eventData.last_seen) : '-' }}</strong>
          </div>
          <div class="meta-tile" v-if="eventData.connection_name">
            <span class="meta-label">Conexión</span>
            <strong>{{ eventData.connection_name }}</strong>
          </div>
        </div>

        <h3 class="hist-title">Historial de la amenaza</h3>

        <div v-if="loading" class="hist-loading">Cargando historial...</div>

        <ul v-else-if="history.length" class="hist-list">
          <li v-for="h in history" :key="h.id" class="hist-item">
            <span class="hist-action" :class="actionClass(h.action)">{{ actionLabel(h.action) }}</span>
            <span class="hist-when">{{ fmtDateTime(h.timestamp) }}</span>
            <span class="hist-detail">{{ h.details }}</span>
          </li>
        </ul>

        <p v-else class="hist-empty">Sin eventos de historial registrados.</p>
      </div>

      <div class="modal-bottom">
        <span>{{ history.length }} evento(s) de historial</span>
        <button class="btn modal-outline" @click="emit('close')">Cerrar</button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { fmtDateTime, severityColor } from '../timelineFormatters'

const props = defineProps({
  show: { type: Boolean, default: false },
  eventData: { type: Object, default: null },
  loading: { type: Boolean, default: false },
})

const emit = defineEmits(['close'])

const color = severityColor

const history = computed(() => {
  if (!props.eventData || !Array.isArray(props.eventData.history)) return []
  return props.eventData.history
})

const ACTION_LABELS = {
  DETECTED: 'Detectada',
  REOPENED: 'Reabierta',
  RESOLVED: 'Resuelta',
  SEVERITY_CHANGED: 'Severidad',
}

const actionLabel = action => ACTION_LABELS[action] || action

const actionClass = action => {
  if (action === 'RESOLVED') return 'a-resolved'
  if (action === 'REOPENED') return 'a-reopened'
  if (action === 'SEVERITY_CHANGED') return 'a-severity'
  return 'a-detected'
}
</script>

<style scoped>
.modal-overlay { position: fixed; inset: 0; background: rgba(0, 0, 0, 0.45); z-index: 200; display: flex; align-items: center; justify-content: center; padding: 1rem; }
.modal-box { width: 100%; max-width: 760px; max-height: 88vh; background: var(--bg-panel); border-radius: var(--radius-lg); display: flex; flex-direction: column; overflow: hidden; }
.modal-top { display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; padding: 1rem 1.2rem; border-bottom: 1px solid var(--border); }
.modal-top h2 { display: flex; align-items: center; gap: 0.6rem; margin: 0; font-size: 1.1rem; }
.sev-tag { color: #fff; font-size: 0.62rem; font-weight: 800; padding: 0.15rem 0.5rem; border-radius: 999px; letter-spacing: 0.03em; }
.modal-close { border: none; background: transparent; color: var(--text-muted); font-size: 1.5rem; cursor: pointer; line-height: 1; }
.modal-content { overflow: auto; padding: 1.2rem; }

.meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 0.75rem; margin-bottom: 1.4rem; }
.meta-tile { border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 0.6rem 0.75rem; background: var(--bg-hover); }
.meta-label { display: block; font-size: 0.65rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700; margin-bottom: 0.25rem; }
.meta-tile strong { font-size: 0.85rem; color: var(--text-main); }
.st-active { color: var(--danger); }
.st-resolved { color: var(--success); }

.hist-title { font-size: 0.85rem; margin: 0 0 0.75rem; color: var(--text-main); }
.hist-loading, .hist-empty { color: var(--text-muted); font-size: 0.85rem; }

.hist-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.5rem; }
.hist-item { display: grid; grid-template-columns: 110px 150px 1fr; gap: 0.6rem; align-items: baseline; padding: 0.5rem 0.6rem; border: 1px solid var(--border); border-radius: var(--radius-sm); font-size: 0.78rem; }
.hist-action { font-weight: 800; font-size: 0.66rem; text-transform: uppercase; padding: 0.15rem 0.4rem; border-radius: 4px; text-align: center; }
.a-detected { background: rgba(110, 164, 42, 0.15); color: #4d7c0f; }
.a-reopened { background: rgba(217, 119, 6, 0.15); color: #b45309; }
.a-resolved { background: rgba(5, 150, 105, 0.15); color: #047857; }
.a-severity { background: rgba(59, 130, 246, 0.15); color: #1d4ed8; }
.hist-when { color: var(--text-muted); }
.hist-detail { color: var(--text-main); }

.modal-bottom { display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 1.2rem; border-top: 1px solid var(--border); font-size: 0.78rem; color: var(--text-muted); }
.modal-outline { background: transparent; color: var(--text-muted); border: 1px solid var(--border); }

@media (max-width: 600px) {
  .hist-item { grid-template-columns: 1fr; gap: 0.2rem; }
}
</style>

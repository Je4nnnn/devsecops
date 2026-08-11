<template>
  <div class="card timeline-card">
    <div class="tl-toolbar">
      <div class="tl-toolbar-left">
        <span class="tl-year">{{ rangeLabel }}</span>
        <span class="tl-info">{{ bars.length }} amenazas</span>
        <span v-if="isFuture" class="tl-note" title="No hay datos posteriores a hoy; la barra se prolonga con el último estado conocido.">
          ⓘ Tiempos futuros: se asume el último estado detectado
        </span>
      </div>
      <div class="tl-legend">
        <span class="lg-item"><i class="dot" style="background:#dc2626"></i>Crítica</span>
        <span class="lg-item"><i class="dot" style="background:#ea580c"></i>Alta</span>
        <span class="lg-item"><i class="dot" style="background:#d97706"></i>Media</span>
        <span class="lg-item"><i class="dot" style="background:#3b82f6"></i>Baja</span>
        <span class="lg-item"><i class="dot ongoing-dot"></i>En curso</span>
        <span class="lg-item"><i class="dot" style="background:#16a34a"></i>Resuelta</span>
        <span class="lg-item"><i class="dot absent-dot"></i>No existía</span>
        <span class="lg-item"><i class="dot unknown-dot"></i>Sin datos</span>
      </div>
    </div>

    <div class="gantt">
      <!-- Filas (una barra por amenaza). El eje va dentro para compartir el
           mismo ancho que las filas cuando aparece el scrollbar. -->
      <div class="gantt-body custom-scroll">
        <!-- Eje de meses: una celda cerrada por mes, pegado arriba -->
        <div class="gantt-axis">
          <div class="gantt-axis-label-col"></div>
          <div class="gantt-axis-track">
            <div
              v-for="m in months"
              :key="m.key"
              class="axis-month"
              :style="{ left: m.leftPct + '%', width: m.widthPct + '%' }"
            >
              <span class="axis-month-label">{{ m.label }}</span>
            </div>
          </div>
        </div>

        <div v-for="bar in bars" :key="bar.id" class="gantt-row">
          <div class="gantt-row-label" :title="`${bar.cve_id} · ${bar.agent_name}`">
            <span class="sev-pip" :style="{ background: color(bar.severity) }"></span>
            <span class="row-cve">{{ bar.cve_id }}</span>
            <span class="row-agent">{{ bar.agent_name }}</span>
          </div>

          <div class="gantt-row-track">
            <!-- Borde vertical de cada mes (columnas cerradas) -->
            <div
              v-for="m in months"
              :key="`g-${bar.id}-${m.key}`"
              class="grid-line"
              :style="{ left: m.leftPct + '%' }"
            ></div>

            <!-- Tramos previos a la detección: sin datos / no existía -->
            <div
              v-for="seg in contextSegments(bar)"
              :key="`s-${bar.id}-${seg.kind}-${seg.leftPct}`"
              class="gantt-seg"
              :class="`seg-${seg.kind}`"
              :style="{ left: seg.leftPct + '%', width: seg.widthPct + '%' }"
              :title="segmentTitle(seg)"
            ></div>

            <!-- Tramo remediado: verde desde la resolución hasta el fin del rango -->
            <div
              v-for="seg in resolvedSegments(bar)"
              :key="`r-${bar.id}-${seg.leftPct}`"
              class="gantt-seg seg-resolved"
              :style="{ left: seg.leftPct + '%', width: seg.widthPct + '%' }"
              :title="segmentTitle(seg)"
            ></div>

            <button
              class="gantt-bar"
              :class="{ ongoing: bar.ongoing, 'clip-left': bar.clippedLeft, 'clip-right': bar.clippedRight }"
              :style="{ left: bar.leftPct + '%', width: bar.widthPct + '%', background: color(bar.severity) }"
              @click="emit('open-threat', bar)"
              :title="barTitle(bar)"
            >
              <span class="bar-text">{{ bar.package_name }}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { severityColor } from '../timelineFormatters'

const props = defineProps({
  bars: { type: Array, required: true },
  range: { type: Object, required: true },
  spanMs: { type: Number, required: true },
})

const emit = defineEmits(['open-threat'])

const color = severityColor

// Una celda por mes calendario dentro del rango visible, recortada a los bordes.
const months = computed(() => {
  const { startMs, endMs } = props.range
  const span = props.spanMs
  if (!(span > 0)) return []
  const out = []
  const start = new Date(startMs)
  let cur = new Date(start.getFullYear(), start.getMonth(), 1)
  while (cur.getTime() < endMs) {
    const next = new Date(cur.getFullYear(), cur.getMonth() + 1, 1)
    const from = Math.max(cur.getTime(), startMs)
    const to = Math.min(next.getTime(), endMs)
    out.push({
      key: `${cur.getFullYear()}-${cur.getMonth()}`,
      leftPct: ((from - startMs) / span) * 100,
      widthPct: ((to - from) / span) * 100,
      label: cur.toLocaleDateString('es-CL', { month: 'short', year: 'numeric' }),
    })
    cur = next
  }
  return out
})

const isFuture = computed(() => props.range.endMs > Date.now())

const fmtMonth = ms =>
  new Date(ms).toLocaleDateString('es-CL', { month: 'short', year: 'numeric' })

const rangeLabel = computed(() => {
  const { startMs, endMs } = props.range
  return `${fmtMonth(startMs)} → ${fmtMonth(endMs)}`
})

const barTitle = bar => {
  const estado = bar.ongoing ? 'En curso (activa)' : 'Resuelta'
  return `${bar.cve_id} · ${bar.agent_name}\n${bar.package_name} v${bar.package_version}\n${estado}`
}

const SEGMENT_LABELS = {
  unknown: 'Sin datos: no había sincronización en este periodo',
  absent: 'La vulnerabilidad todavía no existía en el equipo',
  resolved: 'Remediada: ya no es reportada por el agente',
}

const segmentTitle = seg => SEGMENT_LABELS[seg.kind] || ''

const contextSegments = bar =>
  (bar.segments || []).filter(seg => seg.kind === 'unknown' || seg.kind === 'absent')

const resolvedSegments = bar =>
  (bar.segments || []).filter(seg => seg.kind === 'resolved')
</script>

<style scoped>
.timeline-card { padding: 0; overflow: hidden; }
.tl-toolbar { display: flex; justify-content: space-between; align-items: center; gap: 1rem; flex-wrap: wrap; padding: 0.9rem 1.2rem; border-bottom: 1px solid var(--border); background: var(--bg-hover); }
.tl-toolbar-left { display: flex; gap: 1rem; align-items: baseline; }
.tl-year { font-weight: 800; font-size: 0.95rem; }
.tl-info { font-size: 0.78rem; color: var(--text-muted); }
.tl-note { font-size: 0.72rem; color: var(--primary); font-weight: 600; cursor: help; }
.tl-legend { display: flex; gap: 0.85rem; flex-wrap: wrap; }
.lg-item { display: flex; align-items: center; gap: 0.35rem; font-size: 0.72rem; color: var(--text-muted); font-weight: 600; }
.dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }
.ongoing-dot { background: repeating-linear-gradient(45deg, #64748b, #64748b 2px, #cbd5e1 2px, #cbd5e1 4px); }
.absent-dot { background: #ffffff; border: 1px solid var(--border); }
.unknown-dot { background: repeating-linear-gradient(45deg, #e2e8f0, #e2e8f0 2px, #f8fafc 2px, #f8fafc 4px); }

.gantt { display: flex; flex-direction: column; }

.gantt-axis { display: flex; border-bottom: 1px solid var(--border); background: var(--bg-panel); position: sticky; top: 0; z-index: 4; }
.gantt-axis-label-col { width: 220px; flex-shrink: 0; border-right: 1px solid var(--border); }
.gantt-axis-track { position: relative; flex: 1; height: 34px; }
.axis-month { position: absolute; top: 0; height: 100%; border-left: 1px solid var(--border); display: flex; align-items: center; justify-content: center; overflow: hidden; }
.axis-month:last-child { border-right: 1px solid var(--border); }
.axis-month-label { font-size: 0.7rem; font-weight: 700; color: var(--text-muted); white-space: nowrap; text-transform: capitalize; padding: 0 0.3rem; }

.gantt-body { max-height: 560px; overflow-y: auto; }

.gantt-row { display: flex; align-items: stretch; min-height: 32px; border-bottom: 1px solid var(--border); }
.gantt-row:hover { background: var(--bg-hover); }
.gantt-row:hover .grid-line { background: var(--bg-hover); }

.gantt-row-label {
  width: 220px;
  flex-shrink: 0;
  display: flex;
  align-items: center;
  gap: 0.45rem;
  padding: 0 0.7rem;
  border-right: 1px solid var(--border);
  overflow: hidden;
}
.sev-pip { width: 8px; height: 8px; border-radius: 2px; flex-shrink: 0; }
.row-cve { font-size: 0.72rem; font-weight: 700; color: var(--text-main); white-space: nowrap; }
.row-agent { font-size: 0.68rem; color: var(--text-muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

.gantt-row-track { position: relative; flex: 1; min-width: 0; }
/* Separa cada mes en un cuadrado distinto: corta las barras en el borde del mes. */
.grid-line { position: absolute; top: 0; bottom: 0; width: 3px; transform: translateX(-1.5px); background: var(--bg-panel); z-index: 3; }

/* Tramos de contexto (sin datos / no existía / remediada) */
.gantt-seg {
  position: absolute;
  top: 50%;
  transform: translateY(-50%);
  height: 16px;
  border-radius: 3px;
  z-index: 1;
}

/* Blanco: consta que la vulnerabilidad NO existía en ese periodo */
.seg-absent {
  background: #ffffff;
  border: 1px dashed var(--border);
}

/* Gris tenue: aún no había sincronizaciones, no sabemos qué pasaba */
.seg-unknown {
  background: repeating-linear-gradient(45deg, #e2e8f0, #e2e8f0 3px, #f8fafc 3px, #f8fafc 6px);
  opacity: 0.7;
}

/* Verde: periodo ya remediado */
.seg-resolved {
  background: #16a34a;
  opacity: 0.85;
}

.gantt-bar {
  position: absolute;
  top: 50%;
  transform: translateY(-50%);
  height: 16px;
  min-width: 4px;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  z-index: 2;
  box-shadow: var(--shadow-sm);
  display: flex;
  align-items: center;
  overflow: hidden;
  transition: filter 0.15s ease, transform 0.15s ease;
}
.gantt-bar:hover { filter: brightness(1.1); transform: translateY(-50%) scaleY(1.15); }
.bar-text { font-size: 0.62rem; color: #fff; font-weight: 600; padding: 0 0.4rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

/* Indicadores de recorte fuera de rango */
.gantt-bar.clip-left { border-top-left-radius: 0; border-bottom-left-radius: 0; }
.gantt-bar.clip-right { border-top-right-radius: 0; border-bottom-right-radius: 0; }
/* Amenaza aún activa: rayado para indicar continuidad */
.gantt-bar.ongoing { background-image: repeating-linear-gradient(45deg, rgba(255,255,255,0.18), rgba(255,255,255,0.18) 4px, transparent 4px, transparent 8px); }

@media (max-width: 768px) {
  .gantt-axis-label-col, .gantt-row-label { width: 130px; }
  .row-agent { display: none; }
}
</style>

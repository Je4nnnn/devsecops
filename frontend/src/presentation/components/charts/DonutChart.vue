<template>
  <div class="donut-chart">
    <svg :viewBox="`0 0 ${SIZE} ${SIZE}`" class="donut-svg" role="img" :aria-label="ariaLabel">
      <g :transform="`rotate(-90 ${CENTER} ${CENTER})`">
        <circle
          class="donut-track"
          :cx="CENTER" :cy="CENTER" :r="RADIUS"
          fill="none" :stroke-width="THICKNESS"
        />
        <circle
          v-for="arc in arcs"
          :key="arc.label"
          :cx="CENTER" :cy="CENTER" :r="RADIUS"
          fill="none"
          :stroke="arc.color"
          :stroke-width="THICKNESS"
          :stroke-dasharray="`${arc.length} ${CIRCUMFERENCE}`"
          :stroke-dashoffset="-arc.offset"
          stroke-linecap="butt"
        >
          <title>{{ arc.label }}: {{ arc.value }} ({{ arc.pct }}%)</title>
        </circle>
      </g>

      <text :x="CENTER" :y="CENTER - 2" class="donut-value" text-anchor="middle">
        {{ centerValue }}
      </text>
      <text :x="CENTER" :y="CENTER + 16" class="donut-caption" text-anchor="middle">
        {{ centerLabel }}
      </text>
    </svg>

    <ul class="donut-legend">
      <li v-for="arc in arcs" :key="`lg-${arc.label}`">
        <i class="swatch" :style="{ background: arc.color }"></i>
        <span class="lg-label">{{ arc.label }}</span>
        <strong class="lg-value">{{ arc.value }}</strong>
        <span class="lg-pct">{{ arc.pct }}%</span>
      </li>
    </ul>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  // [{ label, value, color }]
  segments: { type: Array, required: true },
  centerValue: { type: [String, Number], default: '' },
  centerLabel: { type: String, default: '' },
  ariaLabel: { type: String, default: 'Gráfico de torta' },
})

const SIZE = 140
const CENTER = SIZE / 2
const THICKNESS = 22
const RADIUS = CENTER - THICKNESS / 2 - 2
const CIRCUMFERENCE = 2 * Math.PI * RADIUS

const total = computed(() =>
  props.segments.reduce((sum, seg) => sum + (Number(seg.value) || 0), 0)
)

const arcs = computed(() => {
  let offset = 0
  return props.segments.map(seg => {
    const value = Number(seg.value) || 0
    const share = total.value ? value / total.value : 0
    const length = share * CIRCUMFERENCE
    const arc = {
      label: seg.label,
      color: seg.color,
      value,
      pct: total.value ? Math.round(share * 1000) / 10 : 0,
      length,
      offset,
    }
    offset += length
    return arc
  })
})
</script>

<style scoped>
.donut-chart {
  display: flex;
  align-items: center;
  gap: 1.1rem;
  flex-wrap: wrap;
}

.donut-svg {
  width: 140px;
  height: 140px;
  flex-shrink: 0;
}

.donut-track {
  stroke: var(--bg-hover);
}

.donut-value {
  font-size: 1.5rem;
  font-weight: 800;
  fill: var(--text-main);
}

.donut-caption {
  font-size: 0.62rem;
  font-weight: 700;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  fill: var(--text-muted);
}

.donut-legend {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.45rem;
  min-width: 0;
  flex: 1;
}

.donut-legend li {
  display: grid;
  grid-template-columns: 10px minmax(0, 1fr) auto auto;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.8rem;
}

.swatch {
  width: 10px;
  height: 10px;
  border-radius: 3px;
  display: inline-block;
}

.lg-label {
  color: var(--text-muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.lg-value {
  color: var(--text-main);
}

.lg-pct {
  color: var(--text-muted);
  font-size: 0.72rem;
  min-width: 42px;
  text-align: right;
}
</style>

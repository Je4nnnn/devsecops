<template>
  <div class="histogram">
    <p v-if="!bars.length" class="hist-empty">{{ emptyText }}</p>

    <div v-else class="hist-rows">
      <div v-for="bar in bars" :key="bar.key" class="hist-row">
        <span class="hist-label" :title="bar.tooltip || bar.label">{{ bar.label }}</span>
        <div class="hist-track">
          <div
            class="hist-fill"
            :style="{ width: bar.widthPct + '%', background: bar.color || defaultColor }"
          >
            <span v-if="bar.widthPct > 22" class="hist-inline">{{ bar.value }}</span>
          </div>
        </div>
        <strong class="hist-value">{{ bar.value }}</strong>
      </div>
    </div>

    <div v-if="bars.length" class="hist-axis">
      <span v-for="tick in ticks" :key="tick">{{ tick }}</span>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  // [{ key, label, value, color?, tooltip? }]
  items: { type: Array, required: true },
  defaultColor: { type: String, default: '#dc2626' },
  emptyText: { type: String, default: 'Sin datos para graficar.' },
})

const maxValue = computed(() =>
  props.items.reduce((max, item) => Math.max(max, Number(item.value) || 0), 0)
)

const bars = computed(() =>
  props.items.map(item => {
    const value = Number(item.value) || 0
    return {
      ...item,
      value,
      // Mínimo 3% para que una barra con valor 1 siga siendo visible.
      widthPct: maxValue.value ? Math.max(3, (value / maxValue.value) * 100) : 0,
    }
  })
)

const ticks = computed(() => {
  const max = maxValue.value
  if (!max) return []
  return [0, Math.round(max / 2), max]
})
</script>

<style scoped>
.histogram {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.hist-rows {
  display: flex;
  flex-direction: column;
  gap: 0.45rem;
  max-height: 320px;
  overflow-y: auto;
}

.hist-row {
  display: grid;
  grid-template-columns: minmax(90px, 150px) minmax(0, 1fr) 42px;
  gap: 0.65rem;
  align-items: center;
  font-size: 0.82rem;
}

.hist-label {
  color: var(--text-muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.hist-track {
  height: 16px;
  border-radius: 4px;
  background: var(--bg-hover);
  overflow: hidden;
}

.hist-fill {
  height: 100%;
  border-radius: 4px;
  display: flex;
  align-items: center;
  justify-content: flex-end;
  transition: width 0.35s ease;
}

.hist-inline {
  font-size: 0.66rem;
  font-weight: 700;
  color: #fff;
  padding-right: 0.4rem;
}

.hist-value {
  color: var(--text-main);
  text-align: right;
}

.hist-axis {
  display: flex;
  justify-content: space-between;
  padding-left: calc(150px + 0.65rem);
  padding-right: calc(42px + 0.65rem);
  font-size: 0.68rem;
  color: var(--text-muted);
}

.hist-empty {
  color: var(--text-muted);
  margin: 0;
}

@media (max-width: 768px) {
  .hist-row { grid-template-columns: 90px minmax(0, 1fr) 36px; }
  .hist-axis { padding-left: calc(90px + 0.65rem); }
}
</style>

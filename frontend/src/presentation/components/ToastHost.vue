<template>
  <div class="toast-host">
    <transition-group name="toast">
      <div
        v-for="t in toasts"
        :key="t.id"
        class="toast"
        :class="`toast-${t.type}`"
        @click="remove(t.id)"
      >
        <div class="toast-icon">
          <svg v-if="t.type === 'success'" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
          <svg v-else-if="t.type === 'error'" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>
          <svg v-else-if="t.type === 'warning'" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
          <svg v-else width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
        </div>
        <div class="toast-body">
          <strong v-if="t.title" class="toast-title">{{ t.title }}</strong>
          <span class="toast-msg">{{ t.message }}</span>
        </div>
      </div>
    </transition-group>
  </div>
</template>

<script setup>
import { useToast } from '../composables/useToast'

const { toasts, remove } = useToast()
</script>

<style scoped>
.toast-host {
  position: fixed;
  top: 1.25rem;
  right: 1.25rem;
  z-index: 9999;
  display: flex;
  flex-direction: column;
  gap: 0.6rem;
  max-width: 380px;
}

.toast {
  display: flex;
  align-items: flex-start;
  gap: 0.7rem;
  padding: 0.85rem 1rem;
  border-radius: 10px;
  background: var(--bg-panel, #1b1f24);
  border: 1px solid var(--border, #2a2f36);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35);
  cursor: pointer;
  color: var(--text-main, #e7eaee);
  border-left: 4px solid var(--text-muted, #8b94a0);
}

.toast-success { border-left-color: #16a34a; }
.toast-error { border-left-color: #dc2626; }
.toast-warning { border-left-color: #d97706; }
.toast-info { border-left-color: #3b82f6; }

.toast-success .toast-icon { color: #16a34a; }
.toast-error .toast-icon { color: #dc2626; }
.toast-warning .toast-icon { color: #d97706; }
.toast-info .toast-icon { color: #3b82f6; }

.toast-icon { flex-shrink: 0; margin-top: 1px; }

.toast-body { display: flex; flex-direction: column; gap: 0.15rem; }
.toast-title { font-size: 0.86rem; font-weight: 700; }
.toast-msg { font-size: 0.82rem; color: var(--text-muted, #aab2bd); line-height: 1.35; }

.toast-enter-active, .toast-leave-active { transition: all 0.3s ease; }
.toast-enter-from { opacity: 0; transform: translateX(40px); }
.toast-leave-to { opacity: 0; transform: translateX(40px); }
</style>

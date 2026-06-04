import { ref } from 'vue'

// Store singleton de toasts (compartido por toda la app)
const toasts = ref([])
let seq = 0

const remove = (id) => {
  toasts.value = toasts.value.filter(t => t.id !== id)
}

const push = (message, { type = 'info', title = '', timeout = 4500 } = {}) => {
  const id = ++seq
  toasts.value.push({ id, message, type, title })
  if (timeout > 0) {
    setTimeout(() => remove(id), timeout)
  }
  return id
}

export function useToast() {
  return {
    toasts,
    remove,
    toast: push,
    success: (msg, opts = {}) => push(msg, { ...opts, type: 'success' }),
    error: (msg, opts = {}) => push(msg, { ...opts, type: 'error' }),
    info: (msg, opts = {}) => push(msg, { ...opts, type: 'info' }),
    warning: (msg, opts = {}) => push(msg, { ...opts, type: 'warning' }),
  }
}

export const HOUR_MS = 3600000
export const DAY_MS = 86400000

const pad2 = number => String(number).padStart(2, '0')

export const alignHour = ms => Math.floor(ms / HOUR_MS) * HOUR_MS

export const fmtDDMM = ms => {
  const date = new Date(ms)
  return `${pad2(date.getDate())}/${pad2(date.getMonth() + 1)}`
}

export const fmtYear = ms => String(new Date(ms).getFullYear())

export const fmtHour = ms => {
  const date = new Date(ms)
  return `${pad2(date.getHours())}:00`
}

export const fmtDateTime = value => {
  const date = new Date(value)
  return date.toLocaleString('es-CL', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  })
}

export const badge = type => {
  if (type === 'detection') return 'NUEVA'
  if (type === 'resolution') return 'RESUELTA'
  return 'MIXTO'
}

export const fmtDayLabel = ms => {
  const date = new Date(ms)
  return date.toLocaleDateString('es-CL', { day: '2-digit', month: 'short' })
}

// Clave de severidad normalizada (es/en) para color y orden.
export const severityKey = value => {
  const s = (value || '').toLowerCase()
  if (['critical', 'critica', 'crítica'].includes(s)) return 'critical'
  if (['high', 'alta'].includes(s)) return 'high'
  if (['medium', 'media'].includes(s)) return 'medium'
  return 'low'
}

export const SEVERITY_COLORS = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#d97706',
  low: '#3b82f6',
}

export const severityColor = value => SEVERITY_COLORS[severityKey(value)]

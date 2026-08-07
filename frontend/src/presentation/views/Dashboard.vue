<template>
  <div class="fade-in">
    <!-- Header Area -->
    <div class="header-actions">
      <div>
        <h1 class="title">Panorama de Amenazas</h1>
        <p class="subtitle">Visualiza y gestiona el inventario de vulnerabilidades reportado por Wazuh.</p>
      </div>
      <div class="header-right">
        <div v-if="evolutionSummary?.last_sync_at" class="sync-badge">
          <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
          <span>Último sync: <strong>{{ timeAgo(evolutionSummary.last_sync_at) }}</strong></span>
          <span class="sync-date-full">{{ formatDate(evolutionSummary.last_sync_at) }}</span>
        </div>
        <button class="btn btn-primary" @click="onSyncClick" :disabled="isSyncing">
          <svg v-if="isSyncing" class="spin" xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="2" x2="12" y2="6"></line><line x1="12" y1="18" x2="12" y2="22"></line><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"></line><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"></line><line x1="2" y1="12" x2="6" y2="12"></line><line x1="18" y1="12" x2="22" y2="12"></line><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"></line><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"></line></svg>
          <svg v-else xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.59-9.5l1.75 1.93"></path></svg>
          {{ isSyncing ? 'Sincronizando en segundo plano...' : 'Forzar Sincronización' }}
        </button>
      </div>
    </div>

    <!-- Barra de progreso de sincronización (segundo plano) -->
    <div v-if="isSyncing" class="sync-progress card fade-in">
      <div class="sync-progress-head">
        <span class="sync-progress-phase">{{ phaseLabel }}</span>
        <span class="sync-progress-pct">{{ progressPct }}%</span>
      </div>
      <div class="sync-progress-track">
        <div class="sync-progress-fill" :style="{ width: progressPct + '%' }"></div>
      </div>
      <p class="sync-progress-hint">Puedes seguir navegando; te avisaremos cuando termine.</p>
    </div>

    <!-- Error/Loading states -->
    <div v-if="error" class="alert alert-danger fade-in">
      <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
      {{ error }}
    </div>

    <div v-if="evolutionSummary" class="evolution-grid">
      <div class="metric-tile">
        <span class="metric-label">Activas</span>
        <strong>{{ evolutionSummary.active_vulnerabilities }}</strong>
      </div>
      <div class="metric-tile">
        <span class="metric-label">Resueltas</span>
        <strong>{{ evolutionSummary.resolved_vulnerabilities }}</strong>
      </div>
      <div class="metric-tile">
        <span class="metric-label">Assets</span>
        <strong>{{ evolutionSummary.assets }}</strong>
      </div>
      <div class="metric-tile">
        <span class="metric-label">Eventos históricos</span>
        <strong>{{ evolutionSummary.detection_events }}</strong>
      </div>
      <div class="metric-tile metric-tile-wide">
        <span class="metric-label">Timestamp Wazuh (último sync)</span>
        <strong class="sync-ts-value">{{ evolutionSummary.last_sync_at ? timeAgo(evolutionSummary.last_sync_at) : 'Sin sincronizar' }}</strong>
        <span v-if="evolutionSummary.last_sync_at" class="metric-sub">{{ formatDate(evolutionSummary.last_sync_at) }}</span>
      </div>
    </div>

    <!-- Trazabilidad: Nuevas vs Persistentes vs Remediadas -->
    <div v-if="traceability" class="traceability-grid">
      <div class="trace-tile trace-new">
        <span class="trace-label">Nuevas (≤7 días)</span>
        <strong>{{ traceability.nuevas }}</strong>
        <span class="trace-sub">Detectadas recientemente</span>
      </div>
      <div class="trace-tile trace-persistent">
        <span class="trace-label">Persistentes</span>
        <strong>{{ traceability.persistentes }}</strong>
        <span class="trace-sub">Activas sin remediar</span>
      </div>
      <div class="trace-tile trace-resolved">
        <span class="trace-label">Remediadas</span>
        <strong>{{ traceability.remediadas }}</strong>
        <span class="trace-sub">Ya no reportadas</span>
      </div>
    </div>

    <!-- Gráficos de torta -->
    <div class="chart-grid">
      <section class="card chart-card">
        <div class="panel-head">
          <h2>Resueltas vs. activas</h2>
          <span>Estado actual</span>
        </div>
        <DonutChart
          :segments="statusSegments"
          :center-value="statusBreakdown?.total ?? 0"
          center-label="Amenazas"
          aria-label="Distribución de vulnerabilidades resueltas y activas"
        />
      </section>

      <section class="card chart-card">
        <div class="panel-head">
          <h2>Nuevas de {{ selectedYear }}</h2>
          <select v-model.number="selectedYear" class="mini-select" @change="fetchDashboardCharts">
            <option v-for="y in yearOptions" :key="y" :value="y">{{ y }}</option>
          </select>
        </div>
        <DonutChart
          :segments="newUnresolvedSegments"
          :center-value="`${newUnresolved?.pct_sin_corregir ?? 0}%`"
          center-label="Sin corregir"
          aria-label="Porcentaje de vulnerabilidades nuevas del año sin corregir"
        />
      </section>

      <section class="card chart-card">
        <div class="panel-head">
          <h2>Alcance crítico</h2>
          <span>Al menos 1 crítica</span>
        </div>
        <div class="coverage-pair">
          <DonutChart
            :segments="criticalAgentSegments"
            :center-value="`${criticalCoverage?.pct_agentes ?? 0}%`"
            center-label="Agentes"
            aria-label="Porcentaje de agentes con vulnerabilidades críticas"
          />
          <DonutChart
            :segments="criticalGroupSegments"
            :center-value="`${criticalCoverage?.pct_grupos ?? 0}%`"
            center-label="Grupos"
            aria-label="Porcentaje de grupos con vulnerabilidades críticas"
          />
        </div>
      </section>
    </div>

    <!-- Histograma + tendencia mensual -->
    <div class="evolution-panels">
      <section class="card evolution-card">
        <div class="panel-head">
          <h2>Agentes con vulnerabilidades críticas</h2>
          <span>Histograma</span>
        </div>
        <HistogramChart :items="criticalHistogramBars" empty-text="Ningún agente reporta vulnerabilidades críticas." />
      </section>

      <section class="card evolution-card">
        <div class="panel-head">
          <h2>Tendencia mensual</h2>
          <span>{{ trendPeriodLabel }}</span>
        </div>
        <div v-if="monthlyTrend.length" class="weekly-bars">
          <div v-for="point in monthlyTrend" :key="point.mes" class="bar-row">
            <span>{{ formatMonth(point.mes) }}</span>
            <div class="bar-track">
              <div class="bar-fill" :style="{ width: getMonthlyBarWidth(point.total_vulnerabilidades) + '%' }"></div>
            </div>
            <strong>{{ point.total_vulnerabilidades }}</strong>
          </div>
        </div>
        <p v-else class="panel-empty">Sin eventos históricos suficientes.</p>
      </section>
    </div>

    <div class="evolution-panels">
      <section class="card evolution-card">
        <div class="panel-head">
          <h2>Riesgo por grupo</h2>
          <span>Críticas activas</span>
        </div>
        <HistogramChart
          :items="groupRiskBars"
          default-color="#ea580c"
          empty-text="Sin grupos de agentes sincronizados."
        />
      </section>

      <section class="card evolution-card">
        <div class="panel-head">
          <h2>Top servidores</h2>
          <span>CVEs activos</span>
        </div>
        <div v-if="topAssets.length" class="top-assets-list">
          <div v-for="asset in topAssets" :key="asset.hostname" class="asset-row">
            <span>{{ asset.hostname }}</span>
            <strong>{{ asset.total }}</strong>
          </div>
        </div>
        <p v-else class="panel-empty">Sin actividad reciente.</p>
      </section>
    </div>

    <!-- Filter Toggle Bar (minimalista) -->
    <div v-if="totalItems > 0 || showFilters" class="filter-toggle-bar">
      <button class="btn-filter-toggle" @click="showFilters = !showFilters">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"></polygon>
        </svg>
        <span>{{ showFilters ? 'Ocultar filtros' : 'Filtros avanzados' }}</span>
      </button>
      <button v-if="showFilters" class="btn-clear-filters" @click="clearFilters">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M3 6h18"></path>
          <path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"></path>
          <path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"></path>
        </svg>
        <span>Limpiar</span>
      </button>
    </div>

    <!-- Dashboard Filters -->
    <div v-show="showFilters" class="card filter-panel">
      <div class="filter-row">
        <div class="f-group">
          <label>Conexión Wazuh</label>
          <select v-model="selectedConnection" @change="onConnectionChange" class="filter-input">
            <option value="">Todas las conexiones</option>
            <option v-for="conn in connections" :key="conn.id" :value="conn.id">{{ conn.name }}</option>
          </select>
        </div>

        <div class="f-group popover-wrap" v-click-outside="() => (dropdowns.agents = false)">
          <label>Agentes</label>
          <button class="filter-input dd-btn" @click="dropdowns.agents = !dropdowns.agents" :disabled="!agentOptions.length">
            <span>{{ selectedAgents.length ? selectedAgents.length + ' sel.' : 'Todos' }}</span>
            <span>▼</span>
          </button>
          <div v-if="dropdowns.agents" class="dd-panel fade-in">
            <input type="text" v-model="search.agent" placeholder="Buscar agente..." class="dd-search">
            <div class="dd-actions">
              <span @click="selectedAgents = [...agentOptions]">Todos</span>
              <span @click="selectedAgents = []">Limpiar</span>
            </div>
            <div class="dd-list custom-scroll">
              <label v-for="agent in filteredAgents" :key="agent" class="dd-item">
                <input type="checkbox" :value="agent" v-model="selectedAgents"> {{ agent }}
              </label>
            </div>
          </div>
        </div>

        <div class="f-group popover-wrap" v-click-outside="() => (dropdowns.groups = false)">
          <label>Grupos</label>
          <button class="filter-input dd-btn" @click="dropdowns.groups = !dropdowns.groups" :disabled="!groupOptions.length">
            <span>{{ selectedGroups.length ? selectedGroups.length + ' sel.' : 'Todos' }}</span>
            <span>▼</span>
          </button>
          <div v-if="dropdowns.groups" class="dd-panel fade-in">
            <input type="text" v-model="search.group" placeholder="Buscar grupo..." class="dd-search">
            <div class="dd-actions">
              <span @click="selectedGroups = groupOptions.map(g => g.name)">Todos</span>
              <span @click="selectedGroups = []">Limpiar</span>
            </div>
            <div class="dd-list custom-scroll">
              <label v-for="grp in filteredGroups" :key="grp.name" class="dd-item">
                <input type="checkbox" :value="grp.name" v-model="selectedGroups">
                <span class="dd-item-main">{{ grp.name }}</span>
                <span v-if="grp.assets != null" class="dd-item-meta">{{ grp.assets }} ag.</span>
              </label>
            </div>
          </div>
        </div>

        <div class="f-group popover-wrap" v-click-outside="() => (dropdowns.os = false)">
          <label>Sistema Operativo</label>
          <button class="filter-input dd-btn" @click="dropdowns.os = !dropdowns.os" :disabled="!osOptions.length">
            <span>{{ selectedOsPlatforms.length ? selectedOsPlatforms.length + ' sel.' : 'Todos' }}</span>
            <span>▼</span>
          </button>
          <div v-if="dropdowns.os" class="dd-panel fade-in">
            <div class="dd-actions">
              <span @click="selectedOsPlatforms = [...osPlatformOptions]">Todos</span>
              <span @click="selectedOsPlatforms = []">Limpiar</span>
            </div>
            <div class="dd-list custom-scroll">
              <label v-for="platform in osPlatformOptions" :key="platform" class="dd-item">
                <input type="checkbox" :value="platform" v-model="selectedOsPlatforms"> {{ platform }}
              </label>
            </div>
          </div>
        </div>

        <div class="f-group">
          <label>Estado</label>
          <select v-model="selectedStatus" class="filter-input">
            <option value="">Todas</option>
            <option value="no_resuelta">No resueltas</option>
            <option value="resuelta">Resueltas</option>
          </select>
        </div>

        <div class="f-group popover-wrap" v-click-outside="() => (dropdowns.vulns = false)">
          <label>CVE ID</label>
          <button class="filter-input dd-btn" @click="dropdowns.vulns = !dropdowns.vulns" :disabled="!vulnOptions.length">
            <span>{{ selectedVulns.length ? selectedVulns.length + ' sel.' : 'Todas' }}</span>
            <span>▼</span>
          </button>
          <div v-if="dropdowns.vulns" class="dd-panel fade-in">
            <input type="text" v-model="search.vuln" placeholder="Buscar CVE..." class="dd-search">
            <div class="dd-actions">
              <span @click="selectedVulns = [...vulnOptions]">Todas</span>
              <span @click="selectedVulns = []">Limpiar</span>
            </div>
            <div class="dd-list custom-scroll">
              <label v-for="vuln in filteredCVEOptions" :key="vuln" class="dd-item">
                <input type="checkbox" :value="vuln" v-model="selectedVulns"> {{ vuln }}
              </label>
            </div>
          </div>
        </div>

        <div class="f-group popover-wrap" v-click-outside="() => (dropdowns.packages = false)">
          <label>Software Afectado</label>
          <button class="filter-input dd-btn" @click="dropdowns.packages = !dropdowns.packages" :disabled="!packageOptions.length">
            <span>{{ selectedPackages.length ? selectedPackages.length + ' sel.' : 'Todos' }}</span>
            <span>▼</span>
          </button>
          <div v-if="dropdowns.packages" class="dd-panel fade-in">
            <input type="text" v-model="search.package" placeholder="Buscar software..." class="dd-search">
            <div class="dd-actions">
              <span @click="selectedPackages = [...packageOptions]">Todos</span>
              <span @click="selectedPackages = []">Limpiar</span>
            </div>
            <div class="dd-list custom-scroll">
              <label v-for="pkg in filteredPackages" :key="pkg" class="dd-item">
                <input type="checkbox" :value="pkg" v-model="selectedPackages"> {{ pkg }}
              </label>
            </div>
          </div>
        </div>

        <div class="f-group popover-wrap" v-click-outside="() => (dropdowns.severity = false)">
          <label>Severidad</label>
          <button class="filter-input dd-btn" @click="dropdowns.severity = !dropdowns.severity" :disabled="!severityOptions.length">
            <span>{{ selectedSeverities.length ? selectedSeverities.length + ' sel.' : 'Todas' }}</span>
            <span>▼</span>
          </button>
          <div v-if="dropdowns.severity" class="dd-panel fade-in">
            <div class="dd-actions">
              <span @click="selectedSeverities = [...severityOptions]">Todas</span>
              <span @click="selectedSeverities = []">Limpiar</span>
            </div>
            <div class="dd-list custom-scroll">
              <label v-for="sev in severityOptions" :key="sev" class="dd-item">
                <input type="checkbox" :value="sev" v-model="selectedSeverities"> 
                <span :class="'badge-mini ' + getSeverityBadgeClass(sev)">{{ sev }}</span>
              </label>
            </div>
          </div>
        </div>

        <div class="f-group">
          <label>Score CVSS (Base)</label>
          <div class="range-inputs">
            <input type="number" v-model.number="scoreMin" min="0" max="10" step="0.1" placeholder="Min" class="filter-input-sm">
            <span>-</span>
            <input type="number" v-model.number="scoreMax" min="0" max="10" step="0.1" placeholder="Max" class="filter-input-sm">
          </div>
        </div>
      </div>
    </div>

    <div v-if="loading" class="empty-state">
      <div class="spinner-box">
        <svg class="spin" xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="2" x2="12" y2="6"></line><line x1="12" y1="18" x2="12" y2="22"></line><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"></line><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"></line><line x1="2" y1="12" x2="6" y2="12"></line><line x1="18" y1="12" x2="22" y2="12"></line><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"></line><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"></line></svg>
      </div>
      <p>Cargando datos del cluster...</p>
    </div>

    <!-- Table -->
    <div v-else class="card" style="padding: 0;">
      <div class="table-wrapper">
        <div v-if="totalPages > 1" class="pagination-header">
          <span class="pagination-info">
            Mostrando {{ (currentPage - 1) * itemsPerPage + 1 }} - {{ Math.min(currentPage * itemsPerPage, totalItems) }} de {{ totalItems }} vulnerabilidades
          </span>
          <div class="pagination-nav">
            <button class="btn-icon-page" :disabled="currentPage === 1" @click="jumpBackward" title="Retroceder 5 páginas" aria-label="Retroceder 5 páginas">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><polyline points="13 17 8 12 13 7"></polyline><polyline points="19 17 14 12 19 7"></polyline></svg>
            </button>
            <button class="btn-icon-page" :disabled="currentPage === 1" @click="prevPage" title="Anterior">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"></polyline></svg>
            </button>
            <div class="page-numbers">
              <template v-for="(item, idx) in visiblePages" :key="`top-${item}-${idx}`">
                <button
                  v-if="typeof item === 'number'"
                  class="btn-page"
                  :class="{ 'active': currentPage === item }"
                  @click="currentPage = item"
                >
                  {{ item }}
                </button>
                <span v-else class="pagination-ellipsis">...</span>
              </template>
            </div>
            <button class="btn-icon-page" :disabled="currentPage === totalPages" @click="nextPage" title="Siguiente">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg>
            </button>
            <button class="btn-icon-page" :disabled="currentPage === totalPages" @click="jumpForward" title="Avanzar 5 páginas" aria-label="Avanzar 5 páginas">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><polyline points="11 17 16 12 11 7"></polyline><polyline points="5 17 10 12 5 7"></polyline></svg>
            </button>
          </div>
        </div>

        <table v-if="vulns.length > 0" class="vuln-table">
          <caption class="visually-hidden">
            Tabla de vulnerabilidades con severidad, CVE, agente, software afectado y linea de tiempo de actividad.
          </caption>
          <thead>
            <tr>
              <th style="width: 10%;" @click="sortBy('connection_name')">
                Conexión Wazuh
                <span v-if="sortKey === 'connection_name'" class="sort-indicator">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="4" :class="sortOrder === 'asc' ? '' : 'rotate-180'">
                    <path d="M7 14l5-5 5 5z"/>
                  </svg>
                </span>
              </th>
              <th style="width: 12%;" @click="sortBy('severity')">
                Severidad
                <span v-if="sortKey === 'severity'" class="sort-indicator">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="4" :class="sortOrder === 'asc' ? '' : 'rotate-180'">
                    <path d="M7 14l5-5 5 5z"/>
                  </svg>
                </span>
              </th>
              <th style="width: 8%;" @click="sortBy('score_base')">
                Score CVSS
                <span v-if="sortKey === 'score_base'" class="sort-indicator">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="4" :class="sortOrder === 'asc' ? '' : 'rotate-180'">
                    <path d="M7 14l5-5 5 5z"/>
                  </svg>
                </span>
              </th>
              <th class="col-cve" @click="sortBy('cve_id')">
                CVE ID
                <span v-if="sortKey === 'cve_id'" class="sort-indicator">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="4" :class="sortOrder === 'asc' ? '' : 'rotate-180'">
                    <path d="M7 14l5-5 5 5z"/>
                  </svg>
                </span>
              </th>
              <th class="col-agent" @click="sortBy('agent_name')">
                Agente
                <span v-if="sortKey === 'agent_name'" class="sort-indicator">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="4" :class="sortOrder === 'asc' ? '' : 'rotate-180'">
                    <path d="M7 14l5-5 5 5z"/>
                  </svg>
                </span>
              </th>
              <th class="col-package" @click="sortBy('package_name')">
                Software Afectado
                <span v-if="sortKey === 'package_name'" class="sort-indicator">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="4" :class="sortOrder === 'asc' ? '' : 'rotate-180'">
                    <path d="M7 14l5-5 5 5z"/>
                  </svg>
                </span>
              </th>
              <th class="col-timeline" @click="sortBy('last_seen')">
                Línea de Tiempo
                <span v-if="sortKey === 'last_seen'" class="sort-indicator">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="4" :class="sortOrder === 'asc' ? '' : 'rotate-180'">
                    <path d="M7 14l5-5 5 5z"/>
                  </svg>
                </span>
              </th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="vuln in vulns" :key="vuln.id">
              <td>{{ vuln.connection_name || '-' }}</td>
              <td>
                <span :class="getSeverityClass(vuln.severity)">
                  {{ (vuln.severity || 'UNKNOWN').toUpperCase() }}
                </span>
              </td>
              <td class="font-medium score-cell">
                {{ vuln.score_base != null ? vuln.score_base.toFixed(1) : 'N/A' }}
              </td>
              <td class="font-medium text-black">{{ vuln.cve_id || 'N/A' }}</td>
              <td>
                <div class="agent-info">
                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2" ry="2"></rect><rect x="9" y="9" width="6" height="6"></rect><line x1="9" y1="1" x2="9" y2="4"></line><line x1="15" y1="1" x2="15" y2="4"></line><line x1="9" y1="20" x2="9" y2="23"></line><line x1="15" y1="20" x2="15" y2="23"></line><line x1="20" y1="9" x2="23" y2="9"></line><line x1="20" y1="14" x2="23" y2="14"></line><line x1="1" y1="9" x2="4" y2="9"></line><line x1="1" y1="14" x2="4" y2="14"></line></svg>
                  <span>{{ vuln.agent_name || vuln.agent_id || 'N/A' }}</span>
                </div>
              </td>
              <td>
                <div class="package-info">
                  <span class="pkg-name">{{ vuln.package_name }}</span>
                  <span class="pkg-version">v{{ vuln.package_version }}</span>
                </div>
              </td>
              <td>
                <div class="visual-timeline">
                  <!-- Punto de Detección -->
                  <div class="timeline-point start">
                    <div class="point-marker">
                      <svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                    </div>
                    <div class="point-content">
                      <span class="point-title">Detectado</span>
                      <span class="point-time" :title="formatDate(vuln.first_seen)">{{ timeAgo(vuln.first_seen) }}</span>
                    </div>
                  </div>

                  <!-- Línea Conectora: verde cuando la amenaza ya fue resuelta -->
                  <div class="timeline-track" :class="{ resolved: isResolved(vuln) }">
                    <div class="track-progress" :style="{ width: getTimelineProgress(vuln) + '%' }"></div>
                  </div>

                  <!-- Punto de cierre / última vista -->
                  <div class="timeline-point end" :class="{ resolved: isResolved(vuln) }">
                    <div class="point-marker" :class="{ 'pulse-radar': !isResolved(vuln) && isRecentlySeen(vuln.last_seen) }">
                      <svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                    </div>
                    <div class="point-content">
                      <span class="point-title">{{ isResolved(vuln) ? 'Resuelta' : 'Última actividad' }}</span>
                      <span class="point-time" :title="formatDate(vuln.resolved_at || vuln.last_seen)">
                        {{ timeAgo(vuln.resolved_at || vuln.last_seen) }}
                      </span>
                    </div>
                  </div>
                </div>
              </td>
            </tr>
          </tbody>
        </table>

        <!-- Controles de Paginación Abajo -->
        <div v-if="totalPages > 1" class="pagination-controls-bottom">
          <div class="pagination-nav" style="margin-left: auto;">
            <button class="btn-icon-page" :disabled="currentPage === 1" @click="jumpBackward" title="Retroceder 5 páginas" aria-label="Retroceder 5 páginas">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><polyline points="13 17 8 12 13 7"></polyline><polyline points="19 17 14 12 19 7"></polyline></svg>
            </button>
            <button class="btn-icon-page" :disabled="currentPage === 1" @click="prevPage" title="Anterior">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"></polyline></svg>
            </button>
            <div class="page-numbers">
              <template v-for="(item, idx) in visiblePages" :key="`bottom-${item}-${idx}`">
                <button
                  v-if="typeof item === 'number'"
                  class="btn-page"
                  :class="{ 'active': currentPage === item }"
                  @click="currentPage = item"
                >
                  {{ item }}
                </button>
                <span v-else class="pagination-ellipsis">...</span>
              </template>
            </div>
            <button class="btn-icon-page" :disabled="currentPage === totalPages" @click="nextPage" title="Siguiente">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg>
            </button>
            <button class="btn-icon-page" :disabled="currentPage === totalPages" @click="jumpForward" title="Avanzar 5 páginas" aria-label="Avanzar 5 páginas">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><polyline points="11 17 16 12 11 7"></polyline><polyline points="5 17 10 12 5 7"></polyline></svg>
            </button>
          </div>
        </div>

        <div v-if="vulns.length === 0 && !loading" class="empty-state" style="padding: 4rem 2rem;">
          <div class="shield-box">
             <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--success)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="M9 12l2 2 4-4"></path></svg>
          </div>
          <p style="color: var(--text-main); font-weight: 500; font-size: 1.1rem; margin-bottom: 0.5rem;">No hay conexiones activas</p>
          <p style="color: var(--text-muted); font-size: 0.9rem;">El sistema no reporta conexiones activas actualmente.</p>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, computed, watch, reactive } from 'vue'
import vulnService from '../../application/services/vulnService'
import wazuhService from '../../application/services/wazuhService'
import { useSyncJob } from '../composables/useSyncJob'
import DonutChart from '../components/charts/DonutChart.vue'
import HistogramChart from '../components/charts/HistogramChart.vue'

const vulns = ref([])          // Solo la página actual (server-side)
const totalItems = ref(0)
const loading = ref(true)
const error = ref('')
const evolutionSummary = ref(null)
const traceability = ref(null)
const monthlyTrend = ref([])
const topAssets = ref([])
const sortKey = ref('last_seen')
const sortOrder = ref('desc')
const showFilters = ref(false)

// Datos de los gráficos del dashboard
const statusBreakdown = ref(null)
const newUnresolved = ref(null)
const criticalCoverage = ref(null)
const criticalHistogram = ref([])
const groupRisk = ref([])

const currentYear = new Date().getFullYear()
const selectedYear = ref(currentYear)
const yearOptions = computed(() => [0, 1, 2, 3].map(offset => currentYear - offset))
const trendPeriodLabel = 'Últimos 12 meses'

// Sincronización en segundo plano + progreso + toast
const { isSyncing, progressPct, phaseLabel, startSync, resumeIfActive, onDone } = useSyncJob()

// Paginación (server-side)
const currentPage = ref(1)
const itemsPerPage = 50
const pageJump = 10

// Filter state
const connections = ref([])
const agentOptions = ref([])
const vulnOptions = ref([])
const packageOptions = ref([])
const severityOptions = ref([])
const groupOptions = ref([])
const osOptions = ref([])

const selectedConnection = ref('')
const selectedAgents = ref([])
const selectedVulns = ref([])
const selectedPackages = ref([])
const selectedSeverities = ref([])
const selectedGroups = ref([])
const selectedOsPlatforms = ref([])
const selectedStatus = ref('')
const scoreMin = ref('')
const scoreMax = ref('')

// Dropdown state
const search = reactive({ agent: '', vuln: '', package: '', group: '' })
const dropdowns = reactive({
  agents: false, vulns: false, packages: false, severity: false,
  groups: false, os: false,
})

const osPlatformOptions = computed(() =>
  [...new Set(osOptions.value.map(os => os.platform).filter(Boolean))].sort()
)

const filteredGroups = computed(() =>
  groupOptions.value.filter(grp =>
    (grp.name || '').toLowerCase().includes(search.group.toLowerCase())
  )
)

// Filtered lists for search (búsqueda dentro del dropdown, sobre opciones precargadas)
const filteredAgents = computed(() =>
  agentOptions.value.filter(agent => agent.toLowerCase().includes(search.agent.toLowerCase()))
)

const filteredCVEOptions = computed(() =>
  vulnOptions.value.filter(vuln => vuln.toLowerCase().includes(search.vuln.toLowerCase()))
)

const filteredPackages = computed(() =>
  packageOptions.value.filter(pkg => pkg.toLowerCase().includes(search.package.toLowerCase()))
)

const maxMonthlyTotal = computed(() =>
  monthlyTrend.value.reduce((max, point) => Math.max(max, point.total_vulnerabilidades || 0), 0)
)

// === SEGMENTOS DE LOS GRÁFICOS ===
const statusSegments = computed(() => [
  { label: 'Activas', value: statusBreakdown.value?.activas ?? 0, color: '#dc2626' },
  { label: 'Resueltas', value: statusBreakdown.value?.resueltas ?? 0, color: '#16a34a' },
])

const newUnresolvedSegments = computed(() => [
  { label: 'Sin corregir', value: newUnresolved.value?.sin_corregir ?? 0, color: '#d97706' },
  { label: 'Corregidas', value: newUnresolved.value?.corregidas ?? 0, color: '#16a34a' },
])

const criticalAgentSegments = computed(() => {
  const total = criticalCoverage.value?.total_agentes ?? 0
  const criticos = criticalCoverage.value?.agentes_criticos ?? 0
  return [
    { label: 'Con críticas', value: criticos, color: '#dc2626' },
    { label: 'Sin críticas', value: Math.max(0, total - criticos), color: '#16a34a' },
  ]
})

const criticalGroupSegments = computed(() => {
  const total = criticalCoverage.value?.total_grupos ?? 0
  const criticos = criticalCoverage.value?.grupos_criticos ?? 0
  return [
    { label: 'Con críticas', value: criticos, color: '#ea580c' },
    { label: 'Sin críticas', value: Math.max(0, total - criticos), color: '#16a34a' },
  ]
})

const criticalHistogramBars = computed(() =>
  criticalHistogram.value.map(row => ({
    key: row.asset_id ?? row.hostname,
    label: row.hostname,
    value: row.criticas,
    tooltip: row.grupos ? `${row.hostname} · ${row.grupos}` : row.hostname,
  }))
)

const groupRiskBars = computed(() =>
  groupRisk.value.map(row => ({
    key: row.group_id ?? row.name,
    label: row.name,
    value: row.criticas,
    tooltip: `${row.name}: ${row.agentes_criticos}/${row.agentes} agentes con críticas`,
  }))
)

const getSeverityLevel = (s) => {
  if (!s) return 0
  const severity = s.toLowerCase()
  if (severity === 'critical' || severity === 'critica') return 4
  if (severity === 'high' || severity === 'alta') return 3
  if (severity === 'medium' || severity === 'media') return 2
  return 1 // low or unknown
}

// === PAGINACIÓN SERVER-SIDE ===
const totalPages = computed(() => Math.max(1, Math.ceil(totalItems.value / itemsPerPage)))

const visiblePages = computed(() => {
  const pages = []
  const total = totalPages.value
  const current = currentPage.value
  const maxNumericButtons = 7

  if (total <= maxNumericButtons) {
    for (let i = 1; i <= total; i++) pages.push(i)
    return pages
  }

  const middleSlots = maxNumericButtons - 2
  pages.push(1)

  let start = Math.max(2, current - Math.floor(middleSlots / 2))
  let end = start + middleSlots - 1

  if (end > total - 1) {
    end = total - 1
    start = end - middleSlots + 1
  }

  if (start > 2) pages.push('left-ellipsis')
  for (let i = start; i <= end; i++) pages.push(i)
  if (end < total - 1) pages.push('right-ellipsis')

  pages.push(total)
  return pages
})

const nextPage = () => { if (currentPage.value < totalPages.value) currentPage.value++ }
const prevPage = () => { if (currentPage.value > 1) currentPage.value-- }
const jumpBackward = () => { currentPage.value = Math.max(1, currentPage.value - pageJump) }
const jumpForward = () => { currentPage.value = Math.min(totalPages.value, currentPage.value + pageJump) }

// === FETCH SERVER-SIDE ===
const buildParams = () => ({
  page: currentPage.value,
  pageSize: itemsPerPage,
  connectionId: selectedConnection.value || null,
  agents: selectedAgents.value,
  groups: selectedGroups.value,
  cves: selectedVulns.value,
  packages: selectedPackages.value,
  severities: selectedSeverities.value,
  osPlatforms: selectedOsPlatforms.value,
  status: selectedStatus.value || null,
  scoreMin: scoreMin.value,
  scoreMax: scoreMax.value,
  sortBy: sortKey.value || 'last_seen',
  sortOrder: sortOrder.value || 'desc',
})

const fetchVulns = async () => {
  loading.value = true
  error.value = ''
  try {
    const res = await vulnService.getVulns(buildParams())
    const data = res.data || {}
    vulns.value = Array.isArray(data.items) ? data.items : []
    totalItems.value = data.total || 0
  } catch (err) {
    console.error('Error fetching vulns:', err)
    error.value = 'No se pudieron cargar las vulnerabilidades.'
    vulns.value = []
    totalItems.value = 0
  } finally {
    loading.value = false
  }
}

// Debounce para filtros (evita disparar una petición por cada tecla/clic)
let filterTimer = null
const refetchFromFilters = () => {
  currentPage.value = 1
  clearTimeout(filterTimer)
  filterTimer = setTimeout(fetchVulns, 300)
}

// Recargar al cambiar página o el orden (inmediato)
watch(currentPage, fetchVulns)
watch([sortKey, sortOrder], () => { currentPage.value = 1; fetchVulns() })

// Recargar (con debounce) al cambiar filtros
watch(
  [selectedAgents, selectedVulns, selectedPackages, selectedSeverities,
   selectedGroups, selectedOsPlatforms, selectedStatus, scoreMin, scoreMax],
  refetchFromFilters,
  { deep: true }
)

const sortBy = (key) => {
  if (sortKey.value !== key) {
    sortKey.value = key
    sortOrder.value = 'asc'
  } else if (sortOrder.value === 'asc') {
    sortOrder.value = 'desc'
  } else {
    sortKey.value = 'last_seen'
    sortOrder.value = 'desc'
  }
}

const fetchFilterOptions = async () => {
  try {
    const res = await vulnService.getFilterOptions(selectedConnection.value || null)
    const data = res.data || {}
    agentOptions.value = data.agents || []
    vulnOptions.value = data.cves || []
    packageOptions.value = data.packages || []
    groupOptions.value = data.groups || []
    osOptions.value = data.operating_systems || []
    severityOptions.value = (data.severities || []).sort(
      (a, b) => getSeverityLevel(b.toLowerCase()) - getSeverityLevel(a.toLowerCase())
    )
  } catch (err) {
    console.error('Error fetching filter options:', err)
  }
}

const resetFilterSelections = () => {
  selectedAgents.value = []
  selectedVulns.value = []
  selectedPackages.value = []
  selectedSeverities.value = []
  selectedGroups.value = []
  selectedOsPlatforms.value = []
  selectedStatus.value = ''
  scoreMin.value = ''
  scoreMax.value = ''
  currentPage.value = 1
}

const onConnectionChange = () => {
  resetFilterSelections()
  fetchFilterOptions()
  fetchVulns()
  fetchEvolution()
  fetchDashboardCharts()
}

const clearFilters = () => {
  selectedConnection.value = ''
  resetFilterSelections()
  fetchFilterOptions()
  fetchVulns()
}

const fetchConnections = async () => {
  try {
    const res = await wazuhService.getConnections()
    connections.value = res?.data || []
  } catch (err) {
    console.error('Error fetching connections:', err)
    connections.value = []
  }
}

const evolutionParams = () => {
  return selectedConnection.value ? { connection_id: selectedConnection.value } : {}
}

const fetchEvolution = async () => {
  try {
    const params = evolutionParams()
    const [summaryRes, monthlyRes, topRes, traceRes] = await Promise.all([
      vulnService.getEvolutionSummary(params),
      vulnService.getMonthlyTrend({ ...params, period: '12m' }),
      vulnService.getTopAssets({ ...params, limit: 5 }),
      vulnService.getTraceabilitySummary(params),
    ])

    evolutionSummary.value = summaryRes?.data || null
    monthlyTrend.value = Array.isArray(monthlyRes?.data) ? monthlyRes.data : []
    topAssets.value = Array.isArray(topRes?.data) ? topRes.data : []
    traceability.value = traceRes?.data || null
  } catch (err) {
    console.error('Error fetching evolution metrics:', err)
  }
}

const fetchDashboardCharts = async () => {
  try {
    const params = evolutionParams()
    const [statusRes, newRes, coverageRes, histogramRes, groupRes] = await Promise.all([
      vulnService.getStatusBreakdown(params),
      vulnService.getNewUnresolved({ ...params, year: selectedYear.value }),
      vulnService.getCriticalCoverage(params),
      vulnService.getCriticalHistogram({ ...params, limit: 15 }),
      vulnService.getGroupRisk({ ...params, limit: 10 }),
    ])

    statusBreakdown.value = statusRes?.data || null
    newUnresolved.value = newRes?.data || null
    criticalCoverage.value = coverageRes?.data || null
    criticalHistogram.value = Array.isArray(histogramRes?.data) ? histogramRes.data : []
    groupRisk.value = Array.isArray(groupRes?.data) ? groupRes.data : []
  } catch (err) {
    console.error('Error fetching dashboard charts:', err)
  }
}

const onSyncClick = () => {
  startSync()
}

const formatDate = (dateString) => {
  if (!dateString) return 'N/A'
  const d = new Date(dateString)
  return d.toLocaleDateString('es-ES', { 
    day: '2-digit', month: 'short', year: 'numeric', 
    hour: '2-digit', minute: '2-digit' 
  })
}

const formatMonth = (dateString) => {
  if (!dateString) return '-'
  const d = new Date(dateString)
  return d.toLocaleDateString('es-ES', { month: 'short', year: '2-digit' })
}

const getMonthlyBarWidth = (value) => {
  if (!maxMonthlyTotal.value) return 0
  return Math.max(8, Math.round((value / maxMonthlyTotal.value) * 100))
}

const isNew = (firstSeenDate) => {
  if (!firstSeenDate) return false
  const now = new Date()
  const firstSeen = new Date(firstSeenDate)
  const diffTime = Math.abs(now - firstSeen)
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24))
  return diffDays <= 1
}

const getSeverityClass = (severity) => {
  if (!severity) return 'badge badge-low'
  const s = severity.toLowerCase()
  if (['critical', 'high', 'alta', 'critica'].includes(s)) return 'badge badge-critical'
  if (['medium', 'media'].includes(s)) return 'badge badge-medium'
  return 'badge badge-low'
}

const getSeverityBadgeClass = (severity) => {
  const s = severity.toLowerCase()
  if (['critical', 'critica'].includes(s)) return 'badge-critical'
  if (['high', 'alta'].includes(s)) return 'badge-high'
  if (['medium', 'media'].includes(s)) return 'badge-medium'
  return 'badge-low'
}

const isResolved = (vuln) => vuln?.status === 'RESOLVED'

const isRecentlySeen = (lastSeenDate) => {
  if (!lastSeenDate) return false
  const now = new Date()
  const lastSeen = new Date(lastSeenDate)
  const diffMinutes = Math.floor((now - lastSeen) / (1000 * 60))
  return diffMinutes <= 60 // Visto en la última hora
}

const getTimelineProgress = (vuln) => {
  if (!vuln.first_seen || !vuln.last_seen) return 0
  const first = new Date(vuln.first_seen).getTime()
  const last = new Date(vuln.last_seen).getTime()
  const now = new Date().getTime()
  
  if (last === first) return 0
  
  const totalDuration = now - first
  const activeDuration = last - first
  
  // Porcentaje de tiempo que ha estado activa respecto a su edad total
  return Math.min(100, Math.max(5, (activeDuration / totalDuration) * 100))
}

const timeAgo = (date) => {
  if (!date) return 'N/A'
  const seconds = Math.floor((new Date() - new Date(date)) / 1000)
  
  let interval = seconds / 31536000
  if (interval > 1) return `Hace ${Math.floor(interval)} años`
  
  interval = seconds / 2592000
  if (interval > 1) return `Hace ${Math.floor(interval)} meses`
  
  interval = seconds / 86400
  if (interval > 1) return `Hace ${Math.floor(interval)} días`
  
  interval = seconds / 3600
  if (interval > 1) return `Hace ${Math.floor(interval)} horas`
  
  interval = seconds / 60
  if (interval > 1) return `Hace ${Math.floor(interval)} min`
  
  return 'Justo ahora'
}

onMounted(() => {
  fetchConnections()
  fetchFilterOptions()
  fetchVulns()
  fetchEvolution()
  fetchDashboardCharts()

  // Reanuda la barra de progreso si ya había una sync en curso
  resumeIfActive()

  // Cuando termina una sincronización en segundo plano, refresca los datos
  onDone(() => {
    fetchFilterOptions()
    fetchVulns()
    fetchEvolution()
    fetchDashboardCharts()
  })
})
</script>

<style scoped>
.header-right {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.sync-badge {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  font-size: 0.78rem;
  color: var(--text-muted);
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 0.35rem 0.7rem;
}

.sync-badge strong {
  color: var(--text-main);
}

.sync-date-full {
  color: var(--text-muted);
  font-size: 0.72rem;
  opacity: 0.75;
}

.evolution-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr)) minmax(180px, auto);
  gap: 1rem;
  margin-bottom: 1rem;
}

.metric-tile-wide {
  border-left: 3px solid var(--primary);
}

.sync-ts-value {
  font-size: 1.2rem !important;
}

.metric-sub {
  display: block;
  font-size: 0.72rem;
  color: var(--text-muted);
  margin-top: 0.2rem;
}

.metric-tile {
  border: 1px solid var(--border);
  background: var(--bg-panel);
  border-radius: var(--radius);
  padding: 1rem;
}

.metric-label {
  display: block;
  color: var(--text-muted);
  font-size: 0.78rem;
  font-weight: 700;
  text-transform: uppercase;
  margin-bottom: 0.45rem;
}

.metric-tile strong {
  color: var(--text-main);
  font-size: 1.6rem;
  line-height: 1;
}

.evolution-panels {
  display: grid;
  grid-template-columns: minmax(0, 1.35fr) minmax(280px, 0.65fr);
  gap: 1rem;
  margin-bottom: 1rem;
}

/* Rejilla de gráficos de torta */
.chart-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 1rem;
  margin-bottom: 1rem;
}

.chart-card {
  min-height: 210px;
}

.coverage-pair {
  display: flex;
  gap: 0.75rem;
  flex-wrap: wrap;
}

.coverage-pair :deep(.donut-chart) {
  flex: 1 1 140px;
  gap: 0.6rem;
}

.coverage-pair :deep(.donut-svg) {
  width: 108px;
  height: 108px;
}

.mini-select {
  padding: 0.25rem 0.5rem;
  border: 1px solid var(--border);
  background: var(--bg-dark);
  border-radius: var(--radius-sm);
  color: var(--text-main);
  font-size: 0.78rem;
  font-weight: 700;
  cursor: pointer;
}

.dd-item-main {
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.dd-item-meta {
  color: var(--text-muted);
  font-size: 0.7rem;
}

.evolution-card {
  min-height: 180px;
}

.panel-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  margin-bottom: 1rem;
}

.panel-head h2 {
  margin: 0;
  font-size: 1rem;
  color: var(--text-main);
}

.panel-head span {
  color: var(--text-muted);
  font-size: 0.78rem;
  font-weight: 700;
  text-transform: uppercase;
}

.weekly-bars {
  display: flex;
  flex-direction: column;
  gap: 0.65rem;
}

.bar-row {
  display: grid;
  grid-template-columns: 72px minmax(0, 1fr) 42px;
  gap: 0.75rem;
  align-items: center;
  color: var(--text-muted);
  font-size: 0.85rem;
}

.bar-track {
  height: 9px;
  border-radius: 999px;
  background: var(--bg-hover);
  overflow: hidden;
}

.bar-fill {
  height: 100%;
  border-radius: 999px;
  background: var(--primary);
}

.bar-row strong,
.asset-row strong {
  color: var(--text-main);
  text-align: right;
}

.top-assets-list {
  display: flex;
  flex-direction: column;
  gap: 0.55rem;
}

.asset-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 42px;
  gap: 0.75rem;
  align-items: center;
  color: var(--text-muted);
  font-size: 0.9rem;
  padding-bottom: 0.55rem;
  border-bottom: 1px solid var(--border);
}

.asset-row span {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.panel-empty {
  color: var(--text-muted);
  margin: 0;
}

.visual-timeline {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  padding: 0.5rem 0;
  min-width: 180px;
}

.timeline-point {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.point-marker {
  width: 22px;
  height: 22px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.start .point-marker {
  background-color: #f3f4f6;
  color: #6b7280;
  border: 1px solid #e5e7eb;
}

.end .point-marker {
  background-color: rgba(59, 130, 246, 0.1);
  color: #3b82f6;
  border: 1px solid rgba(59, 130, 246, 0.2);
}

/* Amenaza resuelta: el tramo cerrado se marca en verde */
.end.resolved .point-marker {
  background-color: rgba(22, 163, 74, 0.12);
  color: #16a34a;
  border-color: rgba(22, 163, 74, 0.28);
}

.timeline-track.resolved {
  background-color: rgba(22, 163, 74, 0.18);
}

.timeline-track.resolved .track-progress {
  background-color: #16a34a;
}

.point-content {
  display: flex;
  flex-direction: column;
  line-height: 1.2;
}

.point-title {
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.025em;
  color: #9ca3af;
  font-weight: 600;
}

.point-time {
  font-size: 0.85rem;
  color: var(--text-main);
  font-weight: 500;
}

.timeline-track {
  background-color: #f3f4f6;
  border-radius: 2px;
  margin-left: 10px;
  width: 2px; /* Vertical track look */
  height: 12px;
  position: relative;
}

.track-progress {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  background-color: #3b82f6;
  border-radius: 2px;
}

/* Radar pulse for active items */
.pulse-radar {
  position: relative;
}

.pulse-radar::after {
  content: '';
  position: absolute;
  width: 100%;
  height: 100%;
  border-radius: 50%;
  background-color: #3b82f6;
  opacity: 0.4;
  animation: radar-pulse 2s infinite;
}

@keyframes radar-pulse {
  0% { transform: scale(1); opacity: 0.4; }
  100% { transform: scale(2.5); opacity: 0; }
}
.header-actions {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 1.5rem;
}

th {
  cursor: pointer;
}

.sort-indicator {
  margin-left: 0.5rem;
  display: inline-block;
  transition: transform 0.2s ease;
}

.vuln-table .col-severity { width: 12%; }
.vuln-table .col-cve { width: 15%; }
.vuln-table .col-agent { width: 15%; }
.vuln-table .col-package { width: 28%; }
.vuln-table .col-timeline { width: 20%; }

.visually-hidden {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}

.rotate-180 {
  transform: rotate(180deg);
}

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  padding: 3rem;
  color: var(--text-muted);
}

.spinner-box {
  margin-bottom: 1rem;
}

.shield-box {
  width: 80px;
  height: 80px;
  background-color: var(--success-bg);
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  margin: 0 auto 1.5rem;
  border: 4px solid rgba(16, 185, 129, 0.1);
}

.font-medium {
  font-weight: 500;
}
.text-black {
  color: var(--text-main);
  font-weight: 400;
}

.agent-info {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  color: var(--text-muted);
}

.package-info {
  display: flex;
  flex-direction: column;
}

.pkg-name {
  color: var(--text-main);
  font-weight: 500;
}

.pkg-version {
  color: var(--text-muted);
  font-size: 0.8rem;
}

.timeline-info {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  font-size: 0.8rem;
  color: var(--text-muted);
}

.timeline-row {
  display: flex;
  justify-content: space-between;
  gap: 1rem;
}

.timeline-label {
  color: #6b7280;
}

.pulse-dot {
  display: inline-block;
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background-color: var(--primary);
  margin-right: 0.35rem;
  box-shadow: 0 0 0 0 rgba(135, 197, 62, 0.7);
  animation: pulse 1.5s infinite;
}

@keyframes pulse {
  0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(135, 197, 62, 0.7); }
  70% { transform: scale(1); box-shadow: 0 0 0 6px rgba(135, 197, 62, 0); }
  100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(135, 197, 62, 0); }
}

.alert {
  padding: 1rem;
  border-radius: var(--radius-sm);
  margin-bottom: 1.5rem;
  font-size: 0.9rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-weight: 500;
}
.alert-danger {
  color: var(--danger);
  background-color: var(--danger-bg);
  border: 1px solid rgba(239, 68, 68, 0.3);
}

/* PAGINACION */
.pagination-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1rem 1.5rem;
  border-bottom: 1px solid var(--border);
  background-color: var(--bg-panel);
}

.pagination-info {
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--text-muted);
}

.pagination-controls-bottom {
  display: flex;
  justify-content: flex-end;
  align-items: center;
  padding: 1rem 1.5rem;
  border-top: 1px solid var(--border);
  background-color: var(--bg-card);
}

.pagination-nav {
  display: flex;
  align-items: center;
  gap: 0.35rem;
}

.page-numbers {
  display: flex;
  gap: 0.2rem;
}

.btn-icon-page {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  background: transparent;
  border: 1px solid var(--border);
  color: var(--text-main);
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-icon-page:hover:not(:disabled) {
  background-color: var(--bg-hover);
  border-color: var(--text-muted);
}

.btn-icon-page:disabled {
  opacity: 0.3;
  cursor: not-allowed;
  border-color: transparent;
}

.btn-page {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 28px;
  height: 28px;
  padding: 0 0.25rem;
  border: 1px solid transparent;
  background: transparent;
  color: var(--text-muted);
  border-radius: 6px;
  font-size: 0.8rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-page:hover:not(.active) {
  background-color: var(--bg-hover);
  color: var(--text-main);
}

.btn-page.active {
  background-color: var(--primary);
  color: #000;
}

.filter-toggle-bar {
  display: flex;
  justify-content: flex-end;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 0;
  margin-bottom: 0.5rem;
}

.btn-filter-toggle {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 0.85rem;
  background: transparent;
  border: 1px solid var(--border);
  color: var(--text-muted);
  border-radius: 6px;
  font-size: 0.85rem;
  cursor: pointer;
  transition: all 0.2s;
  font-weight: 500;
}

.btn-filter-toggle:hover {
  background-color: var(--bg-hover);
  border-color: var(--text-muted);
  color: var(--text-main);
}

.btn-filter-toggle svg {
  width: 16px;
  height: 16px;
}

.btn-clear-filters {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 0.85rem;
  background: transparent;
  border: 1px solid var(--border);
  color: var(--text-muted);
  border-radius: 6px;
  font-size: 0.85rem;
  cursor: pointer;
  transition: all 0.2s;
  font-weight: 500;
}

.btn-clear-filters:hover {
  background-color: var(--bg-hover);
  border-color: var(--danger);
  color: var(--danger);
}

.btn-clear-filters svg {
  width: 16px;
  height: 16px;
}

.pagination-ellipsis {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 20px;
  color: var(--text-muted);
  font-size: 0.8rem;
  font-weight: 600;
}

/* FILTER PANEL STYLES */
.filter-panel { 
  padding: 0; 
  margin-bottom: 1.5rem; 
  overflow: visible; 
}

.filter-row { 
  display: grid; 
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); 
  align-items: center; 
}

.f-group { 
  display: flex; 
  flex-direction: column; 
  padding: 1rem 1.2rem; 
  border-right: 1px solid var(--border); 
}

.f-group:last-child { 
  border-right: none; 
}

.f-group label { 
  font-size: 0.7rem; 
  font-weight: 700; 
  color: var(--text-muted); 
  text-transform: uppercase; 
  margin-bottom: 0.5rem; 
}

.filter-input, .dd-btn { 
  width: 100%; 
  padding: 0.55rem 0.8rem; 
  border: 1px solid var(--border); 
  background: var(--bg-dark); 
  border-radius: var(--radius-sm); 
  color: var(--text-main); 
  cursor: pointer; 
  font-size: 0.85rem;
}

.filter-input:disabled, .dd-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.filter-input-sm {
  width: 100%;
  padding: 0.45rem 0.6rem;
  border: 1px solid var(--border);
  background: var(--bg-dark);
  border-radius: var(--radius-sm);
  color: var(--text-main);
  font-size: 0.8rem;
}

.range-inputs {
  display: flex;
  align-items: center;
  gap: 0.4rem;
}

.range-inputs span {
  color: var(--text-muted);
  font-weight: 600;
}

.popover-wrap { 
  position: relative; 
}

.dd-btn { 
  display: flex; 
  justify-content: space-between; 
}

.dd-panel { 
  position: absolute; 
  top: calc(100% + 6px); 
  left: 0; 
  width: 280px; 
  border: 1px solid var(--border); 
  border-radius: var(--radius-md); 
  background: var(--bg-panel); 
  z-index: 20; 
  overflow: hidden; 
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
}

.dd-search { 
  width: 100%; 
  border: none; 
  border-bottom: 1px solid var(--border); 
  padding: 0.65rem 0.9rem; 
  background: var(--bg-hover); 
  color: var(--text-main); 
}

.dd-actions { 
  display: flex; 
  justify-content: space-between; 
  padding: 0.5rem 0.9rem; 
  border-bottom: 1px solid var(--border); 
  font-size: 0.75rem; 
  color: var(--primary); 
}

.dd-actions span { 
  cursor: pointer; 
}

.dd-actions span:hover {
  text-decoration: underline;
}

.dd-list { 
  max-height: 220px; 
  overflow-y: auto; 
}

.dd-item { 
  display: flex; 
  gap: 0.6rem; 
  padding: 0.5rem 0.9rem; 
  font-size: 0.82rem; 
  cursor: pointer;
  align-items: center;
}

.dd-item:hover {
  background: var(--bg-hover);
}

.badge-mini {
  padding: 0.15rem 0.5rem;
  border-radius: 4px;
  font-size: 0.7rem;
  font-weight: 700;
  text-transform: uppercase;
}

.badge-critical {
  background: rgba(220, 38, 38, 0.15);
  color: #dc2626;
}

.badge-high {
  background: rgba(234, 88, 12, 0.15);
  color: #ea580c;
}

.badge-medium {
  background: rgba(234, 179, 8, 0.15);
  color: #eab308;
}

.badge-low {
  background: rgba(59, 130, 246, 0.15);
  color: #3b82f6;
}

@media (max-width: 1400px) {
  .filter-row { 
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); 
  }
}

/* Barra de progreso de sincronización */
.sync-progress {
  padding: 1rem 1.25rem;
  margin-bottom: 1rem;
}
.sync-progress-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
}
.sync-progress-phase {
  font-size: 0.85rem;
  font-weight: 600;
  color: var(--text-main);
}
.sync-progress-pct {
  font-size: 0.85rem;
  font-weight: 700;
  color: var(--primary);
}
.sync-progress-track {
  height: 8px;
  border-radius: 999px;
  background: var(--bg-hover);
  overflow: hidden;
}
.sync-progress-fill {
  height: 100%;
  border-radius: 999px;
  background: var(--primary);
  transition: width 0.4s ease;
}
.sync-progress-hint {
  margin: 0.5rem 0 0;
  font-size: 0.75rem;
  color: var(--text-muted);
}

/* Cards de trazabilidad */
.traceability-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 1rem;
  margin-bottom: 1rem;
}
.trace-tile {
  border: 1px solid var(--border);
  background: var(--bg-panel);
  border-radius: var(--radius);
  padding: 1rem;
  border-left: 3px solid var(--text-muted);
}
.trace-tile strong {
  display: block;
  color: var(--text-main);
  font-size: 1.8rem;
  line-height: 1;
  margin: 0.35rem 0;
}
.trace-label {
  font-size: 0.78rem;
  font-weight: 700;
  text-transform: uppercase;
  color: var(--text-muted);
}
.trace-sub {
  font-size: 0.72rem;
  color: var(--text-muted);
}
.trace-new { border-left-color: #dc2626; }
.trace-persistent { border-left-color: #d97706; }
.trace-resolved { border-left-color: #16a34a; }

@media (max-width: 1100px) {
  .evolution-grid,
  .evolution-panels,
  .traceability-grid {
    grid-template-columns: 1fr;
  }

  .filter-row {
    grid-template-columns: 1fr 1fr;
  }
  .f-group {
    border-right: none;
    border-bottom: 1px solid var(--border);
  }
}
</style>

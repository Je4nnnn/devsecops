# 📦 Documentación de Entrega — Cambios desde el 18/05/2026 (rama `main`)

> **Generado:** 2026-07-06 · **Autor:** Ariel Pinochet
> **Baseline:** commit `a04e92a` (2026-05-17) — último estado antes de esta entrega.
> **Alcance:** todo lo agregado/modificado en la rama **`main`**.
> La rama `qa-quality-gates` está **deprecada** y no se considera aquí.

---

# PARTE 1 — RESUMEN COMPLETO (ejecutivo)

Esta entrega ("Análisis de Evolución") reescribe cómo el sistema procesa y muestra las **+20.000 vulnerabilidades**. La idea central: **mover toda la agregación pesada a la base de datos** (PostgreSQL + TimescaleDB) y dejar que el frontend solo consuma APIs, sin descargar el dataset completo.

### Qué se logró
| Área | Antes | Ahora |
|------|-------|-------|
| **Listado de vulns** | Traía TODO + historial por fila (N+1) → carga en minutos | `/vulns` **paginado y filtrado en BD** → `{ items, total, page, ... }` |
| **Sincronización Wazuh** | Bloqueaba la petición ~20 min sin feedback | **Job en segundo plano** + barra de progreso + *toast* al terminar |
| **Línea de tiempo** | Contaba eventos (2 amenazas × 6 updates = 12) y no cargaba fechas/detalle | **Gantt por amenaza única** (cuenta 2), detalle desde BD, rango de fechas editable + filtro criticidad |
| **Top servidores** | No reportaba | Reescrito: CVEs activos distintos por servidor |
| **Trazabilidad** | Inexistente | Algoritmo Nuevas / Persistentes / Reemergidas / Remediadas vía stored procedures |

### Los 3 commits de la entrega
| Commit | Fecha | Qué trae |
|--------|-------|----------|
| `9f1d9ff` | 03/06 | Documentación v1.1 + spec de Entrega 2 |
| `67e0f46` | 06/07 | Grueso del backend Entrega 2 (sync 2º plano, SPs, timeline, filtros) + frontend |
| `4dc1108` | 06/07 | Filtro por criticidad + fecha "Hasta" editable en el Timeline |

### Impacto (diff vs baseline)
- **39 archivos**, +2.707 / −2.570 líneas.
- Backend: `vuln-api/app/main.py` +980 líneas (motor de la entrega).
- Frontend: 3 componentes/composables nuevos + rework completo del Timeline.
- Documentación: `DOCUMENTACION.md` a v1.1 + nuevo `docs/entrega2-analisis-evolucion.md`.

### Puntos de atención antes de entregar
1. **No commitear** `vuln_backup.dump` (~27 MB) y `vuln_backup.sql` (~112 MB) — dumps con credenciales cifradas. Van a `.gitignore`.
2. Sacar `vuln-api/app/__pycache__/*.pyc` del control de versiones.
3. Rotar secretos si los `.env` versionados llegaron al remoto (`JWT_SECRET`, `ENCRYPTION_KEY`, `POSTGRES_PASSWORD`).
4. El stack Jenkins/SonarQube/ZAP presente en `dev-tools/` es infraestructura **preexistente y sin cambios** en esta entrega.

---

# PARTE 2 — DETALLE TÉCNICO

## 1. Backend — `vuln-api/app/main.py` (+980 líneas)

Documento fuente completo: [`entrega2-analisis-evolucion.md`](entrega2-analisis-evolucion.md).

### 1.1 Objetos analíticos — `initialize_analytics_objects()`
Se ejecuta al arrancar. Solo actúa en PostgreSQL (`if engine.dialect.name != "postgresql": return`); en los tests con SQLite se usan rutas de *fallback* en ORM. Crea:

**Índices** en `wazuh_vulnerabilities` para los filtros server-side:
```
idx_wv_conn_status (connection_id, status)   idx_wv_agent_name    idx_wv_cve
idx_wv_severity    idx_wv_last_seen (DESC)    idx_wv_package_name
```

**Stored procedures** (`LANGUAGE sql STABLE`, permiten *inline* del planificador):
- `sp_traceability_timeline(conn, bucket INTERVAL, start, end)` → por cada *bucket* (`time_bucket` de TimescaleDB): `nuevas` (`Detected`), `reemergidas` (`Re-emerged`), `remediadas` (`Resolved`).
- `sp_traceability_summary(conn, ventana DEFAULT '7 days')` → `nuevas`, `persistentes`, `remediadas`, `total_activas`.

### 1.2 Algoritmo de trazabilidad
Cada vulnerabilidad transita estados registrados como **eventos** en la hypertable `vulnerability_detections` y como **estado actual** en `wazuh_vulnerabilities`:

```
Detected (Nueva) → ACTIVE → (deja de reportarse) → Resolved (RESOLVED)
                     ▲                                    │
                     └──── Re-emerged (reaparece) ────────┘
```

| Concepto | Definición |
|----------|------------|
| **Nueva** | `ACTIVE` con `first_seen` dentro de la ventana (def. 7 días) |
| **Persistente** | `ACTIVE` con `first_seen` anterior a la ventana |
| **Reemergida** | Evento `Re-emerged` en el bucket |
| **Remediada** | Estado `RESOLVED` / evento `Resolved` |

### 1.3 Endpoints
| Método | Ruta | Función |
|--------|------|---------|
| GET | `/vulns` | **Paginado + filtrado server-side**, sin N+1 (el historial ya no se carga en el listado) |
| GET | `/vulns/filter-options` | `DISTINCT` precalculados para poblar dropdowns: `agents`, `cves`, `packages`, `severities` |
| GET | `/vulns/{id}/history` | Historial de UNA vuln puntual, bajo demanda (`selectinload`) |
| GET | `/vulns/evolution/timeline` | Serie por bucket; sin filtros usa `sp_traceability_timeline`, con filtros usa consulta parametrizada (`= ANY(:agents)`) |
| GET | `/vulns/evolution/timeline-details` | **Drill-down**: registros de un bucket concreto (`bucket_start`/`bucket_end`) |
| GET | `/vulns/evolution/traceability-summary` | Tarjetas de resumen (SP en PG, *fallback* ORM en SQLite) |
| GET | `/vulns/evolution/threats` | **(julio)** Spans por amenaza única para el Gantt — ver §2 |
| GET | `/vulns/evolution/top-assets` | **(arreglado)** Top servidores — ver §2.1 |
| POST | `/wazuh-connections/{id}/sync` | Lanza sync **en 2º plano** → `job_id` |
| POST | `/vulns/sync-all` | Sync de todas las conexiones activas → `job_id` (**400** si no hay activas) |
| GET | `/sync/status` | Progreso del job (`?job_id=`); sin param → job más reciente o `{ "status": "idle" }` |

**Parámetros de `/vulns`:** `connection_id`, `agent_name`, `cve_id`, `package_name`, `severity`, `status`, `score_min`, `score_max`, `search`, `sort_by`, `sort_order`, `page`, `page_size` (máx. 500), `limit` (compat.). Respuesta: `{ items, total, page, page_size, total_pages }`.

### 1.4 Sincronización en segundo plano
- Registro de jobs en memoria: `SYNC_JOBS` (dict), `SYNC_JOBS_LOCK` (`threading.Lock`), `MAX_SYNC_JOBS=20`.
- Cada job: `status` (`pending|running|completed|error`), `phase`, `total`, `processed`, `synced`, `connections_done/total`, `current_connection`, `results`, `error`, `started_at`, `finished_at`.
- `_start_sync_job(conn_ids)` → crea `job_id`, lanza hilo *daemon* con sesión propia → `_run_sync_job` → `process_wazuh_vulnerabilities` con `progress_cb` (actualiza `processed/total` cada ~200 filas).
- **`SYNC_INLINE`** (env): ejecuta el sync síncrono reutilizando la sesión de la petición → los tests ven datos commiteados sin condiciones de carrera. `conftest.py` la activa.

Flujo:
```
POST /sync → _start_sync_job → responde { job_id, status } de inmediato
Frontend  → GET /sync/status?job_id=… (polling 1.5 s) → al completar: toast ✅ + recarga
```

---

## 2. Rework de la Línea de Tiempo (Gantt) — julio

### 2.1 Bugs corregidos
| Problema | Solución |
|----------|----------|
| Contaba **eventos de detección** (2 amenazas × 6 updates = 12) | Cuenta **amenazas distintas** (= 2): cada barra = 1 `WazuhVulnerability` |
| "Detalle de 01/06" estando a día 11; clic sin resultado | Detalle cargado **directo de BD** vía `/vulns/{id}/history`, al abrir el modal |
| **Top servidores no reporta** | `top_vulnerable_assets` reescrito: cuenta CVEs **activos distintos** por servidor (`status='ACTIVE'`, group by `agent_name`) en vez de eventos de una ventana de 7 días que estaba vacía |
| Filtros no funcionaban (`params[connection_id]=…`) | Doble-envoltura de params corregida: `getThreatSpans(params)` en vez de `getThreatSpans({ params })` |

### 2.2 Diseño nuevo
- **Gráfico Gantt**: eje X = tiempo (fechas), eje Y = amenazas. Cada barra va desde la detección hasta la resolución, **recortada** al rango visible:
  - Detectada antes del inicio → `clippedLeft` (empieza en el borde izquierdo).
  - Activa o termina después del fin → `clippedRight` / `ongoing` (llega al borde derecho).
- **Rango editable**: "Desde" (date picker) y "Hasta" (editable, **sin fechas futuras**; ej. 1-ene → 1-feb). Default: últimos 30 días → hoy.
- **Filtro por criticidad**: multi-select con colores por severidad, **aditivo** con conexión + agente + CVE + rango.
- **Endpoint `GET /vulns/evolution/threats`**: aplica todos los filtros vía `_apply_vuln_filters`, ordena por severidad → antigüedad, y devuelve:
  ```json
  { "range": {"start","end"}, "total", "active", "resolved", "returned", "items": [ /* spans */ ] }
  ```
  Tope de 300 barras renderizadas en el front (`MAX_THREATS`).

### 2.3 Archivos del frontend
| Archivo | Cambio |
|---------|--------|
| `views/Timeline.vue` | Orquestador; refs `selectedSeverities`, `startDate`, `endDate`; carga opciones desde `getFilterOptions`; `openThreat` → historial desde BD |
| `views/timeline/useTimelineData.js` | Geometría de barras (leftPct/widthPct con clamp), conteos distintos, armado de params |
| `.../components/TimelineCanvas.vue` | Render Gantt con eje de fechas |
| `.../components/TimelineFilters.vue` | Dos date inputs ("Desde"/"Hasta") + dropdown "Criticidad" |
| `.../components/TimelineDetailModal.vue` | Cabecera de amenaza + historial cargado de BD |
| `.../components/TimelineKpiStrip.vue` | KPIs: distintas / activas / resueltas / en vista |
| `views/timeline/timelineFormatters.js` | `severityColor`, `SEVERITY_COLORS`, `fmtDayLabel` |
| `services/vulnService.js` | `getThreatSpans()` |
| `views/timeline/useTimelineNavigation.js` | **Eliminado** (+ su spec) |

---

## 3. Frontend transversal

| Archivo | Cambio |
|---------|--------|
| `composables/useToast.js` | Singleton reactivo de *toasts* (`success`/`error`/`info`/`warning`) |
| `components/ToastHost.vue` | Contenedor fijo (arriba-derecha) con transiciones |
| `composables/useSyncJob.js` | Estado global del job; `startSync`, `resumeIfActive`, `onDone`; *polling* `/sync/status` cada 1.5 s + toast al terminar |
| `App.vue` | Monta `<ToastHost />` |
| `views/Dashboard.vue` | Paginación server-side, barra de progreso de sync, tarjetas de trazabilidad, filtros precargados |
| `services/vulnService.js` | Cliente dedicado: `getVulns`, `getFilterOptions`, `getVulnHistory`, `syncVulns`, `syncConnection`, `getSyncStatus`, `getTraceability*`, `getTimelineDetails`, `getThreatSpans` |

### Feedback de carga
- Barra de progreso **determinada** durante el sync (`processed/total`).
- Barra **indeterminada** al construir la línea de tiempo.
- **Toast** al completar/errar el job.

---

## 4. Pruebas
- **Backend** (`vuln-api/tests/`): 52 passed. `conftest.py` usa SQLite en memoria (`StaticPool`) + `SYNC_INLINE`. Aserciones al nuevo contrato: `/vulns` → `{ items, total, page, ... }`; sync → `{ job_id, status, synced, results }`; `/vulns/sync-all` → **400** sin conexiones activas.
- **Frontend**: specs del Timeline reescritas al contrato Gantt (`getThreatSpans`, criticidad, fechas). `npm run build` compila sin errores.

---

## 5. Resumen de archivos modificados (39 archivos, +2.707 / −2.570)

**Backend** — `vuln-api/app/main.py`, `tests/conftest.py`, `tests/test_api.py`.
**Frontend nuevo** — `composables/useToast.js`, `composables/useSyncJob.js`, `components/ToastHost.vue`.
**Frontend modificado** — `App.vue`, `services/vulnService.js`, `views/Dashboard.vue`, `views/Timeline.vue`, todos los `views/timeline/**` (canvas, filters, modal, kpi, useTimelineData, formatters) + specs.
**Frontend eliminado** — `views/timeline/useTimelineNavigation.js` (+ spec).
**Infra/config** — `.env`, `vuln-api/.env`, `docker-compose.yml` (puerto `${DB_HOST_PORT:-5433}:5432` para conexión local).
**Docs** — `DOCUMENTACION.md` (v1.1), `docs/entrega2-analisis-evolucion.md` (nuevo).

---

## 6. Índice de documentación
- Este documento — consolidado de la entrega (rama `main`).
- [`entrega2-analisis-evolucion.md`](entrega2-analisis-evolucion.md) — detalle técnico backend (v1.0).
- [`../DOCUMENTACION.md`](../DOCUMENTACION.md) — documentación técnica general (v1.1).

---

*Generado el 2026-07-06 — cambios en `main` desde `a04e92a` (18/05).*

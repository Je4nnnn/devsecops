# 🧬 Entrega 2 — Análisis de Evolución (Procesamiento Temporal)

> **Versión:** 1.0 — **Fecha:** 2026-05-28
> **Autor:** Ariel Pinochet
> **Alcance:** Algoritmo de trazabilidad, métricas de tendencia, procesamiento
> en backend, sincronización en segundo plano y ajustes de frontend.

---

## Tabla de Contenidos

1. [Problema que resuelve](#1-problema-que-resuelve)
2. [Decisión de arquitectura](#2-decisión-de-arquitectura)
3. [Algoritmo de trazabilidad](#3-algoritmo-de-trazabilidad)
4. [Procesamiento en la base de datos (stored procedures + índices)](#4-procesamiento-en-la-base-de-datos)
5. [API: listado paginado y filtros server-side](#5-api-listado-paginado-y-filtros-server-side)
6. [Línea de tiempo y drill-down bajo demanda](#6-línea-de-tiempo-y-drill-down-bajo-demanda)
7. [Sincronización en segundo plano (job + progreso + toast)](#7-sincronización-en-segundo-plano)
8. [Cambios en el frontend](#8-cambios-en-el-frontend)
9. [Pruebas](#9-pruebas)
10. [Resumen de archivos modificados](#10-resumen-de-archivos-modificados)

---

## 1. Problema que resuelve

El sistema gestiona **+20.000 registros de vulnerabilidades y en aumento**. Antes
de esta entrega:

- `GET /vulns` traía **todas** las filas y, por cada una, accedía a su historial
  (`v.history`) → problema **N+1** → la carga del dashboard tardaba minutos.
- El **frontend** filtraba, ordenaba y construía la línea de tiempo **en el
  cliente**, descargando todo el dataset.
- La **sincronización** con Wazuh bloqueaba la petición HTTP: el usuario quedaba
  esperando ~20 min sin feedback.

### Objetivos de la entrega

| Requisito | Estado |
|-----------|--------|
| Algoritmo de trazabilidad (Nuevas / Persistentes / Remediadas) | ✅ |
| Filtros por criticidad, agente, CVE, paquete, estado | ✅ |
| Cálculo de métricas de tendencia | ✅ |
| Procedimientos almacenados para consultas rápidas | ✅ |
| Filtros precargados (opciones generales por agente/CVE/etc.) | ✅ |
| Sincronización en segundo plano | ✅ |
| Barra de progreso de carga | ✅ |
| Notificación tipo *toast* al terminar | ✅ |
| Línea de trazabilidad de amenazas en el frontend | ✅ |

---

## 2. Decisión de arquitectura

Conforme a la arquitectura objetivo (componente **Processing**), **toda la
agregación pesada vive en la base de datos**; el frontend **solo consume APIs**
y no ejecuta consultas pesadas ni accede a la BD directamente.

```
┌──────────────┐   filtros/orden/paginación    ┌────────────────────────────┐
│  Vue 3 (UI)  │  ───────────────────────────► │  FastAPI (orquestación)    │
│  solo render │   parámetros de consulta       │  + validación + JWT        │
└──────────────┘                                └─────────────┬──────────────┘
       ▲                                                       │
       │ resultados precalculados, baja latencia               ▼
       │                                       ┌────────────────────────────┐
       └─────────────────────────────────────  │ PostgreSQL + TimescaleDB   │
                                                │ índices + stored procedures │
                                                │ time_bucket / hypertable    │
                                                └────────────────────────────┘
```

**Principio:** el cliente nunca descarga 20k filas para "armar" una vista. Pide
exactamente la página/agregación que necesita y la BD responde ya procesada.

---

## 3. Algoritmo de trazabilidad

Cada vulnerabilidad transita por estados que se registran como **eventos** en la
hypertable `vulnerability_detections` (columna `status`) y como **estado actual**
en `wazuh_vulnerabilities` (columna `status` = `ACTIVE` / `RESOLVED`).

```
        Primera vez que un agente la reporta
                        │
                  Detected (Nueva)
                        │
                     ACTIVE ───── sigue reportándose ────► ACTIVE (actualiza last_seen)
                        │
                        └── deja de reportarse ──────────► Resolved (Remediada) / RESOLVED
                                                                │
                                              vuelve a reportarse
                                                                │
                                                  Re-emerged (Reemergida) → ACTIVE
```

### Clasificación para las métricas

| Concepto | Definición | Fuente |
|----------|------------|--------|
| **Nueva** | Evento `Detected` en el bucket / `ACTIVE` con `first_seen` dentro de la ventana (def. 7 días) | `vulnerability_detections` / `wazuh_vulnerabilities` |
| **Reemergida** | Evento `Re-emerged` en el bucket | `vulnerability_detections` |
| **Remediada** | Evento `Resolved` en el bucket / estado `RESOLVED` | ambas |
| **Persistente** | `ACTIVE` con `first_seen` anterior a la ventana | `wazuh_vulnerabilities` |

---

## 4. Procesamiento en la base de datos

`initialize_analytics_objects()` (en `vuln-api/app/main.py`) se ejecuta al
arrancar y crea índices + funciones SQL. Está **protegida para PostgreSQL**
(`if engine.dialect.name != "postgresql": return`) para que los tests con SQLite
usen rutas de *fallback* en ORM.

### 4.1 Índices para filtros server-side

```sql
CREATE INDEX IF NOT EXISTS idx_wv_conn_status   ON wazuh_vulnerabilities (connection_id, status);
CREATE INDEX IF NOT EXISTS idx_wv_agent_name    ON wazuh_vulnerabilities (agent_name);
CREATE INDEX IF NOT EXISTS idx_wv_cve           ON wazuh_vulnerabilities (cve_id);
CREATE INDEX IF NOT EXISTS idx_wv_severity      ON wazuh_vulnerabilities (severity);
CREATE INDEX IF NOT EXISTS idx_wv_last_seen     ON wazuh_vulnerabilities (last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_wv_package_name  ON wazuh_vulnerabilities (package_name);
```

### 4.2 `sp_traceability_timeline` — línea de tiempo por bucket

Devuelve, por cada *bucket* temporal, cuántas vulnerabilidades fueron **nuevas**,
**reemergidas** y **remediadas**. Usa `time_bucket` (TimescaleDB) sobre la
hypertable.

```sql
sp_traceability_timeline(p_connection_id, p_bucket INTERVAL, p_start, p_end)
RETURNS (bucket, nuevas, reemergidas, remediadas)
-- count(*) FILTER (WHERE vd.status = 'Detected')   AS nuevas
-- count(*) FILTER (WHERE vd.status = 'Re-emerged') AS reemergidas
-- count(*) FILTER (WHERE vd.status = 'Resolved')   AS remediadas
-- JOIN assets → managers; filtra por legacy_connection_id y rango de tiempo
```

### 4.3 `sp_traceability_summary` — tarjetas de resumen

```sql
sp_traceability_summary(p_connection_id, p_new_window INTERVAL DEFAULT '7 days')
RETURNS (nuevas, persistentes, remediadas, total_activas)
-- nuevas:       ACTIVE y first_seen >= now() - ventana
-- persistentes: ACTIVE y first_seen <  now() - ventana
-- remediadas:   RESOLVED
-- total_activas: ACTIVE
```

> Las funciones son `LANGUAGE sql STABLE`, lo que permite al planificador de
> PostgreSQL optimizar e *inline*-ar la consulta.

---

## 5. API: listado paginado y filtros server-side

`GET /vulns` se reescribió para paginar y filtrar **en la base de datos**, sin
N+1 (el historial ya **no** se carga en el listado).

### Parámetros

| Parámetro | Descripción |
|-----------|-------------|
| `connection_id` | Filtra por conexión Wazuh |
| `agent_name`, `cve_id`, `package_name`, `severity` | CSV; filtran por columna (`IN`) |
| `status` | `ACTIVE` / `RESOLVED` |
| `score_min`, `score_max` | Rango de CVSS |
| `search` | Texto libre (CVE, agente, paquete, descripción) |
| `sort_by`, `sort_order` | Orden server-side (incluye severidad por rango lógico) |
| `page`, `page_size` | Paginación (page_size máx. 500) |
| `limit` | Compatibilidad hacia atrás (tope simple) |

### Respuesta

```json
{
  "items": [ /* ...vulnerabilidades de la página... */ ],
  "total": 20431,
  "page": 1,
  "page_size": 50,
  "total_pages": 409
}
```

### Opciones de filtro precalculadas

`GET /vulns/filter-options?connection_id=...` devuelve los valores `DISTINCT`
listos para poblar los *dropdowns* sin descargar el dataset:

```json
{ "agents": [...], "cves": [...], "packages": [...], "severities": [...] }
```

### Historial bajo demanda

`GET /vulns/{id}/history` carga el historial de **una** vulnerabilidad puntual
(con `selectinload`), solo cuando el usuario lo pide.

---

## 6. Línea de tiempo y drill-down bajo demanda

| Endpoint | Función |
|----------|---------|
| `GET /vulns/evolution/timeline` | Serie por bucket (nuevas/reemergidas/remediadas). Sin filtros de agente/CVE usa `sp_traceability_timeline`; con filtros usa consulta parametrizada equivalente (`= ANY(:agents)` / `= ANY(:cves)`). |
| `GET /vulns/evolution/traceability-summary` | Tarjetas de resumen (`sp_traceability_summary` en PG; *fallback* ORM en SQLite). |
| `GET /vulns/evolution/timeline-details` | **Drill-down**: registros de un bucket concreto (`bucket_start`/`bucket_end`), solo al abrir el modal. |

**Periodos soportados** (`_PERIOD_CONFIG`): `24h`, `7d`, `30d`, `90d`, `all`,
cada uno con su `delta` y su `bucket` (`time_bucket`).

El frontend pinta primero la línea (rápida) y carga el detalle de cada *slot*
**solo al hacer clic** — no descarga todos los detalles por adelantado.

---

## 7. Sincronización en segundo plano

La sincronización con Wazuh ya **no bloquea** la petición. Se lanza un *job* en
un hilo *daemon* con su propia sesión de BD, y el frontend consulta el progreso.

### Registro de jobs (en memoria)

```python
SYNC_JOBS: dict          # job_id → estado del job
SYNC_JOBS_LOCK           # threading.Lock para acceso seguro
MAX_SYNC_JOBS = 20       # se limita el historial en memoria
```

Cada job: `status` (`pending|running|completed|error`), `phase`, `total`,
`processed`, `synced`, `connections_done/total`, `current_connection`,
`results`, `error`, `started_at`, `finished_at`.

### Flujo

```
POST /wazuh-connections/{id}/sync   ó   POST /vulns/sync-all
        │
        ├─► _start_sync_job(conn_ids)  → crea job_id, lanza hilo
        │        └─► _run_sync_job():  fetch_all_vulns → process_wazuh_vulnerabilities
        │                              progress_cb actualiza processed/total cada 200 filas
        │
        └─► responde { job_id, status, ... } de inmediato
                │
   Frontend ───► GET /sync/status?job_id=...   (polling cada 1.5 s)
                │
                └─► al completarse → toast ✅ + recarga de datos
```

### `/sync/status`

- Con `job_id`: devuelve ese job (404 si no existe).
- Sin `job_id`: devuelve el job más reciente (para **reanudar** la barra si el
  usuario recarga la página), o `{ "status": "idle" }` si no hay ninguno.

### Modo *inline* para pruebas (`SYNC_INLINE`)

Bandera (`SYNC_INLINE`, vía variable de entorno) que ejecuta la sincronización
**de forma síncrona reutilizando la sesión de la petición** en lugar de lanzar
un hilo. Permite que los tests vean los datos *commiteados* de inmediato sin
condiciones de carrera. `conftest.py` la activa automáticamente.

---

## 8. Cambios en el frontend

### Nuevos / modificados

| Archivo | Cambio |
|---------|--------|
| `application/services/vulnService.js` | Servicio dedicado: `getVulns` (paginado), `getFilterOptions`, `getVulnHistory`, `syncVulns`, `syncConnection`, `getSyncStatus`, `getTraceabilityTimeline`, `getTraceabilitySummary`, `getTimelineDetails`, etc. |
| `presentation/composables/useToast.js` | Singleton reactivo de *toasts* (`success`/`error`/`info`/`warning`). |
| `presentation/components/ToastHost.vue` | Contenedor de *toasts* fijo (arriba-derecha) con transiciones. |
| `presentation/composables/useSyncJob.js` | Estado global del job; `startSync`, `resumeIfActive`, `onDone`; *polling* a `/sync/status` cada 1.5 s + toast al terminar. |
| `App.vue` | Monta `<ToastHost />`. |
| `presentation/views/Dashboard.vue` | Paginación server-side, barra de progreso de sync, tarjetas de trazabilidad (nuevas/persistentes/remediadas), filtros precargados. |
| `presentation/views/Timeline.vue` | Filtros por agente/CVE, drill-down asíncrono al abrir slot, barra de carga indeterminada. |
| `presentation/views/timeline/useTimelineData.js` | Consume el timeline del backend; mapea *buckets* a *slots*; `fetchSlotDetails` bajo demanda. |

### Feedback de carga

- **Barra de progreso determinada** durante la sincronización (`processed/total`).
- **Barra indeterminada** mientras se construye la línea de tiempo.
- **Toast** al completar/errar el job de sincronización.

---

## 9. Pruebas

Suite backend (`vuln-api/tests/`): **52 passed**.

- `conftest.py` usa SQLite en memoria (`StaticPool`) y activa `SYNC_INLINE`.
- Las aserciones se actualizaron al nuevo contrato:
  - `/vulns` → `{ items, total, page, ... }` (antes lista plana).
  - Sincronización → `{ job_id, status, synced, results }`.
  - `/vulns/sync-all` → **400** cuando no hay conexiones activas.
- Cobertura del algoritmo de trazabilidad: `DETECTED`, `RESOLVED` por ausencia,
  `REOPENED` al reaparecer, `SEVERITY_CHANGED`, *skip* sin `cve_id`.

```bash
cd vuln-api
./venv/Scripts/python.exe -m pytest -q     # Windows
# source venv/bin/activate && pytest -q    # Linux/Mac
```

Frontend: `npm run build` compila sin errores (108 módulos).

---

## 10. Resumen de archivos modificados

### Backend (`vuln-api/`)
- `app/main.py` — `initialize_analytics_objects()` (índices + stored procedures),
  registro de jobs y sincronización en segundo plano (`SYNC_JOBS`, `_new_sync_job`,
  `_run_sync_job`, `_start_sync_job`, `SYNC_INLINE`), `GET /vulns` paginado y
  filtrado, `/vulns/filter-options`, `/vulns/{id}/history`, `/sync/status`,
  `/vulns/evolution/timeline`, `/vulns/evolution/timeline-details`,
  `/vulns/evolution/traceability-summary`, `process_wazuh_vulnerabilities`
  con `progress_cb`.
- `tests/conftest.py` — activa `SYNC_INLINE`.
- `tests/test_api.py` — aserciones al nuevo contrato.

### Frontend (`frontend/src/`)
- `application/services/vulnService.js`
- `presentation/composables/useToast.js`, `useSyncJob.js`
- `presentation/components/ToastHost.vue`
- `presentation/views/Dashboard.vue`, `Timeline.vue`
- `presentation/views/timeline/useTimelineData.js`
- `App.vue`

---

*Documento generado el 2026-05-28 — Entrega 2: Análisis de Evolución.*

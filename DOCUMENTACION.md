# 📋 Documentación Técnica — DevSecOps Vulnerability Platform

> **Versión:** 1.1 — **Fecha:** 2026-05-28
> **Autor:** Equipo VTYG
>
> **Novedades v1.1 (Entrega 2 — Análisis de Evolución):** procesamiento temporal
> en backend (stored procedures + índices), listado **paginado y filtrado
> server-side**, sincronización **en segundo plano** con barra de progreso y
> *toast*, y línea de **trazabilidad de amenazas**. Ver el detalle completo en
> [`docs/entrega2-analisis-evolucion.md`](docs/entrega2-analisis-evolucion.md).

---

## Tabla de Contenidos

1. [Visión General](#1-visión-general)
2. [Stack Tecnológico](#2-stack-tecnológico)
3. [Estructura de Directorios](#3-estructura-de-directorios)
4. [Pipeline Completo](#4-pipeline-completo-de-wazuh-a-la-pantalla)
5. [Backend — Módulos en Detalle](#5-backend--módulos-en-detalle)
6. [Frontend — Arquitectura y Vistas](#6-frontend--arquitectura-y-vistas)
7. [Base de Datos — Esquema](#7-base-de-datos--esquema-relacional)
8. [Docker Compose — Infraestructura](#8-docker-compose--infraestructura)
9. [Seguridad](#9-seguridad)
10. [Herramientas DevSecOps](#10-herramientas-devsecops)
11. [Variables de Entorno](#11-variables-de-entorno-env)
12. [Comandos de Operación](#12-comandos-de-operación)
13. [Instalación desde Cero](#13-instalación-desde-cero)

---

## 1. Visión General

La plataforma es una aplicación web que **centraliza y visualiza vulnerabilidades** reportadas por servidores Wazuh. Permite conectar múltiples instancias de Wazuh Indexer, sincronizar sus datos de vulnerabilidades y visualizarlos en un dashboard con métricas, tendencias históricas y línea de tiempo interactiva.

### Flujo resumido

```
Wazuh Indexer (OpenSearch)
        ↓  REST API :9200
   FastAPI Backend  :8000
        ↓  SQLAlchemy ORM
  PostgreSQL + TimescaleDB
        ↓  REST + JWT
    Vue 3 Frontend  :5173 / :18080
```

---

## 2. Stack Tecnológico

| Capa | Tecnología | Versión recomendada |
|------|-----------|---------------------|
| Frontend | Vue 3 + Vite + Axios | Node 18+ |
| Backend | FastAPI + Uvicorn | Python 3.11+ |
| Base de Datos | PostgreSQL + TimescaleDB | PG 15 |
| ORM | SQLAlchemy | 2.x |
| Autenticación | JWT (python-jose) + bcrypt | — |
| Cifrado credenciales | Fernet (cryptography) | — |
| Fuente de datos | Wazuh Indexer (OpenSearch) | 4.x+ |
| Proxy / Serving | Nginx | Producción |
| Contenedores | Docker + Docker Compose | — |
| CI/CD | Jenkins + SonarQube + OWASP ZAP | dev-tools/ |

---

## 3. Estructura de Directorios

```
devsecops2/
├── docker-compose.yml              # Orquestación principal (db + api + frontend)
├── .env                            # Variables de entorno globales
├── iniciar_app.sh                  # Script de arranque rápido
├── registrar_wazuh_agent.sh        # Script para registrar agentes Wazuh
│
├── vuln-api/                       # ── BACKEND ──────────────────────────────
│   ├── app/
│   │   ├── main.py                 # Endpoints, lógica de negocio principal
│   │   ├── models.py               # Modelos SQLAlchemy (definición de tablas)
│   │   ├── db.py                   # Conexión a PostgreSQL
│   │   ├── auth.py                 # JWT y autenticación de usuarios
│   │   ├── crypto.py               # Cifrado Fernet de contraseñas Wazuh
│   │   └── wazuh_client.py         # Cliente HTTP al Wazuh Indexer
│   ├── requirements.txt            # Dependencias Python
│   ├── Dockerfile
│   └── .env                        # Variables locales (dev)
│
├── frontend/                       # ── FRONTEND ─────────────────────────────
│   ├── src/
│   │   ├── application/services/
│   │   │   ├── authService.js      # Login, cambio de contraseña
│   │   │   ├── userService.js      # Gestión de usuarios
│   │   │   ├── wazuhService.js     # CRUD de conexiones Wazuh
│   │   │   └── vulnService.js      # Vulns paginadas, filtros, sync, evolución (v1.1)
│   │   ├── infrastructure/http/
│   │   │   ├── apiClient.js        # Instancia Axios con baseURL dinámica
│   │   │   └── interceptors/
│   │   │       └── authInterceptor.js   # Inyecta JWT Bearer en cada request
│   │   ├── presentation/
│   │   │   ├── router/index.js     # Rutas + guards de autenticación
│   │   │   ├── directives/
│   │   │   │   └── clickOutside.js # Directiva custom para cerrar menús
│   │   │   ├── components/
│   │   │   │   └── ToastHost.vue   # Contenedor de notificaciones toast (v1.1)
│   │   │   ├── composables/
│   │   │   │   ├── useToast.js     # Estado reactivo de toasts (v1.1)
│   │   │   │   └── useSyncJob.js   # Polling de /sync/status + progreso (v1.1)
│   │   │   └── views/
│   │   │       ├── Login.vue            # Página de login
│   │   │       ├── Dashboard.vue        # Métricas, gráficos, last sync
│   │   │       ├── Timeline.vue         # Canvas interactivo de detecciones
│   │   │       ├── ConfigWazuh.vue      # CRUD conexiones Wazuh + sync
│   │   │       ├── ConfigUser.vue       # Gestión de usuarios del sistema
│   │   │       ├── ChangePassword.vue   # Cambio obligatorio en primer login
│   │   │       └── NotFound.vue
│   │   └── App.vue
│   ├── vite.config.js              # Config Vite (proxy /api → :8000 en dev)
│   ├── package.json
│   └── Dockerfile
│
├── db-init/
│   ├── 10-init.sql                 # Crea BD sonarqube (para CI)
│   └── 20-add-last-sync-at.sql     # Migración: columna last_sync_at
│
├── nginx/ssl/                      # Certificados SSL autofirmados
│   ├── nginx-selfsigned.crt
│   └── nginx-selfsigned.key
│
├── dev-tools/
│   ├── jenkins/                    # Pipeline CI/CD
│   ├── sonarqube/                  # Análisis estático (SAST)
│   └── zap/                        # OWASP ZAP análisis dinámico (DAST)
│
└── prod_config/
    └── nginx.domain.conf           # Config Nginx para dominio real (HTTPS)
```

---

## 4. Pipeline Completo: De Wazuh a la Pantalla

```
┌─────────────────────────────────────────────────────────────────────┐
│  WAZUH INDEXER (OpenSearch)  — puerto 9200                          │
│  Índice: wazuh-states-vulnerabilities-*                             │
│  Contiene: CVE, severidad, paquete afectado, agente, timestamp      │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           │  HTTPS POST /_search
                           │  Auth Basic UTF-8 (soporta ñ y especiales)
                           │  Paginación: search_after en lotes de 10.000
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  wazuh_client.py                                                    │
│  fetch_all_vulns()                                                  │
│  • Genera header Authorization base64(UTF-8)                        │
│  • Loop: pide 10.000 docs, guarda sort[-1] como cursor              │
│  • Repite hasta recibir menos de 10.000 (fin de datos)              │
│  • Retorna lista completa de documentos JSON crudos                 │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           │  raw_vulns[] (lista de dicts)
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  main.py — process_wazuh_vulnerabilities()                          │
│                                                                     │
│  Por cada documento raw_vuln:                                       │
│  1. Extrae campos: agent{id,name}, host.os, package, vulnerability  │
│  2. Upsert Manager  → 1 Manager por conexión Wazuh                  │
│  3. Upsert Asset    → 1 Asset por agente Wazuh (hostname, IP, OS)   │
│  4. Upsert VulnerabilityCatalog → 1 CVE global (sin duplicados)     │
│  5. Insert/Update WazuhVulnerability                                │
│     • Si existe + ACTIVE   → actualiza last_seen, score             │
│     • Si existe + RESOLVED → reabre (REOPENED), registra historial  │
│     • Si es nuevo          → crea registro, historial DETECTED       │
│  6. Insert VulnerabilityDetection (evento con timestamp de Wazuh)   │
│  7. Vulns ACTIVE no vistas en este sync → marcar RESOLVED           │
│  8. Actualiza conn.last_sync_at = ahora                             │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           │  SQLAlchemy ORM → SQL
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PostgreSQL 15 + TimescaleDB                                        │
│  vulnerability_detections → hypertable (partición automática        │
│  por timestamp, índices optimizados para queries de serie temporal) │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           │  GET /vulns, /vulns/evolution/*
                           │  Authorization: Bearer <JWT>
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  FastAPI REST API — puerto 8000                                     │
│  Todos los endpoints protegidos con JWT Bearer Token                │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           │  Axios + authInterceptor
                           │  VITE_API_URL=/api (proxy en dev)
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Vue 3 Frontend — :5173 (dev) / :18080 (docker)                     │
│  Dashboard │ Timeline │ ConfigWazuh │ ConfigUser                    │
└─────────────────────────────────────────────────────────────────────┘
```

### Estados posibles de una vulnerabilidad

```
          Primera detección
                ↓
            DETECTED
                ↓
            ACTIVE  ──── sync siguiente la ve ────→  ACTIVE (actualiza last_seen)
                │
                └── sync siguiente NO la ve ──────→  RESOLVED
                                                          │
                                              sync la vuelve a ver
                                                          │
                                                       REOPENED → ACTIVE
```

---

## 5. Backend — Módulos en Detalle

### `db.py` — Conexión a la Base de Datos

```python
load_dotenv(override=True)          # Carga .env con prioridad sobre env del sistema
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(...)
```

- Lee `DATABASE_URL` del `.env`
- `get_db()` es un generator usado como dependency injection en FastAPI
- `override=True` evita que variables del sistema sobreescriban el `.env`

---

### `models.py` — Tablas de la Base de Datos

#### `users`
| Columna | Tipo | Descripción |
|---------|------|-------------|
| id | Integer PK | Autoincremental |
| username | String UNIQUE | Nombre de usuario |
| password_hash | String | Hash bcrypt |
| is_active | Boolean | Si puede hacer login |
| is_default_password | Boolean | True = debe cambiar clave al entrar |
| created_at | TimestampTZ | Fecha de creación |

#### `wazuh_connections`
| Columna | Tipo | Descripción |
|---------|------|-------------|
| id | Integer PK | Autoincremental |
| name | String UNIQUE | Nombre descriptivo |
| indexer_url | String | URL del Wazuh Indexer (ej: https://IP:9200) |
| wazuh_user | String | Usuario del Indexer |
| wazuh_password | String | **Contraseña cifrada con Fernet** |
| is_active | Boolean | Si se sincroniza en sync-all |
| tested | Boolean | Si se ha probado la conexión |
| last_tested_at | TimestampTZ | Último test de conectividad |
| last_test_ok | Boolean | Resultado del último test |
| last_sync_at | TimestampTZ | Última sincronización exitosa |

#### `managers`
Capa de abstracción entre conexiones Wazuh y assets. Un Manager = una conexión Wazuh.

#### `assets`
Un asset = un agente Wazuh (equipo monitoreado).

| Columna | Tipo | Descripción |
|---------|------|-------------|
| id | UUID PK | — |
| wazuh_agent_id | String | ID del agente en Wazuh |
| hostname | String | Nombre del equipo |
| os_version | String | Versión del SO |
| ip_address | String/INET | IP del agente |
| manager_id | FK → managers | — |

**Unique:** `(manager_id, wazuh_agent_id)` — no hay assets duplicados por conexión.

#### `vulnerability_catalog`
Catálogo global de CVEs. Un CVE existe una sola vez aquí, independientemente de cuántos agentes lo tengan.

| Columna | Tipo | Descripción |
|---------|------|-------------|
| cve_id | String PK | Ej: CVE-2023-1234 |
| severity | Enum | Low / Medium / High / Critical |
| description | Text | Descripción de la vulnerabilidad |
| cvss_score | Numeric(3,1) | Puntuación CVSS |

#### `vulnerability_detections` ⭐ (Hypertable TimescaleDB)
Cada evento de detección/resolución. Esta tabla es el corazón analítico.

| Columna | Tipo | Descripción |
|---------|------|-------------|
| event_id | UUID PK | — |
| timestamp | TimestampTZ PK | **Partición TimescaleDB** |
| asset_id | FK → assets | Equipo donde se detectó |
| cve_id | FK → vulnerability_catalog | CVE detectado |
| status | Enum | Detected / Resolved / Re-emerged |
| package_name | String | Paquete afectado |
| package_version | String | Versión del paquete |

#### `wazuh_vulnerabilities`
Estado **actual** de cada vulnerabilidad por agente. Clave única: `(connection_id, agent_id, package_name, package_version, cve_id)`.

#### `vulnerability_history`
Cada cambio de estado genera un registro aquí: DETECTED, RESOLVED, REOPENED, SEVERITY_CHANGED.

---

### `crypto.py` — Cifrado de Credenciales

```python
fernet = Fernet(ENCRYPTION_KEY.encode())
encrypt(value)   # AES-128-CBC + HMAC → string base64
decrypt(value)   # Revierte el cifrado
```

- La `ENCRYPTION_KEY` es una clave Fernet de 32 bytes en base64
- **Todas las contraseñas** de conexiones Wazuh se guardan cifradas en BD
- Si se pierde la clave, las contraseñas no son recuperables

---

### `auth.py` — Autenticación JWT

```
POST /auth/login
  └── authenticate_user() → verifica username/password/is_active
  └── create_access_token() → JWT HS256, expira en 60 min
  └── Retorna: { access_token, token_type: "bearer" }

Endpoints protegidos:
  └── Depends(get_current_user)
      └── jwt.decode(token, SECRET_KEY)
      └── Busca user en BD
      └── Si falla → 401 Unauthorized
```

---

### `wazuh_client.py` — Cliente Wazuh Indexer

#### Autenticación UTF-8
```python
token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
# Soporta caracteres especiales: ñ, á, é, ü, etc.
```

#### Paginación sin límite (`search_after`)
```
Iteración 1: GET docs 1–10.000      → cursor = sort del doc #10.000
Iteración 2: GET docs 10.001–20.000 → cursor = sort del doc #20.000
Iteración 3: GET docs 20.001–19.532 → menos de 10.000 → FIN
Total: 19.532 documentos
```

El índice `wazuh-states-vulnerabilities-*` contiene el estado actual de todas las vulnerabilidades detectadas por todos los agentes Wazuh.

---

### `main.py` — Todos los Endpoints

#### Autenticación
| Método | Ruta | Auth | Descripción |
|--------|------|------|-------------|
| POST | `/auth/login` | No | Login → JWT |
| POST | `/auth/change-password` | Sí | Cambiar contraseña (valida robustez) |

#### Usuarios
| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/users/me` | Datos del usuario autenticado |
| GET | `/users` | Listar todos los usuarios |
| POST | `/users` | Crear nuevo usuario |
| DELETE | `/users/{id}` | Eliminar usuario (no puede eliminarse a sí mismo) |

#### Conexiones Wazuh
| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/wazuh-connections` | Listar conexiones con metadata |
| POST | `/wazuh-connections` | Crear conexión (**prueba antes de guardar**) |
| PUT | `/wazuh-connections/{id}` | Editar nombre, URL, usuario, contraseña |
| DELETE | `/wazuh-connections/{id}` | Eliminar + **borrar todos sus datos** |
| POST | `/wazuh-connections/{id}/test` | Probar conectividad → actualiza last_test_ok |
| POST | `/wazuh-connections/{id}/sync` | Lanza sync **en segundo plano** → devuelve `job_id` |

#### Sincronización (segundo plano)
| Método | Ruta | Descripción |
|--------|------|-------------|
| POST | `/vulns/sync-all` | Lanza sync de todas las conexiones activas → `job_id` (400 si no hay activas) |
| GET | `/sync/status` | Progreso de un job (`?job_id=`); sin param. devuelve el más reciente o `idle` |

> La sincronización ya **no bloquea** la petición: corre en un hilo *daemon* y el
> frontend hace *polling* a `/sync/status` para mostrar la barra de progreso y un
> *toast* al terminar. Detalle en [`docs/entrega2-analisis-evolucion.md`](docs/entrega2-analisis-evolucion.md).

#### Vulnerabilidades
| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/vulns` | Lista **paginada y filtrada server-side** → `{ items, total, page, page_size, total_pages }` |
| GET | `/vulns/filter-options` | Opciones `DISTINCT` precalculadas (agents, cves, packages, severities) |
| GET | `/vulns/{id}/history` | Historial detallado de una vulnerabilidad puntual (bajo demanda) |
| GET | `/vulns/evolution/summary` | Resumen: activas, resueltas, assets, eventos, last_sync |
| GET | `/vulns/evolution/weekly` | Tendencia semanal (`time_bucket` TimescaleDB) |
| GET | `/vulns/evolution/top-assets` | Top N equipos más vulnerables |
| GET | `/vulns/evolution/timeline` | Línea de trazabilidad por bucket (nuevas/reemergidas/remediadas) — `sp_traceability_timeline` |
| GET | `/vulns/evolution/timeline-details` | Drill-down: registros de un bucket concreto (bajo demanda) |
| GET | `/vulns/evolution/traceability-summary` | Tarjetas: nuevas, persistentes, remediadas, total activas — `sp_traceability_summary` |

**Parámetros de `/vulns`:** `connection_id`, `agent_name`, `cve_id`,
`package_name`, `severity`, `status`, `score_min`, `score_max`, `search`,
`sort_by`, `sort_order`, `page`, `page_size`, `limit` (compat.).

#### Validación de contraseña (política)
```
✓ Mínimo 8 caracteres
✓ Al menos una mayúscula
✓ Al menos una minúscula
✓ Al menos un número
✓ Al menos un carácter especial (!@#$%^&*...)
```

---

## 6. Frontend — Arquitectura y Vistas

### Arquitectura por capas (Clean Architecture)

```
presentation/views/       → Componentes Vue (UI, lógica de presentación)
application/services/     → Casos de uso (llamadas a la API)
infrastructure/http/      → Detalles técnicos (Axios, interceptores)
```

### Flujo de autenticación completo

```
Usuario accede a cualquier ruta
        ↓
router.beforeEach()
        ↓
¿Hay token en localStorage?
    NO → /login
    SÍ → GET /users/me (valida token con backend)
              ↓
         ¿is_default_password?
            SÍ → fuerza /change-password
            NO → continúa a la ruta pedida
```

### `authInterceptor.js`
Intercepta **todas** las requests de Axios antes de enviarlas:
```javascript
config.headers.Authorization = `Bearer ${localStorage.getItem('token')}`
// Excepto: /auth/login (no tiene token aún)
```

### `apiClient.js`
```javascript
baseURL: import.meta.env.VITE_API_URL  // "/api" en producción / dev
```
En desarrollo, Vite hace proxy: `/api/*` → `http://localhost:8000/*`

### Vistas

#### `Login.vue`
- Formulario usuario/contraseña
- Llama `authService.login()` con `Content-Type: application/x-www-form-urlencoded`
- Guarda JWT en `localStorage.token`

#### `Dashboard.vue`
- Llama `GET /vulns/evolution/summary` → métricas principales
- Llama `GET /vulns/evolution/weekly` → gráfico de tendencia
- Llama `GET /vulns/evolution/top-assets` → tabla top equipos
- Llama `GET /vulns/evolution/traceability-summary` → tarjetas de trazabilidad
- Tabla de vulnerabilidades con **paginación server-side** (`GET /vulns`)
- **Barra de progreso** de sincronización + *toast* al terminar (`useSyncJob`)
- Filtros precargados vía `GET /vulns/filter-options`
- Muestra badge con fecha/hora del último sync

#### `Timeline.vue`
- Canvas interactivo HTML5 con la **línea de trazabilidad de amenazas**
- Datos por bucket desde `GET /vulns/evolution/timeline`
- **Drill-down** del modal bajo demanda (`GET /vulns/evolution/timeline-details`)
- Filtros por agente y CVE; barra de carga indeterminada
- Subcomponentes: `TimelineCanvas`, `TimelineFilters`, `TimelineKpiStrip`, `TimelineDetailModal`
- Helpers/composables: `useTimelineData.js`, `timelineFormatters.js`, `useTimelineNavigation.js`

#### Componentes y composables transversales (v1.1)
- `components/ToastHost.vue` + `composables/useToast.js` → notificaciones *toast*
- `composables/useSyncJob.js` → estado global del job de sync, *polling* a `/sync/status`
- `services/vulnService.js` → cliente dedicado de vulnerabilidades/evolución

#### `ConfigWazuh.vue`
- Lista todas las conexiones Wazuh
- Formulario para crear/editar conexión
- Botón **Probar** → `POST /wazuh-connections/{id}/test`
- Botón **Sincronizar** → `POST /wazuh-connections/{id}/sync`
- Botón **Eliminar** → elimina conexión y **todos sus datos**

#### `ConfigUser.vue`
- Lista usuarios del sistema
- Crear nuevo usuario (con contraseña temporal)
- Eliminar usuario (no puede eliminarse a sí mismo)

#### `ChangePassword.vue`
- Obligatorio en primer login (`is_default_password: true`)
- Valida política de contraseña en frontend y backend

---

## 7. Base de Datos — Esquema Relacional

```
users ──────────────────────────── user_interactions
  (id)                                (user_id FK)

wazuh_connections ──────────────── wazuh_vulnerabilities
  (id)                                (connection_id FK)
    │                                       │
    └── managers ──────── assets ───── vulnerability_detections
        (legacy_connection_id FK)  (manager_id FK)  (asset_id FK)
                                                           │
                                               vulnerability_catalog
                                                    (cve_id FK)

wazuh_vulnerabilities ──────────── vulnerability_history
  (id)                                (vulnerability_id FK)
```

### TimescaleDB en `vulnerability_detections`
```sql
SELECT create_hypertable('vulnerability_detections', 'timestamp');
-- Crea índice compuesto: (asset_id, timestamp DESC)
-- Crea índice compuesto: (cve_id, timestamp DESC)
-- Permite queries eficientes como:
SELECT time_bucket('1 week', timestamp), count(*)
FROM vulnerability_detections
WHERE status = 'Detected'
GROUP BY 1 ORDER BY 1;
```

### Objetos analíticos (v1.1) — `initialize_analytics_objects()`

Al arrancar, el backend crea (solo en PostgreSQL) los índices y procedimientos
almacenados que mueven la agregación pesada a la BD:

- **Índices** sobre `wazuh_vulnerabilities`: `idx_wv_conn_status`,
  `idx_wv_agent_name`, `idx_wv_cve`, `idx_wv_severity`, `idx_wv_last_seen`,
  `idx_wv_package_name` → aceleran los filtros server-side.
- **`sp_traceability_timeline(p_connection_id, p_bucket, p_start, p_end)`** →
  nuevas/reemergidas/remediadas por bucket (`time_bucket`).
- **`sp_traceability_summary(p_connection_id, p_new_window)`** →
  nuevas/persistentes/remediadas/total_activas.

> Bajo SQLite (tests) estos objetos no se crean y los endpoints usan rutas de
> *fallback* en ORM. Detalle completo en
> [`docs/entrega2-analisis-evolucion.md`](docs/entrega2-analisis-evolucion.md).

---

## 8. Docker Compose — Infraestructura

```yaml
services:
  db-api:      # TimescaleDB (PostgreSQL 15)
               # Puerto: solo interno (app-network)
               # Healthcheck: pg_isready

  api:         # FastAPI + Uvicorn
               # Puerto: 8000 (interno)
               # Espera: db-api healthy
               # DATABASE_URL apunta a db-api:5432

  frontend:    # Nginx sirviendo Vue build estático
               # Puertos: 18080:80 y 18443:443
               # Espera: api healthy
               # Proxy: /api/* → http://api:8000/*
```

Todos los servicios están en la red interna `app-network` (bridge).  
Solo el frontend expone puertos al host.

---

## 9. Seguridad

| Aspecto | Implementación | Detalles |
|---------|---------------|---------|
| Autenticación | JWT HS256 | Expira en 60 minutos |
| Contraseñas de usuarios | bcrypt | Hash con salt automático |
| Contraseñas Wazuh en BD | Fernet (AES-128-CBC + HMAC) | Cifrado simétrico |
| Política de contraseña | Validación en backend | 8+ chars, mayús, minús, número, especial |
| Primer login | Forzar cambio de clave | `is_default_password = True` |
| CORS | FastAPI middleware | Configurar origins en producción |
| SSL frontend | Nginx + cert autofirmado | Reemplazar con cert real en prod |
| SSL Wazuh | `verify=False` | Acepta certs autofirmados del Indexer |
| Eliminación en cascada | Al borrar conexión | Borra vulns, historial, assets, detecciones |

---

## 10. Herramientas DevSecOps

```
dev-tools/
├── jenkins/                   Pipeline CI/CD
│   ├── Dockerfile             Imagen Jenkins personalizada
│   ├── docker-compose.yml     Arranque del servidor Jenkins
│   └── scripts/
│       └── setup_jenkins_credentials.sh   Configura credenciales automáticamente
│
├── sonarqube/                 Análisis Estático (SAST)
│   └── sonar-project.properties          Configuración del proyecto
│
└── zap/                       Análisis Dinámico (DAST)
    └── docker-compose.yml     OWASP ZAP scanner
```

| Herramienta | Puerto | Función |
|-------------|--------|---------|
| **Jenkins** | 8080 | Ejecuta pipelines: build, test, análisis, deploy |
| **SonarQube** | 9000 | Detecta bugs, code smells, vulnerabilidades en código fuente |
| **OWASP ZAP** | — | Escanea la app en ejecución buscando vulnerabilidades web |

---

## 11. Variables de Entorno (`.env`)

```env
# ─── Base de Datos ────────────────────────────────
POSTGRES_USER=admin
POSTGRES_PASSWORD=adminpassword
POSTGRES_DB=vulnerabilidades_db

# ─── Backend ──────────────────────────────────────
DATABASE_URL=postgresql://admin:adminpassword@db-api:5432/vulnerabilidades_db
ENCRYPTION_KEY=<clave Fernet — generar con comando abajo>
JWT_SECRET=<string secreto para firmar JWT>

# ─── Frontend ─────────────────────────────────────
VITE_API_URL=/api

# ─── Puertos (opcional, tienen valores por defecto) ──
FRONTEND_HTTP_PORT=18080
FRONTEND_HTTPS_PORT=18443
```

**Generar ENCRYPTION_KEY:**
```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

**Generar JWT_SECRET:**
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

---

## 12. Comandos de Operación

### Docker (Producción)

```bash
# Levantar todo
docker compose up -d

# Ver estado
docker compose ps

# Ver logs en tiempo real
docker compose logs -f api
docker compose logs -f frontend

# Reiniciar solo el backend
docker compose restart api

# Parar todo
docker compose down

# Parar y borrar volúmenes (⚠️ borra la BD)
docker compose down -v
```

### Backend (Desarrollo local)

```bash
cd vuln-api
source venv/bin/activate          # Linux/Mac
# .\venv\Scripts\Activate.ps1     # Windows PowerShell

uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend (Desarrollo local)

```bash
cd frontend
npm run dev                        # http://localhost:5173
npm run build                      # Build para producción
npm run test                       # Correr tests
npm run coverage                   # Reporte de cobertura
```

### API — Ejemplos con curl

```bash
# Login
curl -X POST http://localhost:8000/auth/login \
  -d "username=admin&password=admin"

# Listar conexiones Wazuh
curl http://localhost:8000/wazuh-connections \
  -H "Authorization: Bearer <token>"

# Sincronizar conexión ID=1
curl -X POST http://localhost:8000/wazuh-connections/1/sync \
  -H "Authorization: Bearer <token>"

# Resumen del dashboard
curl http://localhost:8000/vulns/evolution/summary \
  -H "Authorization: Bearer <token>"
```

### Swagger UI (Documentación interactiva)

```
http://localhost:8000/docs
```

---

## 13. Instalación desde Cero

### Opción A — Docker (recomendado)

```bash
# 1. Clonar el repositorio
git clone <url-del-repo>
cd devsecops2

# 2. Crear el .env
cp .env.example .env   # (o crear manualmente con los valores del apartado 11)

# 3. Levantar
docker compose up -d

# 4. Acceder
# Frontend: http://localhost:18080
# API Docs: http://localhost:8000/docs (desde dentro del docker o exponer puerto)
```

### Opción B — Desarrollo local (Linux/Mac/WSL/Kali)

#### Requisitos previos
```bash
# Python 3.11+
python3 --version

# Node 18+
node --version

# PostgreSQL
sudo apt install -y postgresql postgresql-contrib  # Debian/Kali/Ubuntu
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

#### Base de Datos
```bash
sudo -u postgres psql
```
```sql
CREATE DATABASE vulnerabilidades_db;
ALTER USER postgres WITH PASSWORD 'postgres';
GRANT ALL PRIVILEGES ON DATABASE vulnerabilidades_db TO postgres;
\q
```

#### Backend
```bash
cd vuln-api

# Entorno virtual
python3 -m venv venv
source venv/bin/activate

# Dependencias
pip install -r requirements.txt

# Variables de entorno
cat > .env << 'EOF'
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/vulnerabilidades_db
ENCRYPTION_KEY=<tu clave Fernet>
JWT_SECRET=<tu secreto JWT>
EOF

# Migración (solo si la BD ya existía antes)
python3 - << 'EOF'
from app.db import engine
from sqlalchemy import text
with engine.connect() as conn:
    conn.execute(text("ALTER TABLE wazuh_connections ADD COLUMN IF NOT EXISTS last_sync_at TIMESTAMPTZ DEFAULT NULL"))
    conn.commit()
    print("Migración aplicada OK")
EOF

# Arrancar
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

#### Frontend
```bash
cd frontend

# Dependencias
npm install

# Variable de entorno
echo "VITE_API_URL=/api" > .env

# Arrancar
npm run dev   # http://localhost:5173
```

### Credenciales por defecto

| Campo | Valor |
|-------|-------|
| Usuario | `admin` |
| Contraseña | `admin` |

> ⚠️ **El sistema obliga a cambiar la contraseña en el primer login.**

---

## 14. Troubleshooting

| Error | Causa | Solución |
|-------|-------|----------|
| `ENCRYPTION_KEY no está definida` | Falta el `.env` o no tiene la variable | Crear `.env` con `ENCRYPTION_KEY=...` |
| `UnicodeDecodeError en psycopg2` | `DATABASE_URL` con caracteres especiales en el entorno del sistema | Usar `load_dotenv(override=True)` y limpiar variable del sistema |
| `400` al conectar Wazuh con contraseña con `ñ` | HTTPBasicAuth usa latin-1 | Usar `_basic_auth_header()` con UTF-8 base64 ✅ ya implementado |
| Solo trae 10.000 vulns | Límite hard-coded del índice OpenSearch | Usar `search_after` ✅ ya implementado |
| `vite: command not found` | No se ejecutó `npm install` | Correr `npm install` antes de `npm run dev` |
| Frontend no llega al backend | `VITE_API_URL` no configurada | Crear `frontend/.env` con `VITE_API_URL=/api` |
| `pg_isready` falla en Docker | BD aún inicializando | Docker compose espera automáticamente (healthcheck) |

---

*Documentación generada el 2026-05-11 — actualizada el 2026-05-28 (v1.1, Entrega 2).*

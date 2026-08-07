# Modelo de datos escalable + revisión de seguridad

> **Entrega:** rediseño completo de la base de datos, filtros nuevos y dashboard analítico.
> **Fecha:** 2026-08-06 · **Autor:** Ariel Pinochet

---

## 1. Por qué se rehízo el modelo

El modelo anterior tenía **dos representaciones paralelas de los mismos datos**, unidas
por un puente artificial. Eso es lo que hacía el diagrama confuso y lo que producía la
sensación de "id repetida":

```
ANTES  (dos mundos + un puente)

  wazuh_connections ─┐                    managers ──< assets ──< vulnerability_detections
   (id serial)       │                    (id uuid)   (id uuid)   (event_id uuid, timestamp)
                     │                        ▲
                     └── legacy_connection_id ┘        wazuh_vulnerabilities
                             (puente)                  (id serial, agent_id, agent_name,
                                                        os_*, package_*, cve_id, severity,
                                                        description, ...)
```

Problemas concretos:

| # | Problema | Consecuencia |
|---|----------|--------------|
| 1 | `wazuh_connections` y `managers` describían **la misma entidad** con dos ids distintos (`serial` y `uuid`) unidos por `legacy_connection_id`. | Dos identificadores para un mismo manager. Toda consulta necesitaba el puente. |
| 2 | El agente vivía en `assets.wazuh_agent_id` **y** en `wazuh_vulnerabilities.agent_id`/`agent_name`. | El mismo hostname repetido en decenas de miles de filas; renombrar un agente dejaba datos inconsistentes. |
| 3 | Paquete y S.O. eran **texto repetido** en `wazuh_vulnerabilities` y otra vez en `vulnerability_detections`. | ~20.000 filas × 4 columnas de texto duplicadas. Sin tabla de paquetes no había forma de listarlos. |
| 4 | La severidad estaba en `vulnerability_catalog.severity` **y** en `wazuh_vulnerabilities.severity`. | Dos fuentes de verdad que podían discrepar. |
| 5 | `vulnerability_detections.event_id` era un **UUID nuevo por evento**. | Re-sincronizar el mismo documento insertaba filas duplicadas: la tabla crecía sin tope. |
| 6 | No existía nada para **grupos de agentes**. | El filtro por grupos era imposible. |
| 7 | La criticidad solo existía como texto. | Filtrar/ordenar por criticidad exigía un `CASE` en cada consulta, sin índice. |

---

## 2. Modelo nuevo (esquema en estrella)

```mermaid
erDiagram
    wazuh_connections  ||--o{ assets            : "monitorea"
    wazuh_connections  ||--o{ agent_groups      : "define"
    assets             }o--o{ agent_groups      : "asset_group_members"
    operating_systems  ||--o{ assets            : "corre"
    assets             ||--o{ vulnerability_findings : "presenta"
    vulnerability_catalog ||--o{ vulnerability_findings : "clasifica"
    packages           ||--o{ vulnerability_findings : "afecta"
    vulnerability_findings ||--o{ finding_history : "registra"
    vulnerability_findings ||--o{ vulnerability_detections : "genera"
    users              ||--o{ user_interactions : "audita"

    wazuh_connections {
        int     id PK
        string  name UK
        string  indexer_url
        string  wazuh_user
        string  wazuh_password "cifrado en reposo"
        bool    is_active
        ts      last_sync_at
    }
    agent_groups {
        int    id PK
        int    connection_id FK
        string name "UK(connection_id,name)"
    }
    operating_systems {
        int    id PK
        string platform
        string version
        string full "UK(platform,version,full)"
    }
    assets {
        bigint id PK
        int    connection_id FK
        string wazuh_agent_id "UK(connection_id,wazuh_agent_id)"
        string hostname
        inet   ip_address
        int    os_id FK
    }
    asset_group_members {
        bigint asset_id PK_FK
        int    group_id PK_FK
    }
    packages {
        bigint id PK
        string name
        string version
        string type
        string architecture "UK(name,version,type,architecture)"
    }
    vulnerability_catalog {
        string   cve_id PK
        string   severity
        smallint severity_rank "0..4 · criticidad numérica indexada"
        numeric  cvss_score
        text     description
        ts       published_at
    }
    vulnerability_findings {
        bigint  id PK
        bigint  asset_id FK
        string  cve_id FK
        bigint  package_id FK "UK(asset_id,cve_id,package_id)"
        string  status "ACTIVE | RESOLVED"
        numeric score_base
        ts      first_seen
        ts      last_seen
        ts      resolved_at
    }
    finding_history {
        bigint id PK
        bigint finding_id FK
        string action
        ts     timestamp
    }
    vulnerability_detections {
        ts     timestamp PK "hypertable TimescaleDB"
        bigint finding_id PK_FK
        string status "Detected | Re-emerged | Resolved"
    }
```

### Cómo se resuelve cada problema

| Problema | Solución |
|----------|----------|
| 1 · manager duplicado | **`managers` desaparece.** `wazuh_connections` es la única representación del manager y `assets.connection_id` apunta directo a ella. Se eliminó `legacy_connection_id`. |
| 2 · agente duplicado | El agente existe **solo** en `assets`. Los hallazgos lo referencian por `asset_id`. |
| 3 · paquete/S.O. duplicados | Tablas dimensión **`packages`** y **`operating_systems`**, una fila por valor único, referenciadas por FK. |
| 4 · severidad duplicada | La criticidad vive **solo** en `vulnerability_catalog`. El hallazgo guarda el `score_base` observado en ese equipo, que es un dato distinto. |
| 5 · eventos duplicados | La PK de eventos es **`(finding_id, timestamp)`**: reinsertar el mismo evento es idempotente (`ON CONFLICT DO NOTHING`). |
| 6 · sin grupos | **`agent_groups`** + **`asset_group_members`** (N:M, un agente Wazuh puede estar en varios grupos). |
| 7 · criticidad no filtrable | **`severity_rank SMALLINT`** (0–4) indexado, más `cvss_score` numérico indexado. |

### Qué lo hace escalable

- **Un solo camino entre dos entidades.** No hay puentes ni caminos alternativos, así que el
  planificador siempre elige el mismo plan y los índices sirven de verdad.
- **Los textos largos no se repiten.** Cada nombre de paquete, versión de S.O. y descripción de
  CVE se guarda una vez. Con 20k hallazgos eso son megabytes, no gigabytes.
- **Ids enteros en vez de UUID en texto.** `assets` y `vulnerability_findings` pasaron de
  `VARCHAR(36)` a `BIGINT`: índices ~4× más pequeños y joins más rápidos.
- **La tabla que más crece está particionada.** `vulnerability_detections` es hypertable de
  TimescaleDB por `timestamp` y ya no repite CVE/paquete/asset en cada evento.
- **Crecer no exige tocar el esquema.** Un manager nuevo, un grupo nuevo o un S.O. nuevo son
  filas, no columnas.
- **Vocabularios con `CHECK`, no `ENUM` nativo.** Agregar un estado es un `ALTER ... CHECK` sin
  reescribir el tipo ni bloquear la tabla.

---

## 3. Migración desde el modelo anterior

Las migraciones son **versionadas e idempotentes** (`app/migrations.py`), se registran en
`schema_migrations` y corren solas al arrancar la API, en dos fases:

| Versión | Fase | Qué hace |
|---------|------|----------|
| `001_rename_legacy_schema` | antes de `create_all` | Renombra el esquema antiguo a `legacy_*` para dejar sitio a las tablas nuevas. |
| `002_migrate_legacy_data` | después de `create_all` | Copia los datos de `legacy_*` al modelo nuevo, deduplicando dimensiones. |

**No se borra nada.** Las tablas antiguas quedan como `legacy_managers`, `legacy_assets`,
`legacy_wazuh_vulnerabilities`, `legacy_vulnerability_history`, `legacy_vulnerability_catalog`
y `legacy_vulnerability_detections`. Una vez validada la migración se pueden eliminar a mano:

```bash
docker compose exec db-api psql -U admin -d vulnerabilidades_db -c "DROP TABLE IF EXISTS legacy_vulnerability_detections, legacy_vulnerability_history, legacy_wazuh_vulnerabilities, legacy_assets, legacy_managers, legacy_vulnerability_catalog CASCADE"
```

Detalle del remapeo:

- `legacy_wazuh_vulnerabilities` es la fuente principal: de ahí salen las dimensiones
  (`DISTINCT` sobre S.O., paquete y CVE) y un hallazgo por fila.
- Los grupos **no se pueden reconstruir**: el modelo antiguo no los guardaba. Se poblarán en la
  siguiente sincronización, cuando se lean de `agent.groups`.
- La bitácora y los eventos se remapean por `(asset, CVE, paquete)` a su nuevo `finding_id`.
- Al terminar se reajustan las secuencias con `setval`.

---

## 4. Revisión de seguridad de los procedimientos almacenados

Los 14 procedimientos viven en `app/analytics.py` y se recrean al arrancar.

### 4.1 Controles aplicados

| # | Control | Riesgo que mitiga |
|---|---------|-------------------|
| 1 | **`SECURITY INVOKER`** explícito en las 14 funciones. | Escalada de privilegios. Con `SECURITY DEFINER` la función correría como su dueño y cualquier rol con `EXECUTE` heredaría esos permisos. |
| 2 | **`SET search_path = pg_catalog, public`** en la definición. | Secuestro de `search_path` (familia CVE-2018-1058): sin esto, un atacante que pueda crear objetos en un esquema anterior del path logra que la función llame *su* versión de una tabla u operador. |
| 3 | **`LANGUAGE sql` con parámetros tipados**, sin SQL dinámico ni concatenación. | Inyección SQL. No hay `EXECUTE`, ni `format()`, ni cadenas construidas: los parámetros son valores, nunca fragmentos de consulta. |
| 4 | **Lista blanca dentro de la función** para el único parámetro de texto que llega a una función del sistema: `date_trunc(CASE WHEN p_unit IN ('hour','day','week','month','quarter','year') THEN p_unit ELSE 'month' END, ...)`. | Un valor inesperado provoca un error de PostgreSQL en vez de degradar la consulta; el `CASE` lo normaliza a `month`. |
| 5 | **`STABLE`** en todas. | Escritura accidental o maliciosa: PostgreSQL rechaza cualquier `INSERT`/`UPDATE`/`DELETE` dentro de una función `STABLE`. |
| 6 | **`REVOKE ALL ... FROM PUBLIC` + `GRANT EXECUTE TO CURRENT_USER`.** | Por defecto PostgreSQL otorga `EXECUTE` a `PUBLIC`. Sin el `REVOKE`, cualquier rol de la base podría ejecutarlas. |
| 7 | **Límites acotados en SQL**: `LIMIT greatest(1, least(coalesce(p_limit, N), MAX))`. | DoS por `LIMIT` gigante o negativo enviado desde el cliente. El tope se aplica en la BD, no solo en la API. |
| 8 | **Ninguna función lee columnas sensibles.** No se toca `wazuh_connections.wazuh_password` ni `users.password_hash`; no se usa `SELECT *`. | Fuga de credenciales por una consulta analítica. |
| 9 | **Notación nombrada al invocar** (`p_connection_id => :p_connection_id`). | Pasar un valor a la posición equivocada al agregar un parámetro. |
| 10 | **Parámetros `INTEGER`, no `SMALLINT`.** | Fallos de resolución de función (`function does not exist`) cuando el cliente envía un `int4`. |

### 4.2 Inventario

| Procedimiento | Uso | Parámetros |
|---------------|-----|-----------|
| `sp_filter_groups` | Filtro por **grupos** | `p_connection_id` |
| `sp_filter_operating_systems` | Filtro por **S.O.** | `p_connection_id` |
| `sp_filter_severities` | Filtro por **criticidad** (+ rango de score) | `p_connection_id` |
| `sp_filter_agents` | Filtro por agente | `p_connection_id` |
| `sp_filter_packages` | Filtro por paquete | `p_connection_id, p_search, p_limit` |
| `sp_filter_cves` | Filtro por CVE | `p_connection_id, p_search, p_limit` |
| `sp_package_inventory` | **Tabla de paquetes** | `p_connection_id, p_search, p_min_rank, p_limit, p_offset` |
| `sp_traceability_timeline` | Línea temporal **por mes** | `p_connection_id, p_unit, p_start, p_end` |
| `sp_traceability_summary` | Nuevas / persistentes / remediadas | `p_connection_id, p_new_window` |
| `sp_status_breakdown` | Torta **resueltas vs. activas** | `p_connection_id, p_group_id, p_min_rank` |
| `sp_new_unresolved_ratio` | **% nuevas del año sin corregir** | `p_connection_id, p_year` |
| `sp_critical_coverage` | **% agentes y grupos con críticas** | `p_connection_id, p_min_rank` |
| `sp_critical_histogram` | **Histograma de agentes críticos** | `p_connection_id, p_min_rank, p_limit` |
| `sp_group_risk` | Riesgo agregado por grupo | `p_connection_id, p_min_rank, p_limit` |

### 4.3 Hallazgos abiertos (fuera del alcance de esta entrega)

Se detectaron durante la revisión y **no** están corregidos aquí:

1. `CORS` permite `allow_origins=["*"]` junto con `allow_credentials=True` (`main.py`).
2. `wazuh_client.py` usa `verify=False`: no valida el certificado TLS del indexador.
3. `auth.py` usa `datetime.utcnow()` (deprecado) y un `JWT_SECRET` con valor por defecto
   (`"dev-secret-key"`) si falta la variable de entorno.
4. No hay control de roles: cualquier usuario autenticado puede crear y borrar usuarios y
   conexiones.
5. `POST /users` no aplica `validate_strong_password`, que sí se aplica al cambiar contraseña.

---

## 5. Cambios en la API

### Filtros nuevos en `GET /vulns` y `GET /vulns/evolution/threats`

| Parámetro | Ejemplo | Qué hace |
|-----------|---------|----------|
| `status` | `resuelta`, `no_resuelta`, `RESOLVED`, `ACTIVE` | **Filtro por resueltas / no resueltas.** Acepta alias en español e inglés. |
| `score_min` / `score_max` | `score_min=7&score_max=10` | **Filtro por puntaje numérico** de criticidad (CVSS base). |
| `rank_min` | `rank_min=4` | Criticidad como nivel numérico (0 Unknown … 4 Critical). |
| `group` / `group_id` | `group=web,db` | **Filtro por grupos** de agentes. |
| `os_platform` / `os_version` | `os_platform=ubuntu` | Filtro por sistema operativo. |
| `package_name` | `package_name=openssl` | Filtro por paquete. |

### Periodos: de días a meses

`_PERIOD_CONFIG` pasó de `24h/7d/30d/90d` a **`1m/3m/6m/12m/24m/all`**, con `12m` por defecto.
Los valores antiguos se siguen aceptando y se traducen al mes más cercano, para no romper
clientes existentes.

### Endpoints nuevos

| Método | Ruta | Devuelve |
|--------|------|----------|
| GET | `/vulns/packages` | Tabla de paquetes vulnerables (paginada). |
| GET | `/vulns/evolution/monthly` | Tendencia mensual (reemplaza `/evolution/weekly`). |
| GET | `/vulns/dashboard/status-breakdown` | Activas vs. resueltas + porcentajes. |
| GET | `/vulns/dashboard/new-unresolved` | % de las nuevas del año que siguen sin corregir. |
| GET | `/vulns/dashboard/critical-coverage` | % de agentes y de grupos con al menos una crítica. |
| GET | `/vulns/dashboard/critical-histogram` | Agentes con ≥1 crítica y su conteo. |
| GET | `/vulns/dashboard/group-risk` | Riesgo agregado por grupo. |

`GET /vulns/evolution/threats` agrega `resolved_at` por amenaza y un bloque
`coverage.since` con el instante desde el cual hay datos.

---

## 6. Cambios en el frontend

### Línea de tiempo: verde, blanco y gris

Cada barra del Gantt se divide en tramos según lo que **consta** en la base:

| Tramo | Color | Significado |
|-------|-------|-------------|
| `unknown` | gris rayado | Todavía no había sincronizaciones: no sabemos si existía. |
| `absent` | **blanco** | Hubo sincronización y la vulnerabilidad **no existía**. |
| `active` | color por severidad | Detectada y sin remediar. |
| `resolved` | **verde** | Ya remediada. |

El blanco solo se pinta cuando `coverage.since` demuestra que hubo una sincronización previa a
la detección. Si no hay datos anteriores el tramo se marca gris ("sin datos") en vez de afirmar
que la vulnerabilidad no existía — que es justo lo que pedía el requisito.

### Dashboard

- **Tortas** (`DonutChart.vue`, SVG puro, sin dependencias nuevas):
  resueltas/activas · % nuevas del año sin corregir (con selector de año) ·
  % de agentes y % de grupos con críticas.
- **Histogramas** (`HistogramChart.vue`): agentes con al menos una vulnerabilidad crítica y
  riesgo por grupo.
- **Filtros nuevos**: grupos, sistema operativo y estado (resueltas / no resueltas), sumados a
  los ya existentes de agente, CVE, paquete, severidad y rango de score CVSS.
- **Tendencia mensual** en lugar de semanal.
- En la tabla, las vulnerabilidades resueltas muestran su tramo final **en verde** y el rótulo
  pasa de "Última actividad" a "Resuelta".

---

## 7. Pruebas

| Suite | Resultado |
|-------|-----------|
| Backend (`vuln-api/tests/`) | **72 pruebas** — ingesta al modelo nuevo, no duplicación de dimensiones, filtros por estado/score/rank/grupo/S.O., tabla de paquetes, los cuatro endpoints de dashboard, periodos en meses y compatibilidad con periodos en días. |
| Frontend (`frontend/tests/`) | **226 pruebas** — incluye specs nuevas de `DonutChart`, `HistogramChart`, los tramos verde/blanco/gris del Gantt y los filtros nuevos. |

> `Dashboard.spec.js` estaba obsoleto desde antes de esta entrega (probaba una API
> `syncVulns`/`syncing` que ya no existía y una respuesta sin paginar). Se reescribió contra el
> componente real.

### Verificación contra PostgreSQL + TimescaleDB real

Las pruebas unitarias corren sobre SQLite, donde la API usa las rutas equivalentes en ORM. Los
procedimientos almacenados y las migraciones se verificaron **aparte, contra un contenedor
`timescale/timescaledb:latest-pg15`**, con dos escenarios:

**A · Base nueva.** Se comprobó que arrancan los 14 procedimientos, que
`vulnerability_detections` queda como hypertable y que todos los endpoints devuelven los
valores esperados usando los SP (grupos, S.O., criticidad, paquetes, las cuatro métricas del
dashboard, periodos mensuales y la traducción de periodos en días). También que reinsertar el
mismo evento **no** crea duplicados, gracias a la PK `(finding_id, timestamp)`.

**B · Base con el esquema antiguo.** Se reprodujo el modelo anterior completo (con `managers`,
`legacy_connection_id`, hypertable de `event_id` y datos) y se arrancó la API encima. Resultado:
las dos migraciones se aplican, las seis tablas antiguas quedan como respaldo `legacy_*`, los 4
hallazgos / 5 eventos / 5 entradas de bitácora se copian sin huérfanos, las dimensiones se
deduplican (openssl aparecía en dos filas y queda en una sola), `severity_rank` se calcula bien
y volver a ejecutar las migraciones no duplica nada.

Consulta de auditoría usada para el punto 4.1 (los 14 SP, sin excepciones):

```sql
SELECT proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'public' AND proname LIKE 'sp\_%'
  AND (prosecdef                                             -- SECURITY DEFINER
       OR proconfig IS NULL                                  -- sin search_path fijo
       OR NOT ('search_path=pg_catalog, public' = ANY(proconfig))
       OR provolatile <> 's'                                 -- no STABLE
       OR has_function_privilege('public', p.oid, 'EXECUTE')); -- abierto a PUBLIC
```

> Nota: el `_` de `LIKE 'sp_%'` es comodín en SQL. Hay que escaparlo (`'sp\_%'`) o la consulta
> también recoge funciones de TimescaleDB como `split_chunk` y reporta falsos positivos.

Bug encontrado y corregido gracias a esta verificación: `full` es palabra reservada en
PostgreSQL (`FULL JOIN`) y rompía el `INSERT` de `operating_systems` en la migración; ahora va
entrecomillada en todo el SQL crudo.

Al levantar el stack real deben aparecer en el log `[migrations] aplicada
001_rename_legacy_schema` y `[migrations] aplicada 002_migrate_legacy_data`, y **no** debe
aparecer `No se pudieron crear objetos analíticos`:

```bash
docker compose up -d db-api api && docker compose logs -f api
```

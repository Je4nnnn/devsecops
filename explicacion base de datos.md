# Explicacion de la base de datos

Este documento explica como esta organizada la base de datos del proyecto, como se conecta con Wazuh, donde entra TimescaleDB, que tablas existen, como se guardan las vulnerabilidades y si se usan procedimientos almacenados en los filtros de la aplicacion.

La idea principal es que la aplicacion no guarda solamente una lista plana de vulnerabilidades. Guarda dos tipos de informacion:

1. El estado actual de cada vulnerabilidad por agente, paquete y CVE.
2. El historial temporal de detecciones, resoluciones y reapariciones.

Por eso se usa PostgreSQL con TimescaleDB: PostgreSQL entrega el modelo relacional normal, y TimescaleDB optimiza la tabla que funciona como serie de tiempo.

## Resumen rapido

La base de datos corre en el servicio Docker `db-api`.

En `docker-compose.yml` se define asi:

```yaml
db-api:
  image: timescale/timescaledb:latest-pg15
  command: ["postgres", "-c", "shared_preload_libraries=timescaledb"]
```

Esto significa:

- La base es PostgreSQL 15.
- La imagen ya incluye TimescaleDB.
- `shared_preload_libraries=timescaledb` carga TimescaleDB al iniciar PostgreSQL.
- El backend se conecta por la variable `DATABASE_URL`.
- El volumen `postgres_api_data` mantiene los datos aunque se reinicien los contenedores.

La API construye el esquema principal desde los modelos SQLAlchemy en `vuln-api/app/models.py`. Al arrancar, `vuln-api/app/main.py` ejecuta:

```python
Base.metadata.create_all(bind=engine)
initialize_timescale_storage()
initialize_analytics_objects()
```

Eso hace tres cosas:

1. Crea las tablas si no existen.
2. Activa TimescaleDB y convierte `vulnerability_detections` en hypertable.
3. Crea indices y funciones SQL para consultas analiticas.

## Como se conecta la aplicacion a la base

El archivo `vuln-api/app/db.py` lee `DATABASE_URL` desde las variables de entorno:

```python
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
```

En Docker Compose, la API recibe:

```yaml
DATABASE_URL: postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@db-api:5432/${POSTGRES_DB}
```

En simple:

- `api` no se conecta a `localhost`.
- `api` se conecta al hostname Docker `db-api`.
- El puerto interno es `5432`.
- El usuario, password y nombre de base vienen desde `.env`.

Cada endpoint que necesita base de datos usa `get_db()`, que abre una sesion SQLAlchemy y la cierra al terminar la peticion.

## Como se crea el esquema

Hay dos fuentes importantes:

- `vuln-api/app/models.py`: define las tablas reales de la aplicacion.
- `vuln-api/app/main.py`: crea extensiones, hypertable, indices y funciones SQL.

El archivo `db-init/10-init.sql` actualmente solo crea una base llamada `sonarqube`:

```sql
CREATE DATABASE sonarqube;
```

Ese archivo no define las tablas de la aplicacion de vulnerabilidades. Las tablas de la aplicacion se crean desde SQLAlchemy con `Base.metadata.create_all(bind=engine)`.

El archivo `db-init/20-add-last-sync-at.sql` es una migracion puntual para agregar `last_sync_at` a `wazuh_connections` en bases existentes:

```sql
ALTER TABLE wazuh_connections
  ADD COLUMN IF NOT EXISTS last_sync_at TIMESTAMPTZ DEFAULT NULL;
```

## Diagrama general

La relacion principal se puede ver asi:

```text
users ─────────────────────────── user_interactions
  id                                user_id

wazuh_connections ─────────────── wazuh_vulnerabilities
  id                                connection_id
  │
  └── managers ─────── assets ───── vulnerability_detections
        id              id           asset_id
        │               │            cve_id
        │               │
        │               └────────── vulnerability_catalog
        │                              cve_id
        │
        └ legacy_connection_id

wazuh_vulnerabilities ─────────── vulnerability_history
  id                                vulnerability_id
```

Hay dos caminos relacionados con vulnerabilidades:

- `wazuh_vulnerabilities`: estado actual de cada vulnerabilidad.
- `vulnerability_detections`: eventos historicos en el tiempo.

Eso es importante porque una vulnerabilidad puede estar activa hoy, resolverse manana y reaparecer despues. La tabla de estado actual dice como esta ahora. La tabla historica permite reconstruir la evolucion.

## Tablas de usuarios

### `users`

Guarda usuarios que pueden entrar a la aplicacion.

Campos principales:

| Campo | Para que sirve |
|-------|----------------|
| `id` | Identificador interno |
| `username` | Nombre de usuario unico |
| `password_hash` | Password hasheada, no se guarda la password en texto plano |
| `is_active` | Indica si el usuario esta activo |
| `is_default_password` | Indica si aun usa password temporal |
| `created_at` | Fecha de creacion |

Al iniciar la API se crea un usuario admin por defecto si no existe:

```text
username = admin
password = admin
```

Despues el flujo obliga a cambiar la password si `is_default_password` sigue activo.

### `user_interactions`

Guarda interacciones de usuarios con endpoints. En el modelo existe la relacion con `users`, aunque no es la tabla central del analisis de vulnerabilidades.

Campos principales:

| Campo | Para que sirve |
|-------|----------------|
| `id` | Identificador |
| `user_id` | Usuario asociado |
| `endpoint` | Endpoint usado |
| `method` | Metodo HTTP |
| `details` | Detalles opcionales |
| `timestamp` | Fecha de la interaccion |

## Tablas de configuracion Wazuh

### `wazuh_connections`

Representa una conexion configurada hacia un Wazuh Indexer.

Campos principales:

| Campo | Para que sirve |
|-------|----------------|
| `id` | Identificador de la conexion |
| `name` | Nombre visible de la conexion |
| `indexer_url` | URL del Wazuh Indexer |
| `wazuh_user` | Usuario de Wazuh |
| `wazuh_password` | Password cifrada |
| `is_active` | Permite activar/desactivar la conexion |
| `tested` | Indica si se probo la conexion |
| `last_tested_at` | Ultima prueba de conexion |
| `last_test_ok` | Resultado de la ultima prueba |
| `last_sync_at` | Ultima sincronizacion exitosa |

La aplicacion usa esta tabla para saber desde que Wazuh Indexer traer datos. Cuando se crea una conexion, primero se prueba contra Wazuh. Si falla, no se guarda.

### `managers`

Es una capa de normalizacion para representar el origen o manager Wazuh.

Campos principales:

| Campo | Para que sirve |
|-------|----------------|
| `id` | UUID del manager |
| `nombre` | Nombre del manager |
| `api_url` | URL asociada |
| `api_key_vault_ref` | Referencia logica al secreto |
| `legacy_connection_id` | Relacion con `wazuh_connections.id` |
| `created_at` | Fecha de creacion |

En la practica, `legacy_connection_id` conecta el modelo nuevo (`managers`, `assets`, `vulnerability_detections`) con la configuracion antigua o directa de Wazuh (`wazuh_connections`).

## Tablas de activos y catalogo

### `assets`

Representa un equipo/agente Wazuh monitoreado.

Campos principales:

| Campo | Para que sirve |
|-------|----------------|
| `id` | UUID del asset |
| `wazuh_agent_id` | ID del agente en Wazuh |
| `hostname` | Nombre del equipo |
| `os_version` | Sistema operativo/version |
| `ip_address` | IP del agente |
| `manager_id` | Manager al que pertenece |

Tiene una restriccion unica:

```text
(manager_id, wazuh_agent_id)
```

Eso evita duplicar el mismo agente dentro del mismo manager.

### `vulnerability_catalog`

Es el catalogo global de CVEs.

Campos principales:

| Campo | Para que sirve |
|-------|----------------|
| `cve_id` | CVE, por ejemplo `CVE-2024-1234` |
| `severity` | Severidad normalizada: `Low`, `Medium`, `High`, `Critical` |
| `description` | Descripcion |
| `cvss_score` | Score CVSS |

La idea es que el CVE exista una sola vez en el catalogo, aunque aparezca en muchos agentes o paquetes.

## Tabla de estado actual

### `wazuh_vulnerabilities`

Esta es la tabla principal para ver el inventario actual de vulnerabilidades.

Cada fila representa una vulnerabilidad unica para:

```text
connection_id + agent_id + package_name + package_version + cve_id
```

Esa combinacion tiene una restriccion unica llamada `uniq_wazuh_vuln`.

Campos principales:

| Campo | Para que sirve |
|-------|----------------|
| `id` | Identificador interno |
| `connection_id` | Conexion Wazuh |
| `status` | Estado actual: `ACTIVE` o `RESOLVED` |
| `agent_id` | ID del agente Wazuh |
| `agent_name` | Nombre del agente |
| `os_full`, `os_platform`, `os_version` | Datos del sistema operativo |
| `package_name` | Paquete vulnerable |
| `package_version` | Version vulnerable |
| `package_type` | Tipo de paquete |
| `package_arch` | Arquitectura |
| `cve_id` | CVE detectado |
| `severity` | Severidad reportada |
| `score_base` | Score base |
| `score_version` | Version de score |
| `detected_at` | Fecha reportada por Wazuh |
| `published_at` | Fecha de publicacion del CVE |
| `description` | Descripcion |
| `reference` | Referencia |
| `scanner_vendor` | Scanner que reporto |
| `first_seen` | Primera vez que la app la vio |
| `last_seen` | Ultima vez que la app la vio |

Esta tabla responde preguntas como:

- Que vulnerabilidades estan activas ahora.
- Que vulnerabilidades ya estan resueltas.
- Que agente tiene mas CVEs activos.
- Que CVEs se ven en un agente especifico.
- Cual fue la ultima vez que se vio una vulnerabilidad.

Por eso los filtros principales del dashboard trabajan sobre esta tabla.

## Tabla historica con TimescaleDB

### `vulnerability_detections`

Esta tabla guarda eventos historicos. Es la tabla convertida en hypertable de TimescaleDB.

Campos principales:

| Campo | Para que sirve |
|-------|----------------|
| `event_id` | UUID del evento |
| `timestamp` | Fecha del evento; tambien es la columna temporal de TimescaleDB |
| `asset_id` | Agente/asset afectado |
| `cve_id` | CVE |
| `status` | Evento: `Detected`, `Resolved`, `Re-emerged` |
| `package_name` | Paquete |
| `package_version` | Version |

La clave primaria es compuesta:

```text
event_id + timestamp
```

Esto calza con TimescaleDB porque la columna temporal debe formar parte de la organizacion de la hypertable.

Esta tabla no representa solo el estado actual. Representa eventos en el tiempo:

- `Detected`: la vulnerabilidad fue observada en una sincronizacion.
- `Resolved`: antes estaba activa, pero Wazuh ya no la reporta.
- `Re-emerged`: estaba resuelta, pero volvio a aparecer.

## Que es TimescaleDB

TimescaleDB es una extension de PostgreSQL optimizada para datos de series de tiempo.

Una serie de tiempo es un conjunto de registros donde la fecha es parte central del analisis. En este proyecto aplica porque cada sincronizacion con Wazuh genera eventos con `timestamp`.

Ejemplos de preguntas temporales:

- Cuantas vulnerabilidades nuevas aparecieron por semana.
- Cuantas se remediaron en los ultimos 30 dias.
- Que CVEs reaparecieron en una ventana de tiempo.
- Como evoluciono el total de detecciones en el tiempo.

PostgreSQL normal podria guardar esos datos, pero TimescaleDB mejora la organizacion y las consultas temporales usando hypertables y funciones como `time_bucket`.

## Que es una hypertable

Una hypertable es una tabla logica de TimescaleDB que internamente se divide en partes mas pequenas llamadas chunks.

Para la aplicacion, se consulta como una tabla normal:

```sql
SELECT * FROM vulnerability_detections;
```

Pero internamente TimescaleDB organiza los datos por tiempo usando la columna `timestamp`. Eso ayuda cuando la tabla crece mucho, porque las consultas por rangos de fecha pueden tocar solo los chunks necesarios.

En este proyecto la hypertable se crea en `initialize_timescale_storage()`:

```sql
CREATE EXTENSION IF NOT EXISTS timescaledb;

SELECT create_hypertable(
    'vulnerability_detections',
    'timestamp',
    if_not_exists => TRUE,
    migrate_data => TRUE
);
```

Tambien se crean indices:

```sql
CREATE INDEX IF NOT EXISTS idx_vuln_detections_asset_time
ON vulnerability_detections (asset_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_vuln_detections_cve_time
ON vulnerability_detections (cve_id, timestamp DESC);
```

Esos indices ayudan cuando se filtra por asset/CVE y se ordena o agrupa por tiempo.

## `time_bucket`

`time_bucket` es una funcion de TimescaleDB que agrupa eventos por ventanas de tiempo.

Ejemplo:

```sql
SELECT
  time_bucket('1 week', timestamp) AS semana,
  count(*) AS total
FROM vulnerability_detections
GROUP BY semana
ORDER BY semana;
```

Eso agrupa todos los eventos por semana. La app lo usa para construir graficos de evolucion.

## Tabla de historial por vulnerabilidad

### `vulnerability_history`

Esta tabla guarda cambios relevantes de una vulnerabilidad especifica en `wazuh_vulnerabilities`.

Campos principales:

| Campo | Para que sirve |
|-------|----------------|
| `id` | Identificador |
| `vulnerability_id` | Vulnerabilidad asociada |
| `action` | Accion: `DETECTED`, `RESOLVED`, `REOPENED`, `SEVERITY_CHANGED` |
| `details` | Detalle textual |
| `timestamp` | Fecha |

Diferencia con `vulnerability_detections`:

- `vulnerability_detections` sirve para analitica temporal y graficos.
- `vulnerability_history` sirve para explicar la historia de una vulnerabilidad puntual.

Por ejemplo, al abrir el detalle de una vulnerabilidad en la linea de tiempo, la app puede pedir su historial con:

```text
GET /vulns/{id}/history
```

## Flujo de sincronizacion con Wazuh

La sincronizacion se activa desde:

```text
POST /wazuh-connections/{id}/sync
POST /vulns/sync-all
```

El flujo es:

1. El frontend solicita sincronizar una conexion o todas.
2. El backend crea un job en memoria con `job_id`.
3. El backend descarga vulnerabilidades desde Wazuh Indexer.
4. Wazuh devuelve documentos desde el indice:

```text
wazuh-states-vulnerabilities-*/_search
```

5. El backend procesa cada documento.
6. Se crea o actualiza el `manager`.
7. Se crea o actualiza el `asset`.
8. Se crea o actualiza el CVE en `vulnerability_catalog`.
9. Se crea o actualiza el estado actual en `wazuh_vulnerabilities`.
10. Se registra un evento temporal en `vulnerability_detections`.
11. Si una vulnerabilidad antes activa ya no llega desde Wazuh, se marca como `RESOLVED`.
12. Se actualiza `last_sync_at` en `wazuh_connections`.

El frontend consulta el progreso con:

```text
GET /sync/status?job_id=...
```

## Logica de estados

### Vulnerabilidad nueva

Si llega una combinacion que no existia:

```text
connection_id + agent_id + package_name + package_version + cve_id
```

Entonces:

```text
wazuh_vulnerabilities.status = ACTIVE
vulnerability_history.action = DETECTED
vulnerability_detections.status = Detected
```

### Vulnerabilidad persistente

Si la misma combinacion ya existia y sigue llegando desde Wazuh:

```text
wazuh_vulnerabilities.status sigue ACTIVE
wazuh_vulnerabilities.last_seen se actualiza
vulnerability_detections.status = Detected
```

Esto no es un duplicado conceptual. Es otra observacion historica de la misma vulnerabilidad.

### Vulnerabilidad resuelta

Si estaba activa en la base, pero en la nueva sincronizacion Wazuh ya no la reporta:

```text
wazuh_vulnerabilities.status = RESOLVED
vulnerability_history.action = RESOLVED
vulnerability_detections.status = Resolved
```

### Vulnerabilidad reemergida

Si estaba resuelta y Wazuh vuelve a reportarla:

```text
wazuh_vulnerabilities.status = ACTIVE
vulnerability_history.action = REOPENED
vulnerability_detections.status = Re-emerged
```

## Indices creados para acelerar filtros

En `initialize_analytics_objects()` se crean indices sobre `wazuh_vulnerabilities`:

```sql
CREATE INDEX IF NOT EXISTS idx_wv_conn_status
ON wazuh_vulnerabilities (connection_id, status);

CREATE INDEX IF NOT EXISTS idx_wv_agent_name
ON wazuh_vulnerabilities (agent_name);

CREATE INDEX IF NOT EXISTS idx_wv_cve
ON wazuh_vulnerabilities (cve_id);

CREATE INDEX IF NOT EXISTS idx_wv_severity
ON wazuh_vulnerabilities (severity);

CREATE INDEX IF NOT EXISTS idx_wv_last_seen
ON wazuh_vulnerabilities (last_seen DESC);

CREATE INDEX IF NOT EXISTS idx_wv_package_name
ON wazuh_vulnerabilities (package_name);
```

Estos indices estan pensados para los filtros del dashboard:

- Conexion.
- Estado.
- Agente.
- CVE.
- Severidad.
- Paquete.
- Orden por ultima vista.

## Que son los procedimientos almacenados

Un procedimiento almacenado es logica SQL guardada dentro de la base de datos. Sirve para ejecutar operaciones cerca de los datos, sin traer miles de filas a la aplicacion para procesarlas en Python.

En PostgreSQL hay diferencia tecnica entre:

- `CREATE PROCEDURE`: procedimiento que se ejecuta con `CALL`.
- `CREATE FUNCTION`: funcion que se puede usar dentro de un `SELECT`.

En este proyecto no se usan `CREATE PROCEDURE`. Se usan funciones SQL creadas con `CREATE OR REPLACE FUNCTION`. En la documentacion pueden aparecer mencionadas como "stored procedures" porque cumplen el mismo objetivo practico: logica almacenada en la base para consultas analiticas.

Las funciones son:

```text
sp_traceability_timeline
sp_traceability_summary
```

## Funcion almacenada `sp_traceability_timeline`

Se crea asi:

```sql
CREATE OR REPLACE FUNCTION sp_traceability_timeline(
    p_connection_id INTEGER,
    p_bucket INTERVAL,
    p_start TIMESTAMPTZ,
    p_end TIMESTAMPTZ
)
RETURNS TABLE(
    bucket TIMESTAMPTZ,
    nuevas BIGINT,
    reemergidas BIGINT,
    remediadas BIGINT
)
LANGUAGE sql STABLE AS $$
    SELECT
        time_bucket(p_bucket, vd.timestamp) AS bucket,
        count(*) FILTER (WHERE vd.status = 'Detected')    AS nuevas,
        count(*) FILTER (WHERE vd.status = 'Re-emerged')  AS reemergidas,
        count(*) FILTER (WHERE vd.status = 'Resolved')    AS remediadas
    FROM vulnerability_detections vd
    JOIN assets a   ON a.id = vd.asset_id
    JOIN managers m ON m.id = a.manager_id
    WHERE vd.timestamp >= p_start
      AND vd.timestamp <= p_end
      AND (p_connection_id IS NULL OR m.legacy_connection_id = p_connection_id)
    GROUP BY bucket
    ORDER BY bucket
$$;
```

Que devuelve:

| Campo | Significado |
|-------|-------------|
| `bucket` | Ventana temporal, por ejemplo dia o semana |
| `nuevas` | Eventos `Detected` |
| `reemergidas` | Eventos `Re-emerged` |
| `remediadas` | Eventos `Resolved` |

Se usa en:

```text
GET /vulns/evolution/timeline
```

Pero con una condicion importante:

- Si no hay filtros extra de agente o CVE, el endpoint usa `sp_traceability_timeline`.
- Si hay filtros de agente o CVE, el endpoint usa una consulta SQL parametrizada equivalente con `time_bucket` y `ANY(:agents)` / `ANY(:cves)`.

Esto permite mantener el stored function simple para el caso general y aplicar filtros dinamicos cuando el usuario selecciona agentes o CVEs.

## Funcion almacenada `sp_traceability_summary`

Se crea asi:

```sql
CREATE OR REPLACE FUNCTION sp_traceability_summary(
    p_connection_id INTEGER,
    p_new_window INTERVAL DEFAULT INTERVAL '7 days'
)
RETURNS TABLE(
    nuevas BIGINT,
    persistentes BIGINT,
    remediadas BIGINT,
    total_activas BIGINT
)
LANGUAGE sql STABLE AS $$
    SELECT
        count(*) FILTER (
            WHERE wv.status = 'ACTIVE'
              AND wv.first_seen >= now() - p_new_window
        ) AS nuevas,
        count(*) FILTER (
            WHERE wv.status = 'ACTIVE'
              AND wv.first_seen < now() - p_new_window
        ) AS persistentes,
        count(*) FILTER (WHERE wv.status = 'RESOLVED') AS remediadas,
        count(*) FILTER (WHERE wv.status = 'ACTIVE')   AS total_activas
    FROM wazuh_vulnerabilities wv
    WHERE (p_connection_id IS NULL OR wv.connection_id = p_connection_id)
$$;
```

Que devuelve:

| Campo | Significado |
|-------|-------------|
| `nuevas` | Activas vistas por primera vez dentro de la ventana |
| `persistentes` | Activas que vienen desde antes de la ventana |
| `remediadas` | Vulnerabilidades con estado actual `RESOLVED` |
| `total_activas` | Total actual con estado `ACTIVE` |

Se usa en:

```text
GET /vulns/evolution/traceability-summary
```

## Se usan procedimientos almacenados en los filtros de la app?

Respuesta corta: parcialmente.

Los filtros principales del listado de vulnerabilidades no usan procedimientos almacenados. Usan SQLAlchemy y filtros server-side sobre `wazuh_vulnerabilities`.

Endpoint:

```text
GET /vulns
```

Filtros soportados:

| Parametro | Columna usada |
|-----------|---------------|
| `connection_id` | `wazuh_vulnerabilities.connection_id` |
| `agent_name` | `wazuh_vulnerabilities.agent_name` |
| `cve_id` | `wazuh_vulnerabilities.cve_id` |
| `package_name` | `wazuh_vulnerabilities.package_name` |
| `severity` | `wazuh_vulnerabilities.severity` |
| `status` | `wazuh_vulnerabilities.status` |
| `score_min` | `wazuh_vulnerabilities.score_base >= score_min` |
| `score_max` | `wazuh_vulnerabilities.score_base <= score_max` |
| `search` | Busca en CVE, agente, paquete y descripcion |

La funcion Python que aplica esos filtros es `_apply_vuln_filters()`.

Ejemplo conceptual:

```python
if agents:
    query = query.filter(WazuhVulnerability.agent_name.in_(agents))

if cves:
    query = query.filter(WazuhVulnerability.cve_id.in_(cves))

if severities:
    query = query.filter(sql_func.lower(WazuhVulnerability.severity).in_(lowered))
```

Entonces:

- No se trae toda la tabla al frontend.
- No se filtra en el navegador.
- La base ejecuta el `WHERE`, el `ORDER BY`, el `LIMIT` y el `OFFSET`.
- Los indices ayudan a que esos filtros sean mas rapidos.

## Filtros precargados

El endpoint:

```text
GET /vulns/filter-options
```

devuelve listas para poblar los dropdowns:

```json
{
  "agents": [],
  "cves": [],
  "packages": [],
  "severities": []
}
```

Lo hace con consultas `DISTINCT` en la base, no descargando todas las vulnerabilidades.

Si se pasa `connection_id`, las opciones se limitan a esa conexion.

## Filtros de la linea de tiempo tipo Gantt

La vista de linea de tiempo usa:

```text
GET /vulns/evolution/threats
```

Este endpoint consulta `wazuh_vulnerabilities`, no la hypertable.

La razon es que el Gantt muestra una barra por amenaza unica, no una barra por cada evento historico. Cada amenaza viene de `wazuh_vulnerabilities` y usa:

- `first_seen` como inicio.
- `last_seen` como fin si esta resuelta.
- `null` como fin si sigue activa.

Filtros que acepta:

| Parametro | Uso |
|-----------|-----|
| `start` | Inicio del rango visible |
| `end` | Fin del rango visible |
| `connection_id` | Conexion Wazuh |
| `agent_name` | Agentes seleccionados |
| `cve_id` | CVEs seleccionados |
| `severity` | Severidades seleccionadas |
| `limit` | Maximo de barras devueltas |
| `offset` | Paginacion |

En el frontend, `useTimelineData.js` arma los parametros asi:

```javascript
if (selectedAgents.value?.length) params.agent_name = selectedAgents.value.join(',')
if (selectedVulns.value?.length) params.cve_id = selectedVulns.value.join(',')
if (selectedSeverities?.value?.length) params.severity = selectedSeverities.value.join(',')
```

El backend los separa con `_split_csv()` y los aplica con `_apply_vuln_filters()`.

## Filtros de la linea de trazabilidad

La linea de trazabilidad usa:

```text
GET /vulns/evolution/timeline
```

Esta vista si trabaja sobre `vulnerability_detections`, porque necesita contar eventos por tiempo:

- Nuevas.
- Reemergidas.
- Remediadas.

Uso de funciones almacenadas:

| Caso | Como consulta |
|------|---------------|
| Sin filtro de agente/CVE | Usa `sp_traceability_timeline` |
| Con filtro de agente/CVE | Usa SQL directo con `time_bucket` y filtros `ANY` |
| En SQLite/tests | Usa fallback en Python |

## Otros endpoints analiticos

### `GET /vulns/evolution/weekly`

Usa `time_bucket('1 week', vd.timestamp)` sobre `vulnerability_detections` para contar detecciones por semana.

Si no esta en PostgreSQL, usa fallback en Python.

### `GET /vulns/evolution/top-assets`

Usa `wazuh_vulnerabilities` y cuenta CVEs activos distintos por agente.

No usa TimescaleDB porque busca estado actual, no eventos historicos.

### `GET /vulns/evolution/summary`

Calcula:

- Vulnerabilidades activas.
- Vulnerabilidades resueltas.
- Numero de assets.
- Numero de eventos historicos.
- Ultima sincronizacion.

Usa consultas ORM normales.

### `GET /vulns/evolution/timeline-details`

Consulta detalles de eventos dentro de un rango `bucket_start` / `bucket_end`.

Usa:

- `vulnerability_detections`
- `assets`
- `managers`
- `vulnerability_catalog`

Se carga bajo demanda para no descargar miles de eventos cuando solo se necesita ver un bucket.

## Porque hay dos tablas de vulnerabilidades

Puede parecer duplicado tener `wazuh_vulnerabilities` y `vulnerability_detections`, pero cumplen roles distintos.

| Tabla | Rol |
|-------|-----|
| `wazuh_vulnerabilities` | Estado actual e inventario consultable |
| `vulnerability_detections` | Eventos historicos para analitica temporal |
| `vulnerability_history` | Auditoria de cambios de una vulnerabilidad puntual |
| `vulnerability_catalog` | Informacion normalizada del CVE |

Ejemplo:

Una vulnerabilidad `CVE-2024-0001` en `srv-01` puede aparecer en 5 sincronizaciones seguidas.

En `wazuh_vulnerabilities` hay 1 fila, porque es la misma amenaza.

En `vulnerability_detections` puede haber 5 eventos `Detected`, porque fue observada 5 veces en el tiempo.

Si despues se remedia:

- La fila de `wazuh_vulnerabilities` pasa a `RESOLVED`.
- Se agrega un evento `Resolved` en `vulnerability_detections`.
- Se agrega una accion `RESOLVED` en `vulnerability_history`.

## Como verificar TimescaleDB en la base

Ver si la extension esta instalada:

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select extname from pg_extension where extname = '\''timescaledb'\'';"'
```

Ver si `vulnerability_detections` es hypertable:

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select hypertable_name from timescaledb_information.hypertables where hypertable_name = '\''vulnerability_detections'\'';"'
```

Ver chunks internos de TimescaleDB:

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select hypertable_name, chunk_name from timescaledb_information.chunks where hypertable_name = '\''vulnerability_detections'\'' order by chunk_name limit 20;"'
```

Ver funciones almacenadas:

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select proname from pg_proc where proname in ('\''sp_traceability_timeline'\'', '\''sp_traceability_summary'\'');"'
```

Ver indices principales:

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select indexname from pg_indexes where tablename in ('\''wazuh_vulnerabilities'\'', '\''vulnerability_detections'\'') order by tablename, indexname;"'
```

## Consultas utiles para entender los datos

Ver tablas:

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "\dt"'
```

Ver conexiones Wazuh:

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select id, name, indexer_url, is_active, tested, last_test_ok, last_sync_at from wazuh_connections order by id;"'
```

Ver resumen de estado actual:

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select status, count(*) from wazuh_vulnerabilities group by status order by status;"'
```

Ver ultimas vulnerabilidades actuales:

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select agent_name, package_name, package_version, cve_id, severity, score_base, status, first_seen, last_seen from wazuh_vulnerabilities order by last_seen desc limit 10;"'
```

Ver eventos historicos:

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select status, count(*) from vulnerability_detections group by status order by status;"'
```

Ver ultimos eventos historicos:

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select timestamp, status, cve_id, package_name, package_version from vulnerability_detections order by timestamp desc limit 20;"'
```

Ver evolucion semanal:

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select time_bucket('\''1 week'\'', timestamp) as semana, count(*) as total from vulnerability_detections group by semana order by semana;"'
```

Probar `sp_traceability_summary`:

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select * from sp_traceability_summary(NULL, interval '\''7 days'\'');"'
```

Probar `sp_traceability_timeline`:

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select * from sp_traceability_timeline(NULL, interval '\''1 week'\'', now() - interval '\''90 days'\'', now());"'
```

## Sintesis para presentar

La base de datos de la aplicacion usa PostgreSQL con TimescaleDB. PostgreSQL guarda el modelo relacional: usuarios, conexiones Wazuh, agentes, CVEs, vulnerabilidades actuales e historial. TimescaleDB se usa especificamente para `vulnerability_detections`, que es la tabla de eventos historicos por fecha.

El estado actual vive en `wazuh_vulnerabilities`. Ahi se consulta que vulnerabilidades estan activas o resueltas ahora. La evolucion historica vive en `vulnerability_detections`, donde cada sincronizacion deja eventos `Detected`, `Resolved` o `Re-emerged`.

Los filtros principales de la app no son procedimientos almacenados: son consultas SQLAlchemy ejecutadas en la base con `WHERE`, `ORDER BY`, `LIMIT` y `OFFSET`, apoyadas por indices. Los procedimientos almacenados del proyecto son en realidad funciones SQL de PostgreSQL: `sp_traceability_timeline` y `sp_traceability_summary`. Se usan para agregaciones analiticas y trazabilidad, especialmente cuando se necesita agrupar eventos por tiempo con `time_bucket`.

En resumen: la app usa una base relacional para el inventario y TimescaleDB para responder bien a preguntas temporales sobre como evolucionan las vulnerabilidades.

# Defensa tecnica de la aplicacion DevSecOps con Wazuh

## 1. Resumen ejecutivo

Esta aplicacion centraliza vulnerabilidades reportadas por Wazuh, las guarda en una base de datos propia y las presenta en un dashboard web.

El objetivo principal que pide el profesor es demostrar que la app **se comunica correctamente con Wazuh** y que no muestra datos inventados o estaticos. En esta implementacion, la comunicacion real ocurre contra el **Wazuh Indexer** por HTTP/REST:

```text
Notebook con la app -> Backend FastAPI -> Wazuh Indexer en 192.168.1.46:9200
```

Ademas, el notebook tambien funciona como agente Wazuh:

```text
Notebook como agente Wazuh -> Wazuh Manager en PC de escritorio -> Wazuh Indexer
```

Por eso hay dos comunicaciones distintas:

1. El agente Wazuh del notebook reporta informacion al servidor Wazuh del PC de escritorio.
2. La aplicacion consulta el Wazuh Indexer del PC de escritorio y guarda las vulnerabilidades en su propia base de datos.

## 2. Distribucion fisica del sistema

### PC de escritorio

IP actual:

```text
192.168.1.46
```

En este equipo esta el servidor Wazuh:

- Wazuh Dashboard: interfaz web donde se ven agentes, vulnerabilidades y estado general.
- Wazuh Manager: recibe datos desde los agentes.
- Wazuh Indexer/OpenSearch: almacena los indices de Wazuh, incluyendo vulnerabilidades.

URLs y puertos importantes:

```text
https://192.168.1.46
https://192.168.1.46:9200
1514/tcp: comunicacion del agente con el manager
1515/tcp: enrolamiento/autenticacion inicial de agentes
```

### Notebook

En este equipo se ejecutan dos cosas:

1. La aplicacion del proyecto mediante Docker Compose.
2. El agente Wazuh instalado localmente.

La app contiene:

- `frontend`: interfaz Vue servida por Nginx.
- `api`: backend FastAPI.
- `db-api`: base de datos TimescaleDB/PostgreSQL.

## 3. Arquitectura general

Flujo completo:

```text
Agente Wazuh en notebook
        |
        | puerto 1514/tcp
        v
Wazuh Manager en PC escritorio
        |
        v
Wazuh Indexer/OpenSearch en PC escritorio
        ^
        | HTTPS REST, puerto 9200
        |
Backend FastAPI de la app
        |
        | SQL
        v
TimescaleDB/PostgreSQL de la app
        ^
        | HTTP /api
        |
Frontend Vue/Nginx
```

Punto clave para la defensa:

> La aplicacion no lee directamente desde el dashboard visual de Wazuh. La aplicacion se conecta al Wazuh Indexer, que es donde Wazuh guarda los documentos de vulnerabilidades. Desde ahi extrae los datos, los procesa y los guarda en una base de datos propia.

## 4. Servicios Docker de la aplicacion

El archivo principal es:

```text
docker-compose.yml
```

Servicios:

```text
db-api     -> TimescaleDB/PostgreSQL
api        -> Backend FastAPI
frontend   -> Nginx + Vue
```

Comando para levantar la app:

```bash
cd /home/sidwilson0/Escritorio/devsecops
docker compose up -d --build
```

Comando para ver estado:

```bash
docker compose ps
```

Resultado esperado:

```text
vuln-app-wazuh-api-1        Up ... healthy
vuln-app-wazuh-db-api-1     Up ... healthy
vuln-app-wazuh-frontend-1   Up ... 0.0.0.0:80->80, 0.0.0.0:443->443
```

Estado real verificado:

```text
api      healthy
db-api   healthy
frontend up
```

## 5. Como entrar a la app

Desde el notebook:

```text
https://127.0.0.1
```

Tambien puede funcionar con la IP local del notebook si el firewall lo permite:

```text
https://<ip-del-notebook>
```

Como el certificado es autofirmado, el navegador puede mostrar una advertencia de seguridad. Se acepta la excepcion para entrar en entorno local.

Comando para demostrar que el frontend responde:

```bash
curl -k -I https://127.0.0.1/
```

Resultado esperado:

```text
HTTP/1.1 200 OK
Server: nginx
```

## 6. Como funciona el frontend

Tecnologia:

```text
Vue 3 + Vite + Nginx
```

Archivos principales:

```text
frontend/src/presentation/views/Login.vue
frontend/src/presentation/views/Dashboard.vue
frontend/src/presentation/views/Timeline.vue
frontend/src/presentation/views/ConfigWazuh.vue
frontend/src/application/services/vulnService.js
frontend/src/application/services/wazuhService.js
frontend/nginx.conf
```

Responsabilidad del frontend:

- Permitir inicio de sesion.
- Mostrar el dashboard de vulnerabilidades.
- Mostrar evolucion historica.
- Administrar conexiones Wazuh.
- Ejecutar prueba de conexion.
- Ejecutar sincronizacion manual.

El frontend no se conecta directamente a Wazuh. Se conecta al backend usando rutas con prefijo:

```text
/api
```

Nginx hace el proxy:

```text
Navegador -> https://127.0.0.1/api/... -> contenedor api:8000
```

Esto esta configurado en:

```text
frontend/nginx.conf
```

## 7. Como funciona el backend

Tecnologia:

```text
FastAPI + SQLAlchemy + PostgreSQL/TimescaleDB
```

Archivos principales:

```text
vuln-api/app/main.py
vuln-api/app/models.py
vuln-api/app/wazuh_client.py
vuln-api/app/db.py
vuln-api/app/auth.py
vuln-api/app/crypto.py
```

Responsabilidades del backend:

- Autenticar usuarios.
- Administrar usuarios.
- Guardar conexiones Wazuh.
- Cifrar la password de Wazuh.
- Probar conexion contra Wazuh.
- Sincronizar vulnerabilidades desde Wazuh.
- Guardar vulnerabilidades actuales.
- Guardar eventos historicos de evolucion.
- Exponer datos al frontend mediante API REST.

Rutas principales:

```text
POST /auth/login
GET  /users/me
GET  /wazuh-connections
POST /wazuh-connections
POST /wazuh-connections/{id}/test
POST /wazuh-connections/{id}/sync
POST /vulns/sync-all
GET  /vulns
GET  /vulns/evolution/summary
GET  /vulns/evolution/weekly
GET  /vulns/evolution/top-assets
```

Comando para demostrar que el backend expone una API REST real:

```bash
curl -k https://127.0.0.1/api/openapi.json | head
```

Resultado esperado:

```text
"title":"Vulnerability Aggregator API"
```

## 8. Comunicacion con Wazuh

La integracion esta implementada en:

```text
vuln-api/app/wazuh_client.py
```

Funcion de prueba:

```text
test_connection(indexer_url, wazuh_user, wazuh_password)
```

Funcion de extraccion:

```text
fetch_all_vulns(indexer_url, wazuh_user, wazuh_password)
```

La app consulta este patron de indice:

```text
wazuh-states-vulnerabilities-*/_search
```

La URL configurada actualmente en la app es:

```text
https://192.168.1.46:9200
```

Comando para demostrar que el Wazuh Indexer responde desde el notebook:

```bash
curl -k -u admin:admin https://192.168.1.46:9200
```

Resultado real observado:

```text
"cluster_name" : "wazuh-cluster"
"tagline" : "The OpenSearch Project"
```

Interpretacion:

> El notebook puede llegar al Wazuh Indexer del PC de escritorio por red. Por eso el backend tambien puede conectarse, porque el backend corre en el mismo notebook dentro de Docker.

## 9. Conexion del agente Wazuh del notebook

El agente Wazuh del notebook debe apuntar al servidor correcto:

```text
192.168.1.46
```

Antes estaba apuntando a otra IP:

```text
192.168.1.245
```

Ese era el motivo por el que aparecia desconectado.

Archivo corregido:

```text
/var/ossec/etc/ossec.conf
```

Bloque correcto:

```xml
<client>
  <server>
    <address>192.168.1.46</address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
</client>
```

Comandos usados para diagnosticar:

```bash
sudo systemctl status wazuh-agent
nc -vz 192.168.1.46 1514
nc -vz 192.168.1.46 1515
sudo grep -A5 -B2 "<server>" /var/ossec/etc/ossec.conf
```

Resultado de red esperado:

```text
Connection to 192.168.1.46 1514 port [tcp/*] succeeded!
Connection to 192.168.1.46 1515 port [tcp/*] succeeded!
```

Comando para reiniciar el agente:

```bash
sudo systemctl restart wazuh-agent
```

Comando para comprobar estado:

```bash
sudo grep ^status /var/ossec/var/run/wazuh-agentd.state
```

Resultado correcto:

```text
status='connected'
```

En el dashboard Wazuh debe aparecer:

```text
Agents management -> Summary -> Active
```

## 10. Base de datos propia de la app

La app no depende solo de Wazuh para mostrar datos. Despues de consultar Wazuh, guarda los datos en una base propia.

Base usada:

```text
TimescaleDB sobre PostgreSQL
```

Servicio:

```text
db-api
```

Volumen persistente:

```text
postgres_api_data
```

Esto significa que los datos sobreviven si se reinician los contenedores.

Tablas principales:

```text
wazuh_connections
wazuh_vulnerabilities
vulnerability_history
managers
assets
vulnerability_catalog
vulnerability_detections
users
user_interactions
```

## 11. Modelo de datos de evolucion de vulnerabilidades

La pauta del proyecto pedia tres niveles:

### 11.1 Infraestructura

Tabla:

```text
managers
```

Guarda los Wazuh Managers/Indexers configurados:

```text
id
nombre
api_url
api_key_vault_ref
legacy_connection_id
```

Tabla:

```text
assets
```

Guarda los equipos/agentes:

```text
id
wazuh_agent_id
hostname
os_version
ip_address
manager_id
```

### 11.2 Catalogo de vulnerabilidades

Tabla:

```text
vulnerability_catalog
```

Evita duplicar informacion larga de CVEs:

```text
cve_id
severity
description
cvss_score
```

### 11.3 Eventos historicos

Tabla:

```text
vulnerability_detections
```

Esta es la tabla clave de evolucion temporal:

```text
timestamp
asset_id
cve_id
status
package_name
package_version
```

Estados posibles:

```text
Detected
Resolved
Re-emerged
```

## 12. TimescaleDB e hypertable

La tabla:

```text
vulnerability_detections
```

se convierte en hypertable de TimescaleDB usando la columna:

```text
timestamp
```

Esto permite manejar series de tiempo, es decir, guardar multiples observaciones de las vulnerabilidades a lo largo del tiempo.

Comando para demostrar que TimescaleDB esta instalado:

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select extname from pg_extension where extname = '\''timescaledb'\'';"'
```

Resultado esperado:

```text
timescaledb
```

Comando para demostrar que la tabla historica es hypertable:

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select hypertable_name from timescaledb_information.hypertables where hypertable_name = '\''vulnerability_detections'\'';"'
```

Resultado esperado:

```text
vulnerability_detections
```

## 13. Como funciona la sincronizacion

Cuando se presiona "Forzar Sincronizacion":

1. El frontend llama al backend.
2. El backend busca la conexion Wazuh activa.
3. El backend descifra la password guardada.
4. El backend consulta:

```text
https://192.168.1.46:9200/wazuh-states-vulnerabilities-*/_search
```

5. Wazuh devuelve documentos de vulnerabilidades.
6. El backend identifica agente, sistema operativo, paquete, CVE, severidad y score.
7. Se actualiza la tabla de vulnerabilidades actuales.
8. Se actualiza el catalogo de CVEs.
9. Se registra un evento historico en `vulnerability_detections`.
10. El dashboard vuelve a consultar el backend y muestra las metricas actualizadas.

## 14. Logica de evolucion

### Nueva vulnerabilidad

Si llega desde Wazuh una combinacion que no existia:

```text
connection_id + agent_id + package_name + package_version + cve_id
```

se crea como:

```text
status = ACTIVE
evento historico = Detected
```

### Vulnerabilidad persistente

Si la vulnerabilidad ya existia y sigue llegando desde Wazuh:

```text
status = ACTIVE
evento historico = Detected
```

Esto demuestra persistencia temporal. No es duplicado conceptual: es una nueva observacion en otra sincronizacion.

### Vulnerabilidad resuelta

Si una vulnerabilidad estaba activa pero en la nueva sincronizacion ya no llega desde Wazuh:

```text
status = RESOLVED
evento historico = Resolved
```

### Vulnerabilidad reaparecida

Si una vulnerabilidad estaba resuelta y Wazuh vuelve a reportarla:

```text
status = ACTIVE
evento historico = Re-emerged
```

## 15. Por que suben los "eventos historicos"

En el dashboard, "Eventos historicos" no significa "vulnerabilidades unicas".

Significa:

```text
cantidad de observaciones historicas guardadas
```

Ejemplo:

```text
Sync 1: CVE-123 sigue activa -> 1 evento
Sync 2: CVE-123 sigue activa -> otro evento
Sync 3: CVE-123 sigue activa -> otro evento
```

Resultado:

```text
1 vulnerabilidad activa
3 eventos historicos
```

Esto es correcto para series de tiempo, porque permite demostrar cuanto tiempo una vulnerabilidad estuvo activa.

Frase recomendada para defenderlo:

> Eventos historicos aumenta con cada sincronizacion porque la aplicacion registra cada escaneo como una muestra temporal. No son vulnerabilidades duplicadas, son observaciones historicas que permiten medir persistencia, aparicion, resolucion y reaparicion.

## 16. Estado actual de datos verificado

Comando:

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select id, name, indexer_url, is_active, tested, last_test_ok from wazuh_connections order by id;" -c "select status, count(*) from wazuh_vulnerabilities group by status order by status;" -c "select count(*) as managers from managers;" -c "select count(*) as assets from assets;" -c "select status, count(*) from vulnerability_detections group by status order by status;"'
```

Resultado real observado:

```text
Conexion:
id = 3
name = conexion timestamp
indexer_url = https://192.168.1.46:9200
is_active = true
tested = true
last_test_ok = true

Vulnerabilidades actuales:
ACTIVE   = 2841
RESOLVED = 8

Infraestructura:
managers = 1
assets   = 1

Eventos historicos:
Detected = 17253
Resolved = 8
```

Interpretacion para el profesor:

> La app tiene una conexion Wazuh valida, guarda vulnerabilidades actuales, reconoce vulnerabilidades resueltas y mantiene una tabla historica de eventos. Esto cumple el objetivo de evolucion temporal, no solo una foto fija.

## 17. Consultas clave para demostrar la pauta

### 17.1 Ver conexiones Wazuh configuradas

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select id, name, indexer_url, is_active, tested, last_test_ok from wazuh_connections order by id;"'
```

Demuestra:

- La app tiene registrada la URL de Wazuh.
- La conexion fue probada.
- La conexion esta activa.

### 17.2 Ver vulnerabilidades activas y resueltas

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select status, count(*) from wazuh_vulnerabilities group by status order by status;"'
```

Demuestra:

- La app guarda estado actual.
- Diferencia entre `ACTIVE` y `RESOLVED`.

### 17.3 Ver eventos historicos por estado

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select status, count(*) from vulnerability_detections group by status order by status;"'
```

Demuestra:

- La app guarda historia.
- Hay eventos `Detected` y `Resolved`.

### 17.4 Ver ultimos eventos historicos

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select timestamp, status, cve_id, package_name, package_version from vulnerability_detections order by timestamp desc limit 20;"'
```

Demuestra:

- Los eventos tienen fecha/hora.
- Los eventos se asocian a CVE y paquete.

### 17.5 Ver tendencia semanal con TimescaleDB

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select time_bucket('\''1 week'\'', timestamp) as semana, count(*) as total_vulnerabilidades from vulnerability_detections where status = '\''Detected'\'' group by semana order by semana;"'
```

Demuestra:

- Uso de `time_bucket`, funcion propia de TimescaleDB.
- La app puede agrupar eventos por semana.
- Esto alimenta el grafico de tendencia.

### 17.6 Ver top de servidores vulnerables

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select a.hostname, count(distinct vd.cve_id) as total from assets a join vulnerability_detections vd on a.id = vd.asset_id where vd.timestamp > now() - interval '\''7 days'\'' and vd.status in ('\''Detected'\'', '\''Re-emerged'\'') group by a.hostname order by total desc limit 5;"'
```

Demuestra:

- Relacion entre assets y detecciones.
- La app puede responder preguntas utiles para dashboard.

### 17.7 Ver que existen las tablas de la pauta

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "\dt"'
```

Tablas esperadas:

```text
managers
assets
vulnerability_catalog
vulnerability_detections
wazuh_connections
wazuh_vulnerabilities
vulnerability_history
users
```

## 18. Como demostrar que la app se comunica con Wazuh

### Paso 1: demostrar que Wazuh existe y responde

Desde el notebook:

```bash
curl -k -u admin:admin https://192.168.1.46:9200
```

Debe responder JSON de OpenSearch/Wazuh Indexer.

### Paso 2: demostrar que la app tiene esa URL configurada

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select id, name, indexer_url, last_test_ok from wazuh_connections;"'
```

Debe mostrar:

```text
https://192.168.1.46:9200
last_test_ok = true
```

### Paso 3: demostrar que hay datos sincronizados

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select count(*) from wazuh_vulnerabilities;"'
```

Debe ser mayor que cero.

### Paso 4: demostrar que se guardo historia

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select count(*) from vulnerability_detections;"'
```

Debe ser mayor que el numero de vulnerabilidades activas si ya sincronizaste varias veces.

### Paso 5: demostrar visualmente

En la app:

```text
Configuracion Wazuh -> probar conexion
Dashboard -> ver activas, resueltas, assets, eventos historicos
Forzar Sincronizacion -> observar que eventos historicos aumenta
Timeline -> revisar eventos de vulnerabilidades
```

## 19. Guia de uso para la demostracion

### 19.1 Antes de la clase

En el PC de escritorio:

1. Encender el PC.
2. Verificar que Wazuh este arriba.
3. Entrar a:

```text
https://192.168.1.46
```

4. Verificar que el dashboard carga.

En el notebook:

1. Verificar conexion al indexer:

```bash
curl -k -u admin:admin https://192.168.1.46:9200
```

2. Verificar puertos del agente:

```bash
nc -vz 192.168.1.46 1514
nc -vz 192.168.1.46 1515
```

3. Verificar agente:

```bash
sudo grep ^status /var/ossec/var/run/wazuh-agentd.state
```

Debe decir:

```text
status='connected'
```

4. Levantar la app:

```bash
cd /home/sidwilson0/Escritorio/devsecops
docker compose up -d --build
```

5. Verificar contenedores:

```bash
docker compose ps
```

6. Entrar a la app:

```text
https://127.0.0.1
```

### 19.2 Durante la presentacion

Orden recomendado:

1. Mostrar Wazuh en `https://192.168.1.46`.
2. Mostrar el agente del notebook como `Active`.
3. Mostrar desde terminal:

```bash
sudo grep ^status /var/ossec/var/run/wazuh-agentd.state
```

4. Mostrar que el indexer responde:

```bash
curl -k -u admin:admin https://192.168.1.46:9200
```

5. Mostrar app en `https://127.0.0.1`.
6. Ir a Configuracion Wazuh y probar conexion.
7. Ir al Dashboard.
8. Mostrar metricas.
9. Presionar "Forzar Sincronizacion".
10. Mostrar que aumentan eventos historicos.
11. Ejecutar consulta SQL de `vulnerability_detections`.
12. Explicar que la app guarda series de tiempo.

## 20. SonarQube

SonarQube se usa para analisis estatico de calidad de codigo.

Carpeta:

```text
dev-tools/sonarqube
```

Servicios:

```text
sonarqube
db-sonar
```

Archivo:

```text
dev-tools/sonarqube/sonar-project.properties
```

Configura:

```text
sonar.projectKey=vuln-app
sonar.projectName=Vuln App Wazuh
sonar.sources=vuln-api/app,frontend/src
sonar.tests=vuln-api/tests,frontend/tests
sonar.python.coverage.reportPaths=vuln-api/coverage.xml
sonar.javascript.lcov.reportPaths=frontend/coverage/lcov.info
```

Como levantar SonarQube:

```bash
cd /home/sidwilson0/Escritorio/devsecops/dev-tools/sonarqube
docker compose up -d
```

Entrar a:

```text
http://localhost:9000
```

Que demuestra:

- Calidad estatica del backend y frontend.
- Cobertura de tests Python.
- Cobertura de tests JavaScript/Vue.
- Quality Gate para aceptar o rechazar el build.

## 21. Jenkins

Jenkins automatiza el pipeline CI/CD.

Carpeta:

```text
dev-tools/jenkins
```

Archivo principal:

```text
dev-tools/jenkins/Jenkinsfile
```

Etapas del pipeline:

```text
CI: Backend Tests & Coverage
CI: Frontend Tests & Build
SAST: SonarQube Code Analysis
GATE: SonarQube Quality Gate
DAST: OWASP ZAP Dynamic Scan
```

Como levantar Jenkins:

```bash
cd /home/sidwilson0/Escritorio/devsecops/dev-tools/jenkins
docker compose up -d --build
```

Entrar a:

```text
http://localhost:8080
```

Que demuestra Jenkins:

- El proyecto no solo corre manualmente.
- Tiene pipeline automatizado.
- Ejecuta tests backend.
- Ejecuta tests frontend.
- Construye frontend.
- Envia analisis a SonarQube.
- Valida Quality Gate.
- Ejecuta escaneo DAST con OWASP ZAP contra API y frontend.

## 22. OWASP ZAP

ZAP se usa como DAST, es decir, analisis dinamico de seguridad.

Script:

```text
dev-tools/jenkins/scripts/run_zap.sh
```

Hace dos escaneos:

```text
zap-api-scan.py contra OpenAPI del backend
zap-baseline.py contra frontend
```

Reportes generados:

```text
reports/zap_api_report_<build>.html
reports/zap_frontend_report_<build>.html
```

Que demuestra:

- La app es analizada mientras esta corriendo.
- Se revisan posibles problemas HTTP, headers, endpoints y superficie web.

## 23. Tests

Backend:

```bash
docker compose run --rm api sh -c "PYTHONPATH=/app pytest tests"
```

Backend con coverage:

```bash
docker compose run --rm api sh -c "PYTHONPATH=/app pytest tests --cov=app --cov-report=term-missing"
```

Frontend:

```bash
docker run --rm -v "$PWD/frontend:/app" -w /app node:24-alpine sh -c "npm ci && npm run test:coverage"
```

Validacion realizada durante el desarrollo:

```text
Backend: 52 tests passed
Frontend: 272 tests passed
```

Nota:

> El build local con Node 18 puede fallar porque Vite 7 requiere una version mas nueva de Node. El Dockerfile del frontend usa Node 24, por eso el build correcto se valida dentro de Docker.

## 24. Que pasa si hay un apagon de luz

### App del notebook

Los servicios Docker tienen:

```text
restart: unless-stopped
```

Eso significa que Docker intentara levantarlos automaticamente despues de reiniciar el equipo, siempre que Docker arranque.

La base de datos usa un volumen:

```text
postgres_api_data
```

Por eso los datos no se pierden al apagar o reiniciar contenedores.

Despues de un apagon, ejecutar:

```bash
cd /home/sidwilson0/Escritorio/devsecops
docker compose ps
docker compose up -d
```

### Wazuh del PC de escritorio

Despues del apagon, verificar:

```bash
sudo systemctl status wazuh-manager
```

Si corresponde tambien revisar indexer y dashboard, segun como este instalado Wazuh:

```bash
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
```

### Agente del notebook

Verificar:

```bash
sudo systemctl status wazuh-agent
sudo grep ^status /var/ossec/var/run/wazuh-agentd.state
```

Debe decir:

```text
status='connected'
```

### Riesgo principal despues de un apagon

El mayor riesgo es que cambie la IP del PC de escritorio si usa DHCP.

Si `192.168.1.46` cambia, fallaran:

- el agente Wazuh del notebook
- la conexion de la app al indexer
- las pruebas de sincronizacion

Solucion recomendada:

> Configurar IP fija o reserva DHCP para el PC de escritorio, manteniendo `192.168.1.46`.

## 25. Cambios realizados en el proyecto

Cambios funcionales importantes:

1. Se cambio la base a TimescaleDB/PostgreSQL para soportar series de tiempo.
2. Se agregaron tablas `managers`, `assets`, `vulnerability_catalog` y `vulnerability_detections`.
3. Se convirtio `vulnerability_detections` en hypertable.
4. Se agrego procesamiento historico de vulnerabilidades:

```text
Detected
Resolved
Re-emerged
```

5. Se agregaron endpoints de evolucion:

```text
/vulns/evolution/summary
/vulns/evolution/weekly
/vulns/evolution/top-assets
```

6. Se agregaron metricas al dashboard:

```text
Activas
Resueltas
Assets
Eventos historicos
Tendencia semanal
Top servidores vulnerables
```

7. Se corrigio la eliminacion de conexiones Wazuh antiguas para borrar tambien sus datos relacionados.
8. Se eliminaron conexiones antiguas y quedo una sola conexion valida:

```text
conexion timestamp -> https://192.168.1.46:9200
```

9. Se corrigio la configuracion del agente Wazuh del notebook, cambiando la IP antigua:

```text
192.168.1.245
```

por la IP correcta:

```text
192.168.1.46
```

## 26. Explicacion corta para decir al profesor

> Tenemos Wazuh instalado en un PC de escritorio con IP 192.168.1.46. Mi notebook tiene el agente Wazuh instalado y ahora aparece Active porque apunta al manager correcto por el puerto 1514. La aplicacion corre en el notebook con Docker: un frontend Vue en Nginx, un backend FastAPI y una base TimescaleDB/PostgreSQL. El backend no obtiene datos falsos ni estaticos; se conecta por REST al Wazuh Indexer en https://192.168.1.46:9200, consulta el indice wazuh-states-vulnerabilities-*, procesa las vulnerabilidades y las guarda en nuestra base propia. Ademas, guardamos eventos historicos en una hypertable para demostrar evolucion temporal: detectadas, resueltas y reaparecidas.

## 27. Demostracion rapida en 10 comandos

1. Ver agente conectado:

```bash
sudo grep ^status /var/ossec/var/run/wazuh-agentd.state
```

2. Ver puertos Wazuh:

```bash
nc -vz 192.168.1.46 1514
nc -vz 192.168.1.46 1515
```

3. Ver indexer:

```bash
curl -k -u admin:admin https://192.168.1.46:9200
```

4. Ver contenedores:

```bash
cd /home/sidwilson0/Escritorio/devsecops
docker compose ps
```

5. Ver frontend:

```bash
curl -k -I https://127.0.0.1/
```

6. Ver API:

```bash
curl -k https://127.0.0.1/api/openapi.json | head
```

7. Ver conexion Wazuh guardada:

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select id, name, indexer_url, last_test_ok from wazuh_connections;"'
```

8. Ver vulnerabilidades actuales:

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select status, count(*) from wazuh_vulnerabilities group by status;"'
```

9. Ver eventos historicos:

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select status, count(*) from vulnerability_detections group by status;"'
```

10. Ver hypertable:

```bash
docker compose exec -T db-api sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "select hypertable_name from timescaledb_information.hypertables where hypertable_name = '\''vulnerability_detections'\'';"'
```

## 28. Sugerencias de mejora

1. Configurar IP fija o reserva DHCP para el PC de escritorio.
2. Cambiar credenciales por defecto `admin/admin`.
3. Automatizar sincronizacion cada cierto tiempo, por ejemplo cada 6 horas.
4. Agregar backups automaticos del volumen `postgres_api_data`.
5. Usar HashiCorp Vault real para secretos en una version mas avanzada.
6. Agregar una pantalla de detalle por CVE con grafico de primera aparicion, ultima aparicion y duracion activa.
7. Agregar filtros por severidad, agente, paquete y rango de fechas en la vista de evolucion.
8. Documentar un procedimiento de recuperacion ante reinicio del PC Wazuh.
9. Mantener Jenkins y SonarQube como evidencia de practicas DevSecOps.

## 29. Conclusion

La aplicacion cumple el objetivo principal: se comunica correctamente con Wazuh, extrae vulnerabilidades reales desde el Wazuh Indexer, las guarda en una base propia y estructura la informacion para mostrar evolucion temporal.

La parte mas importante para defender es:

```text
Wazuh detecta -> Wazuh Indexer almacena -> Backend consulta -> TimescaleDB guarda -> Frontend visualiza
```

Esto demuestra integracion real, persistencia propia, arquitectura separada por capas y una base preparada para series de tiempo.

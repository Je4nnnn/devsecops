# Despliegue en Windows con Docker Desktop

## Requisitos

- Windows 10 u 11 de 64 bits.
- Docker Desktop iniciado, usando contenedores Linux.
- Docker Compose v2, incluido en Docker Desktop.
- Al menos 6 GB de RAM asignados a Docker Desktop para ejecutar cómodamente aplicación, Jenkins, SonarQube y los análisis.

No es necesario instalar PostgreSQL, Node.js, Python, Wazuh, Bash ni OpenSSL para el inicio normal.

## Opción rápida: Docker Compose

Abra PowerShell en la raíz del repositorio y ejecute:

```powershell
docker compose up -d
docker compose ps
```

El mismo comando levanta todo el entorno:

- Aplicación: `http://localhost:18080` — `admin` / `Admin1234!`
- Jenkins: `http://localhost:8080` — `admin` / `AdminJenkins123!`
- SonarQube: `http://localhost:9000` — `admin` / `AdminSonar123!`

Jenkins crea automáticamente el job `devsecops-pipeline` y recibe un token generado por SonarQube. Presione **Build Now** para ejecutar el pipeline. Los puertos quedan ligados a `127.0.0.1`; las credenciales incorporadas son solo para una prueba local.

Si anteriormente levantó Jenkins o SonarQube por separado, libere una vez sus nombres y puertos sin borrar volúmenes:

```powershell
docker compose -f .\dev-tools\jenkins\docker-compose.yml down
docker compose -f .\dev-tools\sonarqube\docker-compose.yml down
docker compose up -d
```

## Opción recomendada: secretos propios

Ejecute:

```powershell
powershell -ExecutionPolicy Bypass -File .\iniciar_app.ps1
```

El script crea o migra `.env`, genera secretos aleatorios para los tres accesos, descarga las imágenes públicas y conserva los volúmenes. Anote las contraseñas que muestra una sola vez.

Para compilar las imágenes desde el código:

```powershell
powershell -ExecutionPolicy Bypass -File .\iniciar_app.ps1 -Mode Build
```

Para agregar HTTPS autofirmado, Docker descargará una pequeña imagen auxiliar:

```powershell
powershell -ExecutionPolicy Bypass -File .\iniciar_app.ps1 -EnableHttps
```

Accesos:

- HTTP: `http://localhost:18080`
- HTTPS opcional: `https://localhost:18443`
- API: `http://localhost:18080/api/docs`
- Jenkins: `http://localhost:8080`
- SonarQube: `http://localhost:9000`

## Datos y reinicios

La base de la aplicación permanece en `vuln-app-wazuh_postgres_api_data`. Jenkins y SonarQube usan volúmenes independientes.

```powershell
docker compose stop
docker compose start
docker compose down
docker compose up -d
```

Esos comandos conservan los datos. `docker compose down -v` elimina la base sincronizada, la configuración de Jenkins, el token automático y los datos de SonarQube.

## Acceso desde otro computador de la LAN

Primero use el script para generar secretos. Después cambie `BIND_ADDRESS=0.0.0.0` en `.env` y vuelva a crear los servicios:

```powershell
docker compose --env-file .env up -d
```

Autorice TCP 18080 en el Firewall de Windows únicamente para la red privada necesaria. Acceda mediante `http://IP_DEL_EQUIPO:18080`. No exponga el servicio directamente a Internet.

## Diagnóstico

```powershell
docker compose ps
docker compose logs --tail 200 api
docker compose logs --tail 200 frontend
docker compose logs --tail 200 db-api
docker compose logs --tail 200 jenkins
docker compose logs --tail 200 sonarqube
docker compose logs --tail 200 sonar-init
```

Si aparece `pull access denied`, confirme que Compose referencia `matiassandovalp/devsecops-api:entrega3-portable-v6` y `matiassandovalp/devsecops-frontend:entrega3-portable-v6`, y que Docker Desktop tiene Internet.

## Seguridad del pipeline

Jenkins monta `/var/run/docker.sock` para construir imágenes y ejecutar Trivy/ZAP. Esto le entrega control administrativo sobre Docker Desktop, incluidos sus contenedores y volúmenes. Use este stack únicamente en un computador de desarrollo controlado y limite quién puede modificar la rama o ejecutar jobs.

# Vulnerability Aggregator

Aplicación para sincronizar vulnerabilidades desde Wazuh, almacenarlas en un modelo PostgreSQL/TimescaleDB normalizado y analizarlas mediante Dashboard y Timeline.

Esta rama integra:

- El modelo de datos y dashboard de `entrega3-modelo-escalable`.
- Los tests, cobertura y quality gates de `qa-quality-gates`.
- Un despliegue Docker reproducible y un paquete offline para Kali Linux.

## Inicio inmediato con Docker Compose

En un clon nuevo, con Docker Desktop o Docker Engine y Compose v2:

```bash
docker compose up -d
```

Esto descarga las imágenes públicas y levanta en un solo stack la aplicación, PostgreSQL/TimescaleDB, SonarQube y Jenkins con el job `devsecops-pipeline` preconfigurado. No requiere `.env`, Bash ni OpenSSL.

Accesos locales de demostración:

- Aplicación: `http://localhost:18080` — `admin` / `Admin1234!`
- Jenkins: `http://localhost:8080` — `admin` / `AdminJenkins123!`
- SonarQube: `http://localhost:9000` — `admin` / `AdminSonar123!`

Los puertos quedan ligados a `127.0.0.1`. Use estas credenciales únicamente para una prueba local.

Si Jenkins o SonarQube estaban levantados con los Compose antiguos, deténgalos una vez antes de migrar:

```bash
docker compose -f dev-tools/jenkins/docker-compose.yml down
docker compose -f dev-tools/sonarqube/docker-compose.yml down
docker compose up -d
```

Para revisar el estado o detenerla sin borrar datos:

```bash
docker compose ps
docker compose down
```

No ejecute `docker compose down -v`: elimina la base de la aplicación y también los datos persistentes de Jenkins y SonarQube. `docker compose down` conserva todos los volúmenes.

## Inicio reforzado mediante scripts

Los scripts crean o migran `.env` con contraseñas aleatorias para la aplicación, PostgreSQL, Jenkins y SonarQube, además del JWT y la clave Fernet. Las contraseñas nuevas se muestran una sola vez.

Linux, Ubuntu o Kali:

```bash
./iniciar_app.sh          # descarga imágenes públicas y habilita HTTP + HTTPS
./iniciar_app.sh --build  # alternativa: compila desde el código fuente
```

Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\iniciar_app.ps1
powershell -ExecutionPolicy Bypass -File .\iniciar_app.ps1 -Mode Build
powershell -ExecutionPolicy Bypass -File .\iniciar_app.ps1 -EnableHttps
```

La guía de Windows está en [docs/DESPLIEGUE_WINDOWS.md](docs/DESPLIEGUE_WINDOWS.md).

## Despliegue offline en Kali

La guía completa está en [docs/DESPLIEGUE_OFFLINE_KALI.md](docs/DESPLIEGUE_OFFLINE_KALI.md).

```bash
./scripts/create-offline-bundle.sh entrega3-portable-v6
```

El resultado queda en `offline-dist/` e incluye imágenes, checksums, instalador, prueba de humo y utilidades de respaldo.

## Validación

Frontend:

```bash
cd frontend
npm ci
npm test -- --run
```

Backend mediante la etapa de test del contenedor:

```bash
docker build --target test -t devsecops-api-test ./vuln-api
docker run --rm -e PYTHONPATH=/app devsecops-api-test
```

Stack completo:

```bash
./scripts/smoke-test.sh
```

Jenkins carga el pipeline desde `dev-tools/jenkins/Jenkinsfile`, genera automáticamente su credencial de SonarQube y ejecuta Docker mediante el socket del host. Esta integración otorga a Jenkins control administrativo sobre Docker; úsela solo en un equipo de desarrollo controlado.

## Seguridad de configuración

- `.env`, certificados, claves y respaldos no se versionan.
- PostgreSQL no se publica en el host.
- La API y el frontend se ejecutan como usuarios no-root.
- Las imágenes base y dependencias se fijan a versiones/digests reproducibles.
- Cada despliegue debe generar su propia clave Fernet, JWT y contraseñas.

No reutilice un `.env` de demostración en otro equipo.

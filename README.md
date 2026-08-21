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

Esto descarga las imágenes públicas, crea PostgreSQL/TimescaleDB en un volumen local e inicia la aplicación en `http://localhost:18080`. No requiere `.env`, Bash ni OpenSSL. El acceso de demostración es `admin` / `Admin1234!` y el puerto queda ligado a `127.0.0.1`; use esta modalidad solo para una prueba local.

Para revisar el estado o detenerla sin borrar datos:

```bash
docker compose ps
docker compose down
```

No ejecute `docker compose down -v` si desea conservar la base. El volumen predeterminado es `vuln-app-wazuh_postgres_api_data`.

## Inicio reforzado mediante scripts

Los scripts crean `.env` con contraseñas, JWT y clave Fernet aleatorios. La primera ejecución muestra una sola vez la contraseña inicial del administrador.

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

Los pipelines de Jenkins, SonarQube, Trivy y OWASP ZAP se mantienen en `dev-tools/`.

## Seguridad de configuración

- `.env`, certificados, claves y respaldos no se versionan.
- PostgreSQL no se publica en el host.
- La API y el frontend se ejecutan como usuarios no-root.
- Las imágenes base y dependencias se fijan a versiones/digests reproducibles.
- Cada despliegue debe generar su propia clave Fernet, JWT y contraseñas.

No reutilice un `.env` de demostración en otro equipo.

# Despliegue en Windows con Docker Desktop

## Requisitos

- Windows 10 u 11 de 64 bits.
- Docker Desktop iniciado, usando contenedores Linux.
- Docker Compose v2, incluido en Docker Desktop.
- Espacio libre para las imágenes y el volumen de PostgreSQL.

No es necesario instalar PostgreSQL, Node.js, Python, Wazuh, Bash ni OpenSSL para el inicio normal.

## Opción rápida: Docker Compose

Abra PowerShell en la raíz del repositorio y ejecute:

```powershell
docker compose up -d
docker compose ps
```

Abra `http://localhost:18080`. En un clon sin `.env`, el acceso local de demostración es:

- Usuario: `admin`
- Contraseña: `Admin1234!`

Esta opción liga el puerto a `127.0.0.1`, por lo que solo responde en ese computador. Los valores incorporados son únicamente para una prueba local.

## Opción recomendada: secretos propios

Ejecute:

```powershell
powershell -ExecutionPolicy Bypass -File .\iniciar_app.ps1
```

El script crea `.env` solo si no existe, genera secretos aleatorios, descarga las imágenes públicas y conserva el volumen entre reinicios. Anote la contraseña inicial que muestra una sola vez.

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

## Datos y reinicios

La base no está dentro de la imagen. Docker la guarda en el volumen `vuln-app-wazuh_postgres_api_data`.

```powershell
docker compose stop
docker compose start
docker compose down
docker compose up -d
```

Esos comandos conservan los datos. `docker compose down -v` elimina el volumen y la base; no lo ejecute si debe conservar una sincronización.

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
```

Si aparece `pull access denied`, confirme que Compose referencia `matiassandovalp/devsecops-api:entrega3-portable-v6` y `matiassandovalp/devsecops-frontend:entrega3-portable-v6`, y que Docker Desktop tiene Internet.

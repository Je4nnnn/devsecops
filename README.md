# Vulnerability Aggregator

Aplicación para sincronizar vulnerabilidades desde Wazuh, almacenarlas en un modelo PostgreSQL/TimescaleDB normalizado y analizarlas mediante Dashboard y Timeline.

Esta rama integra:

- El modelo de datos y dashboard de `entrega3-modelo-escalable`.
- Los tests, cobertura y quality gates de `qa-quality-gates`.
- Un despliegue Docker reproducible y un paquete offline para Kali Linux.

## Despliegue recomendado en Kali

La guía completa se encuentra en:

[docs/DESPLIEGUE_OFFLINE_KALI.md](docs/DESPLIEGUE_OFFLINE_KALI.md)

Para generar el paquete transportable:

```bash
./scripts/create-offline-bundle.sh entrega3-portable-v4
```

El resultado queda en `offline-dist/` e incluye las imágenes de base, API y frontend, checksums, instalador, prueba de humo y utilidades de respaldo.

## Ejecución local con Internet

Requisitos: Docker Engine, Docker Compose v2 y OpenSSL.

```bash
cp .env.example .env
nano .env
sudo ./iniciar_app.sh
```

Antes de iniciar, reemplace todos los valores `REEMPLAZAR_*` de `.env`. El script genera un certificado autofirmado local sin sobrescribir Compose ni modificar cronjobs.

Acceso predeterminado:

- HTTP: `http://localhost:18080`
- HTTPS: `https://localhost:18443`
- API: `https://localhost:18443/api/docs`

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

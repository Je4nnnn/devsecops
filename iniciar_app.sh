#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "${PROJECT_DIR}"

MODE="${1:---pull}"
if [ "${MODE}" != "--pull" ] && [ "${MODE}" != "--build" ]; then
  echo "Uso: ./iniciar_app.sh [--pull|--build]" >&2
  exit 2
fi

for command_name in docker openssl sed; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "ERROR: falta el comando ${command_name}." >&2
    exit 2
  fi
done

if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: se requiere Docker Compose v2 (comando docker compose)." >&2
  exit 2
fi

if [ ! -f .env ]; then
  cp .env.example .env
  postgres_password="$(openssl rand -hex 24)"
  admin_password="$(openssl rand -base64 18 | tr -d '\n' | tr '/+' '_-')"
  jwt_secret="$(openssl rand -hex 48)"
  encryption_key="$(openssl rand -base64 32 | tr '/+' '_-' | tr -d '\n')"
  sed -i \
    -e "s|REEMPLAZAR_POSTGRES_PASSWORD|${postgres_password}|" \
    -e "s|REEMPLAZAR_ADMIN_PASSWORD|${admin_password}|" \
    -e "s|REEMPLAZAR_JWT_SECRET|${jwt_secret}|" \
    -e "s|REEMPLAZAR_ENCRYPTION_KEY|${encryption_key}|" .env
  chmod 600 .env
  echo "Se creo .env con secretos aleatorios."
  echo "Usuario inicial: admin"
  echo "Contrasena inicial: ${admin_password}"
  echo "Guardela ahora; no se volvera a mostrar."
fi

if grep -q 'REEMPLAZAR_' .env; then
  echo "ERROR: .env contiene valores REEMPLAZAR_*; elimine .env para regenerarlo o complete los valores." >&2
  exit 2
fi

mkdir -p nginx/ssl
chmod 755 nginx nginx/ssl
if [ ! -s nginx/ssl/nginx-selfsigned.key ] || [ ! -s nginx/ssl/nginx-selfsigned.crt ]; then
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout nginx/ssl/nginx-selfsigned.key \
    -out nginx/ssl/nginx-selfsigned.crt \
    -subj "/C=CL/O=DevSecOps/CN=localhost" >/dev/null 2>&1
fi
chmod 644 nginx/ssl/nginx-selfsigned.key nginx/ssl/nginx-selfsigned.crt

compose=(docker compose --env-file .env -f docker-compose.yml -f docker-compose.tls.yml)
"${compose[@]}" config --quiet

if [ "${MODE}" = "--build" ]; then
  APP_PULL_POLICY=build "${compose[@]}" up -d --build
else
  "${compose[@]}" pull
  "${compose[@]}" up -d --no-build
fi

echo
echo "Servicios iniciados. Revise el estado con:"
echo "  docker compose --env-file .env -f docker-compose.yml -f docker-compose.tls.yml ps"
echo "Acceso:"
echo "  http://localhost:18080"
echo "  https://localhost:18443"

#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "${PROJECT_DIR}"

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: ejecute sudo ./iniciar_app.sh para preparar permisos TLS y Docker." >&2
  exit 2
fi

for command_name in docker openssl; do
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
  chmod 600 .env
  echo "Se creo .env desde la plantilla." >&2
  echo "Reemplace todos los valores REEMPLAZAR_* y vuelva a ejecutar el script." >&2
  exit 2
fi

if grep -q 'REEMPLAZAR_' .env; then
  echo "ERROR: .env contiene secretos sin configurar (REEMPLAZAR_*)." >&2
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
chown 101:101 nginx/ssl/nginx-selfsigned.key nginx/ssl/nginx-selfsigned.crt
chmod 600 nginx/ssl/nginx-selfsigned.key
chmod 644 nginx/ssl/nginx-selfsigned.crt

docker compose --env-file .env config --quiet
docker compose --env-file .env up -d --build

echo
echo "Servicios iniciados. Revise el estado con:"
echo "  docker compose --env-file .env ps"
echo "Acceso:"
echo "  http://localhost:18080"
echo "  https://localhost:18443"

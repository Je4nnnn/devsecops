#!/usr/bin/env bash
set -Eeuo pipefail

if [ "$#" -ne 2 ] || [ "$2" != "--confirmar-restauracion" ]; then
  echo "Uso: $0 ARCHIVO.dump --confirmar-restauracion" >&2
  echo "ADVERTENCIA: reemplaza los objetos existentes de la base." >&2
  exit 2
fi

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
BACKUP_PATH="$(realpath "$1")"
cd "${SCRIPT_DIR}"

if [ ! -s "${BACKUP_PATH}" ]; then
  echo "ERROR: respaldo inexistente o vacio: ${BACKUP_PATH}" >&2
  exit 2
fi

if [ -f "${BACKUP_PATH}.sha256" ]; then
  (cd "$(dirname "${BACKUP_PATH}")" && sha256sum -c "$(basename "${BACKUP_PATH}").sha256")
fi

if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  echo "ERROR: no se encontro Docker Compose." >&2
  exit 2
fi

if [ -f images.tar.gz ]; then
  COMPOSE_FILE=docker-compose.offline.yml
else
  cd ..
  COMPOSE_FILE=docker-compose.yml
fi

compose() {
  "${COMPOSE[@]}" --env-file .env -f "${COMPOSE_FILE}" "$@"
}

echo "Deteniendo API durante la restauracion..."
compose stop api

restore_mode=false
cleanup() {
  if [ "${restore_mode}" = true ]; then
    compose exec -T db-api sh -lc \
      'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT timescaledb_post_restore();"' \
      >/dev/null 2>&1 || true
  fi
  compose start api >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Recreando la base de destino..."
compose exec -T db-api sh -lc \
  'dropdb --force --if-exists -U "$POSTGRES_USER" "$POSTGRES_DB" && createdb -U "$POSTGRES_USER" -O "$POSTGRES_USER" "$POSTGRES_DB"'

compose exec -T db-api sh -lc \
  'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "CREATE EXTENSION IF NOT EXISTS timescaledb; SELECT timescaledb_pre_restore();"'
restore_mode=true

compose exec -T db-api sh -lc \
  'pg_restore --exit-on-error --no-owner --no-privileges -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
  < "${BACKUP_PATH}"

compose exec -T db-api sh -lc \
  'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT timescaledb_post_restore();"'
restore_mode=false

compose start api
trap - EXIT
echo "Restauracion completada."

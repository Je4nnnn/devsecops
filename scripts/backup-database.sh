#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "${SCRIPT_DIR}"

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

BACKUP_DIR="${1:-backups}"
mkdir -p "${BACKUP_DIR}"
BACKUP_PATH="${BACKUP_DIR}/vulnerabilidades_$(date -u +%Y%m%dT%H%M%SZ).dump"

compose exec -T db-api sh -lc 'pg_dump -Fc -U "$POSTGRES_USER" "$POSTGRES_DB"' > "${BACKUP_PATH}"
(
  cd "$(dirname "${BACKUP_PATH}")"
  sha256sum "$(basename "${BACKUP_PATH}")" > "$(basename "${BACKUP_PATH}").sha256"
)
chmod 600 "${BACKUP_PATH}" "${BACKUP_PATH}.sha256"

echo "Respaldo creado: ${BACKUP_PATH}"

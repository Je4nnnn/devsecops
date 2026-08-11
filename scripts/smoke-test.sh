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
  COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.offline.yml}"
else
  PROJECT_DIR="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)"
  cd "${PROJECT_DIR}"
  COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
fi

compose() {
  "${COMPOSE[@]}" --env-file .env -f "${COMPOSE_FILE}" "$@"
}

echo "== Estado de contenedores =="
compose ps

for service in db-api api frontend; do
  container_id="$(compose ps -q "${service}")"
  if [ -z "${container_id}" ]; then
    echo "ERROR: no existe contenedor para ${service}." >&2
    exit 1
  fi
  health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${container_id}")"
  if [ "${health}" != "healthy" ]; then
    echo "ERROR: ${service} tiene estado ${health}." >&2
    exit 1
  fi
  echo "OK: ${service} healthy"
done

compose exec -T db-api sh -lc 'pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"' >/dev/null
echo "OK: PostgreSQL acepta conexiones"

compose exec -T api python -c \
  "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/docs', timeout=5).read(32)" >/dev/null
echo "OK: backend FastAPI responde"

compose exec -T frontend wget -qO- http://127.0.0.1/ >/dev/null
echo "OK: frontend Nginx responde"

compose exec -T db-api sh -lc 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "
   SELECT to_regclass('\''public.packages'\'') AS packages,
          to_regclass('\''public.vulnerability_findings'\'') AS findings,
          to_regclass('\''public.vulnerability_detections'\'') AS detections;
  "'

echo "SMOKE TEST: OK"

#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PROJECT_DIR="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_DIR}"

BUNDLE_VERSION="${1:-entrega3-$(git rev-parse --short HEAD)}"
case "${BUNDLE_VERSION}" in
  *[!A-Za-z0-9._-]*|'')
    echo "ERROR: version invalida. Use solo letras, numeros, punto, guion o guion bajo." >&2
    exit 2
    ;;
esac

SOURCE_DB_IMAGE="${SOURCE_DB_IMAGE:-timescale/timescaledb@sha256:867dc9cbb3232dece516122d49e56ce472754fe31cbffb54d64920f8d2ed79b6}"
DB_IMAGE="devsecops-db:${BUNDLE_VERSION}"
API_IMAGE="devsecops-api:${BUNDLE_VERSION}"
FRONTEND_IMAGE="devsecops-frontend:${BUNDLE_VERSION}"
OUTPUT_ROOT="${PROJECT_DIR}/offline-dist"
BUNDLE_NAME="devsecops-${BUNDLE_VERSION}"
BUNDLE_DIR="${OUTPUT_ROOT}/${BUNDLE_NAME}"
ARCHIVE_PATH="${OUTPUT_ROOT}/${BUNDLE_NAME}.tar.gz"

mkdir -p "${OUTPUT_ROOT}"
if [ -e "${BUNDLE_DIR}" ] || [ -e "${ARCHIVE_PATH}" ]; then
  echo "ERROR: ya existe una salida para ${BUNDLE_VERSION} en offline-dist/." >&2
  echo "Use otra version o retire manualmente el artefacto anterior." >&2
  exit 2
fi

WORK_DIR="$(mktemp -d "${OUTPUT_ROOT}/.bundle.XXXXXX")"
cleanup() {
  if [ -n "${WORK_DIR:-}" ] && [ -d "${WORK_DIR}" ]; then
    rm -rf -- "${WORK_DIR}"
  fi
}
trap cleanup EXIT

echo "[1/6] Verificando Docker..."
docker info >/dev/null

echo "[2/6] Construyendo API ${API_IMAGE}..."
docker build \
  --target production \
  --tag "${API_IMAGE}" \
  "${PROJECT_DIR}/vuln-api"

echo "[3/6] Construyendo frontend ${FRONTEND_IMAGE}..."
docker build \
  --build-arg VITE_API_URL=/api \
  --tag "${FRONTEND_IMAGE}" \
  "${PROJECT_DIR}/frontend"

echo "[4/6] Preparando TimescaleDB..."
if ! docker image inspect "${SOURCE_DB_IMAGE}" >/dev/null 2>&1; then
  docker pull "${SOURCE_DB_IMAGE}"
fi
docker tag "${SOURCE_DB_IMAGE}" "${DB_IMAGE}"

ARCHITECTURE="$(docker image inspect "${API_IMAGE}" --format '{{.Architecture}}')"
printf '%s\n' "${BUNDLE_VERSION}" > "${WORK_DIR}/VERSION"
printf '%s\n' "${ARCHITECTURE}" > "${WORK_DIR}/PLATFORM"
git rev-parse HEAD > "${WORK_DIR}/SOURCE_COMMIT"

echo "[5/6] Exportando imagenes (puede tardar varios minutos)..."
docker save "${DB_IMAGE}" "${API_IMAGE}" "${FRONTEND_IMAGE}" \
  | gzip -9 > "${WORK_DIR}/images.tar.gz"

(
  cd "${WORK_DIR}"
  sha256sum images.tar.gz > images.tar.gz.sha256
)

sed \
  -e "s/^APP_VERSION=.*/APP_VERSION=${BUNDLE_VERSION}/" \
  -e "s|^DB_IMAGE=.*|DB_IMAGE=${DB_IMAGE}|" \
  -e "s|^API_IMAGE=.*|API_IMAGE=${API_IMAGE}|" \
  -e "s|^FRONTEND_IMAGE=.*|FRONTEND_IMAGE=${FRONTEND_IMAGE}|" \
  "${PROJECT_DIR}/.env.example" > "${WORK_DIR}/.env.example"
mkdir -p "${WORK_DIR}/nginx"

cp "${PROJECT_DIR}/docker-compose.offline.yml" "${WORK_DIR}/"
cp "${PROJECT_DIR}/frontend/nginx-https.conf" "${WORK_DIR}/nginx/"
cp "${PROJECT_DIR}/scripts/deploy-kali-offline.sh" "${WORK_DIR}/deploy.sh"
cp "${PROJECT_DIR}/scripts/smoke-test.sh" "${WORK_DIR}/smoke-test.sh"
cp "${PROJECT_DIR}/scripts/backup-database.sh" "${WORK_DIR}/backup-database.sh"
cp "${PROJECT_DIR}/scripts/restore-database.sh" "${WORK_DIR}/restore-database.sh"
cp "${PROJECT_DIR}/docs/DESPLIEGUE_OFFLINE_KALI.md" "${WORK_DIR}/README.md"
chmod +x "${WORK_DIR}"/*.sh

docker image inspect "${DB_IMAGE}" "${API_IMAGE}" "${FRONTEND_IMAGE}" \
  > "${WORK_DIR}/image-manifest.json"

mv "${WORK_DIR}" "${BUNDLE_DIR}"
WORK_DIR=""

echo "[6/6] Comprimiendo paquete final..."
tar -czf "${ARCHIVE_PATH}" -C "${OUTPUT_ROOT}" "${BUNDLE_NAME}"
(
  cd "${OUTPUT_ROOT}"
  sha256sum "${BUNDLE_NAME}.tar.gz" > "${BUNDLE_NAME}.tar.gz.sha256"
)

echo
echo "Paquete offline creado:"
echo "  ${ARCHIVE_PATH}"
echo "  ${ARCHIVE_PATH}.sha256"
echo "Arquitectura: ${ARCHITECTURE}"

#!/bin/bash
set -euo pipefail

BUILD_ID=${1:?Uso: run_zap.sh <build-id>}
NETWORK="${NETWORK:-vuln-app-wazuh_app-network}"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-}"
TARGET_API="${TARGET_API:-http://api:8000/openapi.json}"
TARGET_FRONTEND="${TARGET_FRONTEND:-http://frontend:80}"
API_HEALTH_URL="${API_HEALTH_URL:-http://api:8000/docs}"
APP_USERNAME="${APP_USERNAME:-admin}"
APP_PASSWORD="${APP_PASSWORD:-admin}"
ZAP_DOCKER_ARGS=(
    --user root
    --network="${NETWORK}"
    -v "$(pwd)/reports:/zap/wrk:rw"
    -w /zap/wrk
)

mkdir -p reports

if [ -f /.dockerenv ] && docker inspect jenkins >/dev/null 2>&1; then
    JENKINS_HOME_SOURCE=$(docker inspect jenkins \
        --format '{{range .Mounts}}{{if eq .Destination "/var/jenkins_home"}}{{.Source}}{{end}}{{end}}')

    case "$(pwd)" in
        /var/jenkins_home/*)
            HOST_REPORTS="${JENKINS_HOME_SOURCE}${PWD#/var/jenkins_home}/reports"
            ZAP_DOCKER_ARGS=(
                --user root
                --network="${NETWORK}"
                -v "${HOST_REPORTS}:/zap/wrk:rw"
                -w /zap/wrk
            )
            ;;
        *)
            echo "ERROR: no se pudo mapear el workspace de Jenkins a una ruta del host Docker." >&2
            exit 1
            ;;
    esac
fi

echo "--- Iniciando escaneo DAST OWASP ZAP (Build ${BUILD_ID}) ---"
echo "Esperando API en ${API_HEALTH_URL} dentro de la red ${NETWORK}..."

MAX_RETRIES=30
COUNT=0

probe_in_network() {
    docker run --rm --network="${NETWORK}" curlimages/curl:8.12.1 \
        --output /dev/null --silent --head --fail "${API_HEALTH_URL}"
}

until probe_in_network; do
    if [ "${COUNT}" -eq "${MAX_RETRIES}" ]; then
        echo "ERROR: La API no levanto despues de $((MAX_RETRIES * 2)) segundos. Abortando ZAP."
        exit 1
    fi
    printf '.'
    sleep 2
    COUNT=$((COUNT + 1))
done

echo
echo "API lista. Obteniendo token de acceso para escaneo autenticado..."
RESPONSE=$(docker run --rm --network="${NETWORK}" curlimages/curl:8.12.1 \
    -s -X POST http://api:8000/auth/login \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${APP_USERNAME}&password=${APP_PASSWORD}")

TOKEN=$(printf '%s' "${RESPONSE}" | python3 -c "import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('access_token', ''))
except Exception:
    print('')")

ZAP_AUTH_ARGS=()
if [ -n "${TOKEN}" ]; then
    echo "Token obtenido. El escaneo API usara header Authorization."
    ZAP_AUTH_ARGS=(
        -z "-config replacer.full_list(0).description=auth-header -config replacer.full_list(0).enabled=true -config replacer.full_list(0).matchtype=REQ_HEADER -config replacer.full_list(0).matchstr=Authorization -config replacer.full_list(0).replacement=Bearer ${TOKEN}"
    )
else
    echo "No se obtuvo token. ZAP continuara sin autenticacion."
fi

echo "--- ZAP API Scan ---"
docker run --rm \
    "${ZAP_DOCKER_ARGS[@]}" \
    ghcr.io/zaproxy/zaproxy:stable \
    zap-api-scan.py \
    -t "${TARGET_API}" \
    -f openapi \
    -r "zap_api_report_${BUILD_ID}.html" \
    -J "zap_api_report_${BUILD_ID}.json" \
    -I \
    "${ZAP_AUTH_ARGS[@]}"

echo "--- ZAP Frontend Baseline ---"
echo "Esperando frontend en ${TARGET_FRONTEND} dentro de la red ${NETWORK}..."
FRONTEND_COUNT=0
until docker run --rm --network="${NETWORK}" curlimages/curl:8.12.1 \
    --output /dev/null --silent --head --fail "${TARGET_FRONTEND}"; do
    if [ "${FRONTEND_COUNT}" -eq "${MAX_RETRIES}" ]; then
        echo "ERROR: El frontend no levanto despues de $((MAX_RETRIES * 2)) segundos. Abortando ZAP."
        if [ -n "${COMPOSE_PROJECT_NAME}" ]; then
            COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME}" docker compose -f docker-compose.yml ps || true
            COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME}" docker compose -f docker-compose.yml logs --tail=120 frontend || true
        fi
        exit 1
    fi
    printf '.'
    sleep 2
    FRONTEND_COUNT=$((FRONTEND_COUNT + 1))
done
echo

docker run --rm \
    "${ZAP_DOCKER_ARGS[@]}" \
    ghcr.io/zaproxy/zaproxy:stable \
    zap-baseline.py \
    -t "${TARGET_FRONTEND}" \
    -r "zap_frontend_report_${BUILD_ID}.html" \
    -J "zap_frontend_report_${BUILD_ID}.json" \
    -I

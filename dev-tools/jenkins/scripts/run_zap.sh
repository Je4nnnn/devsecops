#!/bin/bash
set -euo pipefail

BUILD_ID=${1:?Uso: run_zap.sh <build-id>}
NETWORK="${NETWORK:-vuln-app-wazuh_app-network}"
TARGET_API="${TARGET_API:-http://api:8000/openapi.json}"
TARGET_FRONTEND="${TARGET_FRONTEND:-http://frontend:80}"
API_HEALTH_URL="${API_HEALTH_URL:-http://api:8000/docs}"
APP_USERNAME="${APP_USERNAME:-admin}"
APP_PASSWORD="${APP_PASSWORD:-admin}"
JENKINS_CONTAINER="${JENKINS_CONTAINER:-jenkins}"
JENKINS_HOME_DIR="${JENKINS_HOME:-/var/jenkins_home}"
USE_JENKINS_VOLUMES=false

case "$(pwd)" in
    "$JENKINS_HOME_DIR"/*)
        if docker container inspect "$JENKINS_CONTAINER" >/dev/null 2>&1; then
            USE_JENKINS_VOLUMES=true
        fi
        ;;
esac

mkdir -p reports

echo "--- Iniciando escaneo DAST OWASP ZAP (Build ${BUILD_ID}) ---"
echo "Esperando API en ${API_HEALTH_URL} dentro de la red ${NETWORK}..."

MAX_RETRIES=30
COUNT=0

probe_in_network() {
    docker run --rm --network="${NETWORK}" curlimages/curl:8.12.1 \
        --output /dev/null --silent --head --fail "${API_HEALTH_URL}"
}

zap() {
    if [ "$USE_JENKINS_VOLUMES" = "true" ]; then
        docker run --rm \
            --user root \
            --network="${NETWORK}" \
            --volumes-from "$JENKINS_CONTAINER" \
            -e "ZAP_REPORT_DIR=$(pwd)/reports" \
            --entrypoint /bin/bash \
            ghcr.io/zaproxy/zaproxy:stable \
            -c 'rm -rf /zap/wrk && ln -s "$ZAP_REPORT_DIR" /zap/wrk && exec "$@"' \
            zap-runner "$@"
    else
        docker run --rm \
            --user root \
            --network="${NETWORK}" \
            -v "$(pwd)/reports:/zap/wrk:rw" \
            ghcr.io/zaproxy/zaproxy:stable \
            "$@"
    fi
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
zap \
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
        exit 1
    fi
    printf '.'
    sleep 2
    FRONTEND_COUNT=$((FRONTEND_COUNT + 1))
done
echo

zap \
    zap-baseline.py \
    -t "${TARGET_FRONTEND}" \
    -r "zap_frontend_report_${BUILD_ID}.html" \
    -J "zap_frontend_report_${BUILD_ID}.json" \
    -I

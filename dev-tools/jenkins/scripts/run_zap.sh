#!/bin/bash
BUILD_ID=$1
NETWORK="${NETWORK:-vuln-app-wazuh_app-network}"
TARGET_API="${TARGET_API:-http://api:8000/openapi.json}"
TARGET_FRONTEND="${TARGET_FRONTEND:-http://frontend:80}"

echo "--- Iniciando Escaneo Profundo DAST (Build $BUILD_ID) ---"

echo "Esperando a que la API responda en http://api:8000/docs..."
MAX_RETRIES=30
COUNT=0

probe_in_network() {
    docker run --rm --network="$NETWORK" curlimages/curl:8.12.1 \
        --output /dev/null --silent --head --fail http://api:8000/docs
}

# Solución al bucle infinito
until probe_in_network; do
    if [ ${COUNT} -eq ${MAX_RETRIES} ]; then
        echo -e "\nERROR: La API no levantó después de 60 segundos. Abortando escaneo ZAP."
        exit 1
    fi
    printf '.'
    sleep 2
    COUNT=$((COUNT+1))
done

echo -e "\n¡La API está lista!"

echo "Obteniendo token de acceso para escaneo autenticado..."
RESPONSE=$(docker run --rm --network="$NETWORK" curlimages/curl:8.12.1 \
    -s -X POST http://api:8000/auth/login \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=admin&password=admin")

TOKEN=$(echo "$RESPONSE" | python3 -c "import sys, json; 
try:
    data = json.load(sys.stdin)
    print(data.get('access_token', ''))
except:
    print('')
")

ZAP_AUTH_ARGS=()
if [ -n "$TOKEN" ]; then
    echo "Token obtenido con éxito."
    ZAP_AUTH_ARGS=(
        -z "-config replacer.full_list(0).description=auth-header -config replacer.full_list(0).enabled=true -config replacer.full_list(0).matchtype=REQ_HEADER -config replacer.full_list(0).matchstr=Authorization -config replacer.full_list(0).replacement=Bearer $TOKEN"
    )
fi

echo "--- Fase 1: Escaneando Backend (API) ---"
docker run --rm \
    --user root \
    --network=$NETWORK \
    -v "$(pwd)/reports:/zap/wrk:rw" \
    ghcr.io/zaproxy/zaproxy:stable \
    zap-api-scan.py \
    -t "$TARGET_API" \
    -f openapi \
    -r "zap_api_report_${BUILD_ID}.html" \
    -I \
    "${ZAP_AUTH_ARGS[@]}" || echo "ZAP API finalizó" 
    # El flag -I evita que el script falle violentamente si ZAP encuentra warnings menores

echo "--- Fase 2: Escaneando Frontend (Baseline Spider) ---"
docker run --rm \
    --user root \
    --network=$NETWORK \
    -v "$(pwd)/reports:/zap/wrk:rw" \
    ghcr.io/zaproxy/zaproxy:stable \
    zap-baseline.py \
    -t "$TARGET_FRONTEND" \
    -r "zap_frontend_report_${BUILD_ID}.html" \
    -I || echo "ZAP Frontend finalizó"

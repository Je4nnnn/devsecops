#!/bin/sh
set -eu

BUILD_ID="${1:?Uso: run_trivy.sh <build-id> [fs|images|all]}"
MODE="${2:-all}"
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy:latest}"
TRIVY_SEVERITY="${TRIVY_SEVERITY:-${TRIVY_FAIL_SEVERITIES:-CRITICAL,HIGH}}"
TRIVY_IGNORE_UNFIXED="${TRIVY_IGNORE_UNFIXED:-true}"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-jenkins-security}"
BACKEND_IMAGE="${BACKEND_IMAGE:-${COMPOSE_PROJECT_NAME}-api}"
FRONTEND_IMAGE="${FRONTEND_IMAGE:-${COMPOSE_PROJECT_NAME}-frontend}"
CACHE_DIR="${TRIVY_CACHE_DIR:-$(pwd)/.trivy-cache}"
JENKINS_CONTAINER="${JENKINS_CONTAINER:-jenkins}"
JENKINS_HOME_DIR="${JENKINS_HOME:-/var/jenkins_home}"
USE_JENKINS_VOLUMES=false
IGNORE_UNFIXED_FLAG=""

case "$(pwd)" in
    "$JENKINS_HOME_DIR"/*)
        if docker container inspect "$JENKINS_CONTAINER" >/dev/null 2>&1; then
            USE_JENKINS_VOLUMES=true
        fi
        ;;
esac

if [ "$TRIVY_IGNORE_UNFIXED" = "true" ]; then
    IGNORE_UNFIXED_FLAG="--ignore-unfixed"
fi

mkdir -p reports "$CACHE_DIR"

restore_cache_owner() {
    if [ "$USE_JENKINS_VOLUMES" = "true" ]; then
        docker run --rm \
            --volumes-from "$JENKINS_CONTAINER" \
            busybox:latest \
            chown -R "$(id -u):$(id -g)" "$CACHE_DIR" >/dev/null 2>&1 || true
    else
        docker run --rm \
            -v "$CACHE_DIR:/cache" \
            busybox:latest \
            chown -R "$(id -u):$(id -g)" /cache >/dev/null 2>&1 || true
    fi
}
trap restore_cache_owner EXIT

trivy() {
    if [ "$USE_JENKINS_VOLUMES" = "true" ]; then
        docker run --rm \
            --volumes-from "$JENKINS_CONTAINER" \
            -w "$(pwd)" \
            "$TRIVY_IMAGE" --cache-dir "$CACHE_DIR" "$@"
    else
        docker run --rm \
            -v /var/run/docker.sock:/var/run/docker.sock \
            -v "$(pwd):/workspace" \
            -v "$CACHE_DIR:/root/.cache/trivy" \
            -w /workspace \
            "$TRIVY_IMAGE" "$@"
    fi
}

scan_fs() {
    echo "--- Trivy FS/SCA: dependencias e IaC ---"
    trivy fs \
        --scanners vuln,misconfig \
        --severity "$TRIVY_SEVERITY" \
        $IGNORE_UNFIXED_FLAG \
        --exit-code 0 \
        --skip-dirs .git \
        --skip-dirs frontend/node_modules \
        --skip-dirs frontend/dist \
        --skip-dirs reports \
        --skip-dirs .trivy-cache \
        --format json \
        --output "reports/trivy_fs_${BUILD_ID}.json" \
        .
}

scan_image() {
    image="$1"
    output="$2"
    echo "--- Trivy Image: $image ---"
    docker image inspect "$image" >/dev/null
    trivy image \
        --severity "$TRIVY_SEVERITY" \
        $IGNORE_UNFIXED_FLAG \
        --exit-code 0 \
        --format json \
        --output "$output" \
        "$image"
}

case "$MODE" in
    fs)
        scan_fs
        ;;
    images)
        scan_image "$BACKEND_IMAGE" "reports/trivy_backend_image_${BUILD_ID}.json"
        scan_image "$FRONTEND_IMAGE" "reports/trivy_frontend_image_${BUILD_ID}.json"
        ;;
    all)
        scan_fs
        scan_image "$BACKEND_IMAGE" "reports/trivy_backend_image_${BUILD_ID}.json"
        scan_image "$FRONTEND_IMAGE" "reports/trivy_frontend_image_${BUILD_ID}.json"
        ;;
    *)
        echo "Modo Trivy invalido: $MODE" >&2
        exit 2
        ;;
esac

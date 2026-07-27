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
IGNORE_UNFIXED_FLAG=""
WORKSPACE_MOUNT_ARGS="-v $(pwd):/workspace"
TRIVY_WORKDIR="/workspace"
TRIVY_CACHE_IN_CONTAINER="/workspace/.trivy-cache"
BUSYBOX_MOUNT_ARGS="-v $(pwd):/workspace"
BUSYBOX_CACHE_DIR="/workspace/.trivy-cache"

if [ -f /.dockerenv ] && docker inspect jenkins >/dev/null 2>&1; then
    WORKSPACE_MOUNT_ARGS="--volumes-from jenkins"
    TRIVY_WORKDIR="$(pwd)"
    TRIVY_CACHE_IN_CONTAINER="$CACHE_DIR"
    BUSYBOX_MOUNT_ARGS="--volumes-from jenkins"
    BUSYBOX_CACHE_DIR="$CACHE_DIR"
fi

if [ "$TRIVY_IGNORE_UNFIXED" = "true" ]; then
    IGNORE_UNFIXED_FLAG="--ignore-unfixed"
fi

mkdir -p reports "$CACHE_DIR"

restore_cache_owner() {
    docker run --rm \
        $BUSYBOX_MOUNT_ARGS \
        -w "$TRIVY_WORKDIR" \
        busybox:latest \
        chown -R "$(id -u):$(id -g)" "$BUSYBOX_CACHE_DIR" >/dev/null 2>&1 || true
}
trap restore_cache_owner EXIT

trivy() {
    docker run --rm \
        -v /var/run/docker.sock:/var/run/docker.sock \
        $WORKSPACE_MOUNT_ARGS \
        -w "$TRIVY_WORKDIR" \
        "$TRIVY_IMAGE" --cache-dir "$TRIVY_CACHE_IN_CONTAINER" "$@"
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

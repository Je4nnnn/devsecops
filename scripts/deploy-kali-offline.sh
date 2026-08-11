#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "${SCRIPT_DIR}"

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: ejecute sudo ./deploy.sh para configurar Docker y permisos TLS." >&2
  exit 2
fi

for command_name in docker openssl sha256sum gzip; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "ERROR: falta el comando ${command_name}." >&2
    exit 2
  fi
done

if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker no esta disponible para este usuario." >&2
  echo "Ejecute este instalador con sudo o habilite su usuario en el grupo docker." >&2
  exit 2
fi

if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  echo "ERROR: no se encontro Docker Compose v2." >&2
  exit 2
fi

compose() {
  "${COMPOSE[@]}" --env-file "${SCRIPT_DIR}/.env" \
    -f "${SCRIPT_DIR}/docker-compose.offline.yml" "$@"
}

for required_file in VERSION PLATFORM images.tar.gz images.tar.gz.sha256 \
  docker-compose.offline.yml .env.example; do
  if [ ! -f "${required_file}" ]; then
    echo "ERROR: paquete incompleto; falta ${required_file}." >&2
    exit 2
  fi
done

BUNDLE_VERSION="$(tr -d '[:space:]' < VERSION)"
EXPECTED_ARCH="$(tr -d '[:space:]' < PLATFORM)"
case "$(uname -m)" in
  x86_64) HOST_ARCH=amd64 ;;
  aarch64|arm64) HOST_ARCH=arm64 ;;
  armv7l) HOST_ARCH=arm ;;
  *) HOST_ARCH="$(uname -m)" ;;
esac

if [ "${HOST_ARCH}" != "${EXPECTED_ARCH}" ]; then
  echo "ERROR: paquete ${EXPECTED_ARCH}, pero este equipo es ${HOST_ARCH}." >&2
  exit 2
fi

echo "[1/5] Verificando integridad..."
sha256sum -c images.tar.gz.sha256

echo "[2/5] Cargando imagenes locales..."
gzip -dc images.tar.gz | docker load

if [ ! -f .env ]; then
  echo "[3/5] Generando secretos y configuracion local..."
  umask 077
  POSTGRES_PASSWORD="$(openssl rand -hex 24)"
  INITIAL_ADMIN_PASSWORD="$(openssl rand -hex 12)"
  JWT_SECRET="$(openssl rand -hex 32)"
  ENCRYPTION_KEY="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '\n')"

  sed \
    -e "s/REEMPLAZAR_POSTGRES_PASSWORD/${POSTGRES_PASSWORD}/" \
    -e "s/REEMPLAZAR_ADMIN_PASSWORD/${INITIAL_ADMIN_PASSWORD}/" \
    -e "s/REEMPLAZAR_JWT_SECRET/${JWT_SECRET}/" \
    -e "s|REEMPLAZAR_ENCRYPTION_KEY|${ENCRYPTION_KEY}|" \
    .env.example > .env
  chmod 600 .env

  {
    printf 'URL local: http://localhost:18080\n'
    printf 'Usuario inicial: admin\n'
    printf 'Contrasena inicial: %s\n' "${INITIAL_ADMIN_PASSWORD}"
    printf 'Cambie la contrasena al ingresar por primera vez.\n'
  } > CREDENCIALES_INICIALES.txt
  chmod 600 CREDENCIALES_INICIALES.txt
else
  echo "[3/5] Conservando .env existente..."
  if grep -q 'REEMPLAZAR_' .env; then
    echo "ERROR: .env contiene valores sin configurar." >&2
    exit 2
  fi
  if ! grep -q "^APP_VERSION=${BUNDLE_VERSION}$" .env; then
    echo "ERROR: .env pertenece a otra version. Respaldelo y vuelva a desplegar." >&2
    exit 2
  fi
fi

echo "[4/5] Preparando certificado TLS local..."
mkdir -p nginx/ssl
if [ ! -s nginx/ssl/nginx-selfsigned.key ] || [ ! -s nginx/ssl/nginx-selfsigned.crt ]; then
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout nginx/ssl/nginx-selfsigned.key \
    -out nginx/ssl/nginx-selfsigned.crt \
    -subj "/C=CL/O=DevSecOps/CN=kali-local" >/dev/null 2>&1
fi
chown 101:101 nginx/ssl/nginx-selfsigned.key nginx/ssl/nginx-selfsigned.crt
chmod 600 nginx/ssl/nginx-selfsigned.key
chmod 644 nginx/ssl/nginx-selfsigned.crt

echo "[5/5] Levantando servicios sin descargas..."
compose config --quiet
compose up -d

for attempt in $(seq 1 90); do
  all_healthy=true
  for service in db-api api frontend; do
    container_id="$(compose ps -q "${service}")"
    if [ -z "${container_id}" ]; then
      all_healthy=false
      continue
    fi
    health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${container_id}")"
    if [ "${health}" = "unhealthy" ] || [ "${health}" = "exited" ]; then
      echo "ERROR: ${service} termino con estado ${health}." >&2
      compose logs --tail=120 "${service}"
      exit 1
    fi
    if [ "${health}" != "healthy" ]; then
      all_healthy=false
    fi
  done
  if [ "${all_healthy}" = true ]; then
    break
  fi
  if [ "${attempt}" -eq 90 ]; then
    echo "ERROR: los servicios no quedaron saludables dentro de 180 segundos." >&2
    compose ps
    compose logs --tail=120
    exit 1
  fi
  sleep 2
done

KALI_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo
echo "Despliegue ${BUNDLE_VERSION} completado."
echo "Local:  http://localhost:18080"
echo "HTTPS:  https://localhost:18443"
if [ -n "${KALI_IP}" ]; then
  echo "En LAN: http://${KALI_IP}:18080"
fi
echo "Credenciales: ${SCRIPT_DIR}/CREDENCIALES_INICIALES.txt"
echo "Validacion: sudo ./smoke-test.sh"

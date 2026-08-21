#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "${PROJECT_DIR}"

MODE="${1:---pull}"
if [ "${MODE}" != "--pull" ] && [ "${MODE}" != "--build" ]; then
  echo "Uso: ./iniciar_app.sh [--pull|--build]" >&2
  exit 2
fi

for command_name in docker openssl sed; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "ERROR: falta el comando ${command_name}." >&2
    exit 2
  fi
done

if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: se requiere Docker Compose v2 (comando docker compose)." >&2
  exit 2
fi

if [ ! -f .env ]; then
  cp .env.example .env
  postgres_password="$(openssl rand -hex 24)"
  admin_password="$(openssl rand -base64 18 | tr -d '\n' | tr '/+' '_-')"
  jwt_secret="$(openssl rand -hex 48)"
  encryption_key="$(openssl rand -base64 32 | tr '/+' '_-' | tr -d '\n')"
  sonar_db_password="$(openssl rand -hex 24)"
  sonar_admin_password="$(openssl rand -base64 18 | tr -d '\n' | tr '/+' '_-')"
  jenkins_admin_password="$(openssl rand -base64 18 | tr -d '\n' | tr '/+' '_-')"
  sed -i \
    -e "s|REEMPLAZAR_POSTGRES_PASSWORD|${postgres_password}|" \
    -e "s|REEMPLAZAR_ADMIN_PASSWORD|${admin_password}|" \
    -e "s|REEMPLAZAR_JWT_SECRET|${jwt_secret}|" \
    -e "s|REEMPLAZAR_ENCRYPTION_KEY|${encryption_key}|" \
    -e "s|REEMPLAZAR_SONAR_DB_PASSWORD|${sonar_db_password}|" \
    -e "s|REEMPLAZAR_SONAR_ADMIN_PASSWORD|${sonar_admin_password}|" \
    -e "s|REEMPLAZAR_JENKINS_ADMIN_PASSWORD|${jenkins_admin_password}|" .env
  chmod 600 .env
  echo "Se creo .env con secretos aleatorios."
  echo "Usuario inicial: admin"
  echo "Aplicacion admin: ${admin_password}"
  echo "Jenkins admin: ${jenkins_admin_password}"
  echo "SonarQube admin: ${sonar_admin_password}"
  echo "Guarde estas contrasenas ahora; no se volveran a mostrar."
fi

ci_credentials_added=false
if ! grep -q '^SONAR_DB_PASSWORD=' .env; then
  sonar_db_password="$(openssl rand -hex 24)"
  printf '\nSONAR_DB_PASSWORD=%s\n' "${sonar_db_password}" >> .env
  ci_credentials_added=true
fi
if ! grep -q '^SONAR_ADMIN_PASSWORD=' .env; then
  sonar_admin_password="$(openssl rand -base64 18 | tr -d '\n' | tr '/+' '_-')"
  printf 'SONAR_ADMIN_PASSWORD=%s\n' "${sonar_admin_password}" >> .env
  ci_credentials_added=true
fi
if ! grep -q '^JENKINS_ADMIN_ID=' .env; then
  printf 'JENKINS_ADMIN_ID=admin\n' >> .env
fi
if ! grep -q '^JENKINS_ADMIN_PASSWORD=' .env; then
  jenkins_admin_password="$(openssl rand -base64 18 | tr -d '\n' | tr '/+' '_-')"
  printf 'JENKINS_ADMIN_PASSWORD=%s\n' "${jenkins_admin_password}" >> .env
  ci_credentials_added=true
fi
if [ "${ci_credentials_added}" = true ]; then
  chmod 600 .env
  echo "Se agregaron credenciales CI/CD al .env existente."
  [ -n "${jenkins_admin_password:-}" ] && echo "Jenkins admin: ${jenkins_admin_password}"
  [ -n "${sonar_admin_password:-}" ] && echo "SonarQube admin: ${sonar_admin_password}"
  echo "Guarde estas contrasenas ahora; no se volveran a mostrar."
fi

if grep -q 'REEMPLAZAR_' .env; then
  echo "ERROR: .env contiene valores REEMPLAZAR_*; elimine .env para regenerarlo o complete los valores." >&2
  exit 2
fi

mkdir -p nginx/ssl
chmod 755 nginx nginx/ssl
if [ ! -s nginx/ssl/nginx-selfsigned.key ] || [ ! -s nginx/ssl/nginx-selfsigned.crt ]; then
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout nginx/ssl/nginx-selfsigned.key \
    -out nginx/ssl/nginx-selfsigned.crt \
    -subj "/C=CL/O=DevSecOps/CN=localhost" >/dev/null 2>&1
fi
chmod 644 nginx/ssl/nginx-selfsigned.key nginx/ssl/nginx-selfsigned.crt

compose=(docker compose --env-file .env -f docker-compose.yml -f docker-compose.tls.yml)
"${compose[@]}" config --quiet

if [ "${MODE}" = "--build" ]; then
  APP_PULL_POLICY=build "${compose[@]}" up -d --build
else
  "${compose[@]}" pull
  "${compose[@]}" up -d --no-build
fi

echo
echo "Servicios iniciados. Revise el estado con:"
echo "  docker compose --env-file .env -f docker-compose.yml -f docker-compose.tls.yml ps"
echo "Acceso:"
echo "  http://localhost:18080"
echo "  https://localhost:18443"
echo "  Jenkins: http://localhost:8080"
echo "  SonarQube: http://localhost:9000"

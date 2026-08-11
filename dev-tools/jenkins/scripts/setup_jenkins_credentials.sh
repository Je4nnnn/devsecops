#!/usr/bin/env bash
set -Eeuo pipefail

echo "Este proyecto no crea credenciales Jenkins desde valores versionados."
echo "Configure los secretos en Manage Jenkins > Credentials:"
echo "  - sonar-token"
echo "  - credenciales Wazuh de un entorno QA aislado, si el job las necesita"
echo "Consulte dev-tools/jenkins/README.md."
exit 2

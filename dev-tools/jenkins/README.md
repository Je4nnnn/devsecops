# Jenkins DevSecOps Pipeline

Este Jenkinsfile valida el proyecto sin modificar la logica de la aplicacion. El flujo agrega gates explicitos por seccion:

1. `GATE: Backend Coverage`: falla si la cobertura backend baja de `BACKEND_MIN_COVERAGE`.
2. `GATE: Frontend Coverage`: falla si la cobertura frontend baja de `FRONTEND_MIN_COVERAGE`.
3. `GATE: SonarQube Availability`: confirma que SonarQube esta listo antes del scanner.
4. `GATE: SonarQube Quality Gate`: consulta el Quality Gate real de SonarQube por API.
5. `GATE: Trivy SCA`: falla por vulnerabilidades o misconfiguraciones `CRITICAL,HIGH` en dependencias/IaC.
6. `GATE: Trivy Containers`: falla por vulnerabilidades `CRITICAL,HIGH` corregibles en imagen backend/frontend.
7. `GATE: OWASP ZAP`: falla por alertas ZAP de riesgo `High`.

## Puesta en marcha manual

Desde la raiz del proyecto:

```bash
docker network create sonarqube_sonar-network 2>/dev/null || true
cd dev-tools/jenkins
docker compose up -d --build
```

En Jenkins:

1. Abrir `http://localhost:8080`.
2. Crear o verificar la credencial secreta `sonar-token` en `Manage Jenkins > Credentials`.
3. Verificar que la instalacion de SonarQube se llame `sonarqube` en `Manage Jenkins > System`, porque el Jenkinsfile usa `withSonarQubeEnv('sonarqube')`.
4. Ejecutar el job que apunta a este repositorio.

## Ajustes de gates

Los umbrales se controlan desde el bloque `environment` del Jenkinsfile:

```groovy
BACKEND_MIN_COVERAGE = '70'
FRONTEND_MIN_COVERAGE = '60'
TRIVY_FAIL_SEVERITIES = 'CRITICAL,HIGH'
TRIVY_IGNORE_UNFIXED = 'true'
ZAP_FAIL_RISK_LEVELS = 'High'
```

`TRIVY_IGNORE_UNFIXED=true` evita bloquear el pipeline por CVE sin version corregida publicada. Si Trivy falla, revisar los artefactos `reports/trivy_*_<build>.json` en Jenkins. Si ZAP falla, revisar `reports/zap_*_<build>.html` y `reports/zap_*_<build>.json`.

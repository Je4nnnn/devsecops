# Jenkins DevSecOps Pipeline

Este Jenkinsfile valida el proyecto sin modificar la logica de la aplicacion. El flujo agrega gates explicitos por seccion:

1. `GATE: Backend Coverage`: falla si la cobertura backend baja de `BACKEND_MIN_COVERAGE`.
2. `GATE: Frontend Coverage`: falla si la cobertura frontend baja de `FRONTEND_MIN_COVERAGE`.
3. `GATE: SonarQube Availability`: confirma que SonarQube esta listo antes del scanner.
4. `SAST: Configure SonarQube Quality Gate`: crea/asigna `DevSecOps CI Gate` para que SonarQube use la politica del pipeline.
5. `GATE: SonarQube Quality Gate`: consulta el Quality Gate real de SonarQube por API.
6. `GATE: Trivy SCA`: falla por vulnerabilidades o misconfiguraciones `CRITICAL,HIGH` en dependencias/IaC.
7. `GATE: Trivy Containers`: falla por vulnerabilidades `CRITICAL,HIGH` corregibles en imagen backend/frontend.
8. `GATE: OWASP ZAP`: falla por alertas ZAP de riesgo `High`.

## Puesta en marcha

Desde la raíz del proyecto:

```bash
docker compose up -d
```

El Compose raíz levanta aplicación, SonarQube y Jenkins. El inicializador genera el token `sonar-token`, Jenkins registra la instalación `sonarqube` y crea o actualiza el job `devsecops-pipeline` apuntando a `main`.

1. Abra `http://localhost:8080`.
2. Ingrese como `admin` con la contraseña de `.env` o la credencial local documentada.
3. Abra `devsecops-pipeline` y presione **Build Now**.

Jenkins monta `/var/run/docker.sock`. Esto le permite ejecutar los stages Docker, pero también le entrega control administrativo sobre el daemon y sus volúmenes. Use este entorno solo para desarrollo controlado.

## Ajustes de gates

Los umbrales se controlan desde el bloque `environment` del Jenkinsfile:

```groovy
BACKEND_MIN_COVERAGE = '70'
FRONTEND_MIN_COVERAGE = '60'
SONAR_QUALITY_GATE_NAME = 'DevSecOps CI Gate'
SONAR_MIN_COVERAGE = '70'
TRIVY_FAIL_SEVERITIES = 'CRITICAL,HIGH'
TRIVY_IGNORE_UNFIXED = 'true'
ZAP_FAIL_RISK_LEVELS = 'High'
```

El Quality Gate de SonarQube usa cobertura global `coverage >= SONAR_MIN_COVERAGE` y ratings nuevos `A` para mantenibilidad, confiabilidad y seguridad. La cobertura por seccion se valida antes con `GATE: Backend Coverage` y `GATE: Frontend Coverage`.

`TRIVY_IGNORE_UNFIXED=true` evita bloquear el pipeline por CVE sin version corregida publicada. Si Trivy falla, revisar los artefactos `reports/trivy_*_<build>.json` en Jenkins. Si ZAP falla, revisar `reports/zap_*_<build>.html` y `reports/zap_*_<build>.json`.

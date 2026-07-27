# Demo pipeline DevSecOps en otra laptop

Objetivo: levantar Jenkins + SonarQube + Docker y ejecutar el job `vuln-app-pipeline` hasta `Finished: SUCCESS`, igual que en la laptop actual.

## Requisitos de la laptop

- Windows con Docker Desktop funcionando.
- WSL2 habilitado.
- Git instalado.
- PowerShell.
- Al menos 8 GB de RAM libres recomendados para Docker.
- Puertos libres:
  - Jenkins: `8080`
  - SonarQube: `9000`

## Archivos importantes exportados

Este directorio contiene:

- `Jenkinsfile.inline`: definición exacta del pipeline que funcionó.
- `vuln-app-pipeline-config.xml`: export del job Jenkins.
- `docker-compose.postgres-ci.yml`: override usado para reemplazar TimescaleDB por `postgres:15` en CI.
- `docker-wrapper`: wrapper de Docker usado dentro del contenedor Jenkins para aplicar el override automáticamente.

## Cambios funcionales que deben estar presentes

El pipeline exitoso depende de estas correcciones:

- Checkout explícito de `qa-quality-gates`.
- Jenkinsfile inline con `skipDefaultCheckout(true)`.
- `configure_sonar_gate.py` crea/verifica el proyecto Sonar antes de asignar el Quality Gate.
- Trivy escribe reportes en el workspace real de Jenkins usando el volumen del contenedor Jenkins.
- DAST escribe un `frontend/nginx.conf` HTTP-only temporal para evitar problemas de certificados en Jenkins-in-Docker.
- OWASP ZAP monta la carpeta `reports` como `/zap/wrk`, requisito obligatorio de ZAP.
- ZAP falla solo con riesgo `High`; warnings `Medium`, `Low` e `Informational` no bloquean.

## Pasos recomendados

1. Clonar el repo:

```powershell
git clone https://github.com/Je4nnnn/devsecops.git
cd devsecops
git checkout qa-quality-gates
```

2. Copiar o aplicar los cambios locales que todavía no estén en GitHub:

- `dev-tools/jenkins/Jenkinsfile`
- `dev-tools/jenkins/scripts/run_zap.sh`
- `dev-tools/jenkins/scripts/run_trivy.sh`, si aparece modificado por saltos de linea.

Si no quieres depender del repo remoto, lleva completa la carpeta local `devsecops` en un ZIP.

3. Levantar Jenkins:

```powershell
docker compose -f dev-tools/jenkins/docker-compose.yml up -d --build
```

4. Verificar Jenkins:

```powershell
docker ps
```

Abrir:

```text
http://localhost:8080
```

5. Instalar/restaurar el job.

Opcion A, restaurar el job exportado:

```powershell
docker cp handoff-profesor/vuln-app-pipeline-config.xml jenkins:/tmp/vuln-app-pipeline-config.xml
docker exec jenkins sh -lc "/opt/java/openjdk/bin/java -jar /var/jenkins_home/war/WEB-INF/lib/cli-2.568.1.jar -s http://localhost:8080/ -auth 'codex-runner:Codex-Run-7f3c9A!2026' create-job vuln-app-pipeline < /tmp/vuln-app-pipeline-config.xml || /opt/java/openjdk/bin/java -jar /var/jenkins_home/war/WEB-INF/lib/cli-2.568.1.jar -s http://localhost:8080/ -auth 'codex-runner:Codex-Run-7f3c9A!2026' update-job vuln-app-pipeline < /tmp/vuln-app-pipeline-config.xml"
```

Opcion B, actualizar solo el Jenkinsfile inline:

```powershell
docker cp handoff-profesor/Jenkinsfile.inline jenkins:/var/jenkins_home/ci-overrides/Jenkinsfile.inline
```

6. Restaurar los overrides de Jenkins-in-Docker:

```powershell
docker exec jenkins sh -lc "mkdir -p /var/jenkins_home/ci-overrides"
docker cp handoff-profesor/docker-compose.postgres-ci.yml jenkins:/var/jenkins_home/ci-overrides/docker-compose.postgres-ci.yml
docker cp handoff-profesor/docker-wrapper jenkins:/usr/local/bin/docker
docker exec jenkins sh -lc "chmod +x /usr/local/bin/docker"
```

7. Validar el Jenkinsfile:

```powershell
docker exec jenkins sh -lc "/opt/java/openjdk/bin/java -jar /var/jenkins_home/war/WEB-INF/lib/cli-2.568.1.jar -s http://localhost:8080/ -auth 'codex-runner:Codex-Run-7f3c9A!2026' declarative-linter < /var/jenkins_home/ci-overrides/Jenkinsfile.inline"
```

Debe mostrar:

```text
Jenkinsfile successfully validated.
```

8. Ejecutar el build desde Jenkins:

```text
http://localhost:8080/job/vuln-app-pipeline/
```

Presionar `Build Now`.

## Resultado esperado

El final debe mostrar:

```text
GATE ZAP: riesgos evaluados para fallo: high
GATE ZAP: resumen informational=6, low=8, medium=2
GATE ZAP: OK
Finished: SUCCESS
```

Los valores pueden variar levemente, pero no debe haber hallazgos `High`.

## Si algo falla

- Si falla ZAP con `/zap/wrk`, revisar que `run_zap.sh` tenga el bloque que calcula `JENKINS_HOME_SOURCE` y monta `reports` como `/zap/wrk`.
- Si falla Trivy por reportes faltantes, revisar que `run_trivy.sh` use `--volumes-from jenkins` cuando corre dentro de Jenkins.
- Si falla TimescaleDB, confirmar que el wrapper de Docker esté usando `docker-compose.postgres-ci.yml`.
- Si SonarQube tarda, esperar a que `http://localhost:9000` esté disponible y repetir build.

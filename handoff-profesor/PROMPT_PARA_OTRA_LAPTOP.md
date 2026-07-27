# Prompt para usar en la otra laptop

Estoy mostrando una demo de un pipeline DevSecOps en Jenkins para el repo:

`https://github.com/Je4nnnn/devsecops`

Rama:

`qa-quality-gates`

Necesito reproducir el pipeline que ya funcionó con `Finished: SUCCESS`.

Contexto importante:

- Jenkins corre en Docker.
- SonarQube corre en Docker en `http://localhost:9000`.
- Jenkins queda en `http://localhost:8080`.
- El job se llama `vuln-app-pipeline`.
- El pipeline exitoso usa una definición inline exportada en `handoff-profesor/Jenkinsfile.inline`.
- También tengo exportado `handoff-profesor/vuln-app-pipeline-config.xml`.
- Hay overrides necesarios:
  - `handoff-profesor/docker-compose.postgres-ci.yml`
  - `handoff-profesor/docker-wrapper`

Problemas que ya fueron resueltos:

- SonarQube necesitaba crear/verificar el proyecto antes de asignar el Quality Gate.
- Trivy necesitaba escribir reportes en el workspace real de Jenkins.
- El frontend en DAST necesitaba un `nginx.conf` HTTP-only temporal.
- OWASP ZAP exige que `/zap/wrk` sea un volumen real, por eso `run_zap.sh` monta la carpeta `reports` del workspace Jenkins directamente como `/zap/wrk`.
- El gate de ZAP debe fallar solo con riesgo `High`.

Necesito que me ayudes a:

1. Levantar Jenkins con Docker Compose.
2. Restaurar/importar el job `vuln-app-pipeline` desde `handoff-profesor/vuln-app-pipeline-config.xml`.
3. Copiar `Jenkinsfile.inline` a `/var/jenkins_home/ci-overrides/Jenkinsfile.inline`.
4. Copiar `docker-compose.postgres-ci.yml` a `/var/jenkins_home/ci-overrides/docker-compose.postgres-ci.yml`.
5. Copiar `docker-wrapper` a `/usr/local/bin/docker` dentro del contenedor Jenkins y darle permisos.
6. Validar el Jenkinsfile con Jenkins CLI.
7. Ejecutar el build y verificar que termine con:

```text
GATE ZAP: OK
Finished: SUCCESS
```

No cambies la lógica del pipeline salvo que sea necesario por diferencias de la laptop. Si algo falla, diagnostica primero rutas de Docker, mounts de Jenkins y existencia de reportes en `reports/`.

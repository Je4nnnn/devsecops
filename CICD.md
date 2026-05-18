# 🔄 Pipeline CI/CD — DevSecOps Vulnerability Platform

> **Stack:** Jenkins + SonarQube + OWASP ZAP  
> **Enfoque:** DevSecOps — la seguridad va integrada en cada etapa del pipeline

---

## Tabla de Contenidos

1. [Arquitectura del Pipeline](#1-arquitectura-del-pipeline)
2. [Infraestructura de las Herramientas](#2-infraestructura-de-las-herramientas)
3. [Etapas del Pipeline](#3-etapas-del-pipeline)
4. [Jenkins — Configuración y Setup](#4-jenkins--configuración-y-setup)
5. [SonarQube — Análisis Estático (SAST)](#5-sonarqube--análisis-estático-sast)
6. [OWASP ZAP — Análisis Dinámico (DAST)](#6-owasp-zap--análisis-dinámico-dast)
7. [Jenkinsfile Completo](#7-jenkinsfile-completo)
8. [Credenciales Requeridas](#8-credenciales-requeridas)
9. [Arranque Completo del Entorno CI/CD](#9-arranque-completo-del-entorno-cicd)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Arquitectura del Pipeline

```
  Developer
     │
     │  git push / PR
     ▼
┌─────────────────────────────────────────────────────────────────┐
│  JENKINS  :8080                                                  │
│                                                                  │
│  Stage 1 ── Checkout          Clona el repositorio              │
│  Stage 2 ── Test Backend      pytest + cobertura (coverage.xml) │
│  Stage 3 ── Test Frontend     vitest + cobertura (lcov.info)    │
│  Stage 4 ── SAST ─────────────────────────────────────────────► │
│                                                                  │
│             ┌─────────────────────────┐                         │
│             │  SONARQUBE  :9000       │                         │
│             │  Analiza Python + Vue   │                         │
│             │  Reporta bugs, smells,  │                         │
│             │  vulnerabilidades       │                         │
│             └─────────────────────────┘                         │
│                                                                  │
│  Stage 5 ── Build Docker      Construye imágenes api + frontend │
│  Stage 6 ── Deploy Staging    Levanta la app en contenedores    │
│  Stage 7 ── DAST ─────────────────────────────────────────────► │
│                                                                  │
│             ┌─────────────────────────┐                         │
│             │  OWASP ZAP              │                         │
│             │  Escanea la app viva    │                         │
│             │  Detecta: SQLi, XSS,   │                         │
│             │  CSRF, headers, etc.    │                         │
│             └─────────────────────────┘                         │
│                                                                  │
│  Stage 8 ── Publicar Reportes  HTML archivados en Jenkins       │
│  Stage 9 ── Deploy Prod        (manual approval)                │
└─────────────────────────────────────────────────────────────────┘
```

### Redes Docker entre servicios

```
jenkins ──── jenkins-network  (interno Jenkins)
        ──── sonar-network    (conecta con SonarQube)
        ──── app-network      (conecta con la app desplegada)

sonarqube ── sonar-network
          ── sonarqube_db

zap ──────── zap-network
             host.docker.internal → accede a la app en el host
```

---

## 2. Infraestructura de las Herramientas

### Estructura de archivos

```
dev-tools/
├── jenkins/
│   ├── Dockerfile                      # Imagen Jenkins con Docker CLI + plugins
│   ├── docker-compose.yml              # Arranque Jenkins
│   └── scripts/
│       └── setup_jenkins_credentials.sh  # Configura credenciales via API
├── sonarqube/
│   └── sonar-project.properties        # Config del proyecto para SonarQube
└── zap/
    └── docker-compose.yml              # Escaneo DAST con ZAP
```

### Imagen Jenkins personalizada

La imagen incluye:
- **Docker CLI** instalado → Jenkins puede ejecutar `docker compose`
- **Python 3** instalado → para ejecutar scripts de análisis
- **Plugins pre-instalados:**
  - `git` — integración con repositorios
  - `workflow-aggregator` — soporte para Pipelines declarativos
  - `docker-workflow` — pasos Docker en Pipelines
  - `sonar` — integración con SonarQube
  - `credentials-binding` — manejo seguro de secrets
  - `htmlpublisher` — publicar reportes HTML de ZAP
  - `pipeline-stage-view` — vista visual del pipeline

### Puertos

| Herramienta | Puerto | URL |
|-------------|--------|-----|
| Jenkins | 8080 | http://localhost:8080 |
| SonarQube | 9000 | http://localhost:9000 |
| App (staging) | 18080 | http://localhost:18080 |

---

## 3. Etapas del Pipeline

### Stage 1 — Checkout
```
Acción:   git clone del repositorio
Resultado: código fuente disponible en el workspace de Jenkins
```

### Stage 2 — Test Backend (pytest)
```
Acción:   cd vuln-api → pip install → pytest --cov
Salida:   coverage.xml (formato Cobertura, leído por SonarQube)
Falla si: algún test no pasa
```

### Stage 3 — Test Frontend (vitest)
```
Acción:   cd frontend → npm install → npm run coverage
Salida:   coverage/lcov.info (formato LCOV, leído por SonarQube)
Falla si: algún test no pasa
```

### Stage 4 — SAST con SonarQube
```
Acción:   sonar-scanner analiza vuln-api/app + frontend/src
Lee:      coverage.xml + lcov.info para % de cobertura
Reporta:  bugs, code smells, vulnerabilidades, duplicaciones
Falla si: Quality Gate no se aprueba (configurable en SonarQube)
```

**¿Qué detecta SonarQube?**
- SQL Injection potencial
- Secrets hardcodeados (API keys, passwords)
- Variables sin sanitizar
- Código muerto
- Funciones demasiado complejas
- Cobertura de tests insuficiente

### Stage 5 — Build Docker
```
Acción:   docker compose build api frontend
Resultado: imágenes vuln-app-wazuh-api y vuln-app-wazuh-frontend actualizadas
```

### Stage 6 — Deploy Staging
```
Acción:   docker compose up -d (con variables de staging)
Resultado: app corriendo en :18080 lista para ser escaneada
Espera:   health checks de todos los contenedores
```

### Stage 7 — DAST con OWASP ZAP
```
Acción:   zap-baseline.py -t http://host.docker.internal:18080
Escanea:  la app corriendo en vivo
Salida:   zap_report.html + zap_report.json
Detecta:
  - Cross-Site Scripting (XSS)
  - SQL Injection
  - Headers de seguridad faltantes (CSP, HSTS, X-Frame-Options)
  - Cookies sin flags Secure/HttpOnly
  - Información sensible expuesta
  - CSRF
```

### Stage 8 — Publicar Reportes
```
Acción:   archiva zap_report.html en Jenkins (htmlpublisher)
Acceso:   Jenkins UI → Pipeline → Build → ZAP Report
```

### Stage 9 — Deploy Producción (manual)
```
Acción:   input() → aprobación manual en Jenkins UI
Ejecuta:  docker compose -f docker-compose.yml up -d (producción)
Solo si:  todos los stages anteriores pasaron
```

---

## 4. Jenkins — Configuración y Setup

### Levantar Jenkins

```bash
cd dev-tools/jenkins
docker compose up -d
```

### Primer acceso

```bash
# Obtener contraseña inicial
docker exec jenkins cat /var/jenkins_home/secrets/initialAdminPassword
```

1. Abrir http://localhost:8080
2. Pegar la contraseña inicial
3. Instalar plugins sugeridos (ya vienen pre-instalados en la imagen)
4. Crear usuario administrador

### Configurar SonarQube en Jenkins

1. Jenkins → **Manage Jenkins** → **Configure System**
2. Sección **SonarQube servers** → Add
   - Name: `SonarQube`
   - URL: `http://sonarqube:9000`
   - Token: (generado en SonarQube → My Account → Security)

### Configurar credenciales

```bash
# Editar el script con tu token de Jenkins
nano dev-tools/jenkins/scripts/setup_jenkins_credentials.sh

# Cambiar estos valores:
JENKINS_TOKEN="tu_api_token_de_jenkins"

# Ejecutar
bash dev-tools/jenkins/scripts/setup_jenkins_credentials.sh
```

El script crea automáticamente:
| ID Credencial | Tipo | Uso |
|---------------|------|-----|
| `vuln-db-url` | Secret Text | DATABASE_URL de la app |
| `wazuh-indexer-creds` | Username/Password | Credenciales Wazuh |
| `app-admin-creds` | Username/Password | Admin de la app |

### Crear el Pipeline en Jenkins

1. Jenkins → **New Item** → **Pipeline**
2. Nombre: `vuln-app-pipeline`
3. Pipeline → Definition: **Pipeline script from SCM**
4. SCM: **Git**
5. Repository URL: `<url de tu repo>`
6. Branch: `*/main`
7. Script Path: `Jenkinsfile`
8. Guardar

---

## 5. SonarQube — Análisis Estático (SAST)

### Levantar SonarQube

SonarQube necesita su propio `docker-compose.yml`. Créalo así:

```bash
cat > dev-tools/sonarqube/docker-compose.yml << 'EOF'
name: sonarqube

services:
  sonarqube:
    image: sonarqube:community
    container_name: sonarqube
    depends_on:
      - sonarqube_db
    ports:
      - "9000:9000"
    environment:
      SONAR_JDBC_URL: jdbc:postgresql://sonarqube_db:5432/sonar
      SONAR_JDBC_USERNAME: sonar
      SONAR_JDBC_PASSWORD: sonar
    volumes:
      - sonarqube_data:/opt/sonarqube/data
      - sonarqube_logs:/opt/sonarqube/logs
    networks:
      - sonar-network

  sonarqube_db:
    image: postgres:15
    container_name: sonarqube_db
    environment:
      POSTGRES_USER: sonar
      POSTGRES_PASSWORD: sonar
      POSTGRES_DB: sonar
    volumes:
      - sonarqube_db_data:/var/lib/postgresql/data
    networks:
      - sonar-network

volumes:
  sonarqube_data:
  sonarqube_logs:
  sonarqube_db_data:

networks:
  sonar-network:
    driver: bridge
EOF

cd dev-tools/sonarqube
docker compose up -d
```

### Primer acceso SonarQube

1. Abrir http://localhost:9000
2. Login: `admin` / `admin` (te pide cambiar la clave)
3. **My Account** → **Security** → **Generate Token**
4. Copiar el token y configurarlo en Jenkins

### Configuración del proyecto (`sonar-project.properties`)

```properties
# Identidad
sonar.projectKey=vuln-app
sonar.projectName=Vuln App Wazuh

# Código fuente analizado
sonar.sources=vuln-api/app,frontend/src
sonar.tests=vuln-api/tests

# Versiones de lenguaje
sonar.python.version=3.12

# Reportes de cobertura
sonar.python.coverage.reportPaths=vuln-api/coverage.xml
sonar.javascript.lcov.reportPaths=frontend/coverage/lcov.info

# Exclusiones
sonar.exclusions=**/__pycache__/**,**/*.pyc,**/venv/**,frontend/node_modules/**,frontend/dist/**
```

### Quality Gate por defecto

SonarQube falla el pipeline si:
- Cobertura de tests < 80%
- Rating de seguridad peor que A
- Hay vulnerabilidades de severidad BLOCKER o CRITICAL
- Más del 3% de código duplicado

---

## 6. OWASP ZAP — Análisis Dinámico (DAST)

### ¿Cómo funciona?

ZAP levanta un contenedor, se conecta a la app corriendo en staging (`host.docker.internal:18080`), y ejecuta un baseline scan:

```
ZAP Container
     │
     │  HTTP requests automatizados
     │  Spider + Passive scan
     ▼
App en staging :18080
     │
     │  Respuestas HTTP
     ▼
ZAP analiza headers, cookies, respuestas
     │
     ▼
zap_report.html + zap_report.json
```

### Tipos de alertas ZAP

| Nivel | Color | Acción |
|-------|-------|--------|
| HIGH | 🔴 Rojo | Falla el pipeline |
| MEDIUM | 🟡 Naranja | Warning, no falla |
| LOW | 🔵 Azul | Informativo |
| INFORMATIONAL | ⚪ Gris | Ignorado |

### Ejecución manual de ZAP

```bash
# Ajustar el volumen a tu ruta local
cd dev-tools/zap
docker compose up
```

El reporte queda en `dev-tools/reports/zap_report.html`.

---

## 7. Jenkinsfile Completo

Crear este archivo en la **raíz del repositorio** como `Jenkinsfile`:

```groovy
pipeline {
    agent any

    environment {
        APP_NAME        = 'vuln-app-wazuh'
        SONAR_PROJECT   = 'vuln-app'
        STAGING_PORT    = '18080'
        REPORTS_DIR     = "${WORKSPACE}/dev-tools/reports"
    }

    options {
        timeout(time: 30, unit: 'MINUTES')
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '10'))
    }

    stages {

        // ─────────────────────────────────────────────
        stage('Checkout') {
        // ─────────────────────────────────────────────
            steps {
                checkout scm
                echo "✅ Código obtenido: ${env.GIT_BRANCH} @ ${env.GIT_COMMIT[0..7]}"
            }
        }

        // ─────────────────────────────────────────────
        stage('Test Backend') {
        // ─────────────────────────────────────────────
            steps {
                sh '''
                    cd vuln-api
                    python3 -m venv venv
                    . venv/bin/activate
                    pip install -r requirements.txt -q
                    pytest tests/ \
                        --cov=app \
                        --cov-report=xml:coverage.xml \
                        --cov-report=term-missing \
                        -v
                '''
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'vuln-api/junit.xml'
                }
            }
        }

        // ─────────────────────────────────────────────
        stage('Test Frontend') {
        // ─────────────────────────────────────────────
            steps {
                sh '''
                    cd frontend
                    npm install --silent
                    npm run coverage
                '''
            }
        }

        // ─────────────────────────────────────────────
        stage('SAST — SonarQube') {
        // ─────────────────────────────────────────────
            steps {
                withSonarQubeEnv('SonarQube') {
                    sh '''
                        sonar-scanner \
                            -Dsonar.projectKey=${SONAR_PROJECT} \
                            -Dsonar.sources=vuln-api/app,frontend/src \
                            -Dsonar.tests=vuln-api/tests \
                            -Dsonar.python.version=3.12 \
                            -Dsonar.python.coverage.reportPaths=vuln-api/coverage.xml \
                            -Dsonar.javascript.lcov.reportPaths=frontend/coverage/lcov.info \
                            -Dsonar.exclusions=**/venv/**,**/node_modules/**,**/dist/**
                    '''
                }
            }
        }

        // ─────────────────────────────────────────────
        stage('Quality Gate') {
        // ─────────────────────────────────────────────
            steps {
                timeout(time: 5, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }

        // ─────────────────────────────────────────────
        stage('Build Docker') {
        // ─────────────────────────────────────────────
            steps {
                sh 'docker compose build --no-cache api frontend'
                echo "✅ Imágenes construidas"
            }
        }

        // ─────────────────────────────────────────────
        stage('Deploy Staging') {
        // ─────────────────────────────────────────────
            steps {
                sh '''
                    docker compose down --remove-orphans || true
                    docker compose up -d
                    echo "⏳ Esperando que la app esté lista..."
                    sleep 15
                    curl -f http://localhost:${STAGING_PORT} || \
                        (echo "❌ App no responde en staging" && exit 1)
                    echo "✅ App disponible en :${STAGING_PORT}"
                '''
            }
        }

        // ─────────────────────────────────────────────
        stage('DAST — OWASP ZAP') {
        // ─────────────────────────────────────────────
            steps {
                sh '''
                    mkdir -p ${REPORTS_DIR}
                    docker run --rm \
                        --network host \
                        -v ${REPORTS_DIR}:/zap/wrk:rw \
                        zaproxy/zap-weekly \
                        zap-baseline.py \
                            -t http://localhost:${STAGING_PORT} \
                            -r zap_report.html \
                            -J zap_report.json \
                            -m 2 \
                            -I
                '''
            }
            post {
                always {
                    publishHTML(target: [
                        allowMissing         : true,
                        alwaysLinkToLastBuild: true,
                        keepAll              : true,
                        reportDir            : "${REPORTS_DIR}",
                        reportFiles          : 'zap_report.html',
                        reportName           : 'ZAP Security Report'
                    ])
                }
            }
        }

        // ─────────────────────────────────────────────
        stage('Deploy Producción') {
        // ─────────────────────────────────────────────
            when {
                branch 'main'
            }
            steps {
                input message: '¿Aprobar despliegue a producción?',
                      ok: 'Desplegar'

                sh '''
                    echo "🚀 Desplegando en producción..."
                    docker compose up -d
                    echo "✅ Desplegado exitosamente"
                '''
            }
        }
    }

    // ─────────────────────────────────────────────
    post {
    // ─────────────────────────────────────────────
        success {
            echo '✅ Pipeline completado exitosamente'
        }
        failure {
            echo '❌ Pipeline falló — revisar logs'
            sh 'docker compose down || true'
        }
        always {
            echo '📋 Reportes disponibles en Jenkins UI'
        }
    }
}
```

---

## 8. Credenciales Requeridas

Configurar en **Jenkins → Manage Jenkins → Credentials**:

| ID | Tipo | Valor | Usado en |
|----|------|-------|----------|
| `sonarqube-token` | Secret Text | Token de SonarQube | Stage SAST |
| `vuln-db-url` | Secret Text | `postgresql://admin:adminpassword@db-api:5432/vulnerabilidades_db` | Deploy |
| `wazuh-indexer-creds` | Username/Password | Credenciales del Wazuh Indexer | Tests de integración |
| `app-admin-creds` | Username/Password | `admin` / `admin` | ZAP autenticado |

### Configurar automáticamente

```bash
# Editar el script con tu token de admin de Jenkins
nano dev-tools/jenkins/scripts/setup_jenkins_credentials.sh

# Reemplazar:
JENKINS_TOKEN="tu_api_token"

# Ejecutar desde el host
bash dev-tools/jenkins/scripts/setup_jenkins_credentials.sh
```

---

## 9. Arranque Completo del Entorno CI/CD

### Orden correcto de arranque

```bash
# 1. Levantar la app principal (necesaria para que ZAP pueda escanearla)
cd /ruta/del/proyecto
docker compose up -d

# 2. Levantar SonarQube
cd dev-tools/sonarqube
docker compose up -d

# 3. Levantar Jenkins
cd dev-tools/jenkins
docker compose up -d

# 4. Verificar que todo esté corriendo
docker ps
```

### Verificar servicios

```bash
# App principal
curl http://localhost:18080

# SonarQube
curl http://localhost:9000

# Jenkins
curl http://localhost:8080
```

### URLs de acceso

| Servicio | URL | Credenciales |
|----------|-----|-------------|
| App | http://localhost:18080 | admin / admin |
| Jenkins | http://localhost:8080 | admin / (password inicial) |
| SonarQube | http://localhost:9000 | admin / admin |

---

## 10. Troubleshooting

### Jenkins no puede ejecutar `docker compose`

```bash
# Verificar que el socket Docker esté montado
docker exec jenkins ls -la /var/run/docker.sock

# Agregar jenkins al grupo docker
docker exec -u root jenkins usermod -aG docker jenkins
docker restart jenkins
```

### SonarQube no responde

```bash
# Verificar logs
docker compose -f dev-tools/sonarqube/docker-compose.yml logs -f sonarqube

# SonarQube necesita bastante memoria. Verificar:
docker stats sonarqube

# Aumentar vm.max_map_count si falla con "max virtual memory areas"
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

### ZAP no llega a la app

```bash
# En Linux, verificar que host.docker.internal esté disponible
docker run --rm --network host alpine wget -q -O- http://localhost:18080

# Si no funciona, usar la IP del host directamente
ip route | grep docker | awk '{print $9}'
# Usar esa IP en el docker-compose.yml de ZAP
```

### Quality Gate siempre falla

```bash
# Ver el estado del Quality Gate en SonarQube
# http://localhost:9000 → Projects → vuln-app → Quality Gate

# Para ajustar los umbrales:
# SonarQube → Quality Gates → Crear uno personalizado
# Asignar al proyecto en: Project Settings → Quality Gate
```

### Pipeline no encuentra el Jenkinsfile

```
# Verificar que el archivo esté en la raíz del repo
ls -la Jenkinsfile

# Verificar en Jenkins:
# Pipeline → Configure → Script Path = "Jenkinsfile"
```

---

## Diagrama Resumen

```
git push
   │
   ▼
Jenkins detecta cambio
   │
   ├─ [FAIL] ──────────────────────────────────────► Notificación error
   │
   ▼
1. Checkout código
2. pytest → coverage.xml
3. vitest → lcov.info
4. SonarQube scan ──► Quality Gate ──[FAIL]──► Pipeline se detiene
5. docker compose build
6. docker compose up (staging)
7. OWASP ZAP scan ──► zap_report.html
8. Publicar reporte en Jenkins UI
9. [solo rama main] Aprobación manual ──► Deploy producción
   │
   ▼
✅ Build exitoso
```

---

*Documentación CI/CD generada el 2026-05-11*

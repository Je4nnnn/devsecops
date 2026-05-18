pipeline {
    agent any

    environment {
        APP_NAME      = 'vuln-app-wazuh'
        SONAR_PROJECT = 'vuln-app'
        STAGING_PORT  = '18080'
        REPORTS_DIR   = "${WORKSPACE}/dev-tools/reports"
    }

    options {
        timeout(time: 30, unit: 'MINUTES')
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '10'))
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
                echo "Rama: ${env.GIT_BRANCH} | Commit: ${env.GIT_COMMIT?.take(7)}"
            }
        }

        stage('Test Backend') {
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
        }

        stage('Test Frontend') {
            steps {
                sh '''
                    cd frontend
                    npm install --silent
                    npm run coverage
                '''
            }
        }

        stage('SAST - SonarQube') {
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
                            -Dsonar.exclusions=**/venv/**,**/node_modules/**,**/dist/**,**/__pycache__/**
                    '''
                }
            }
        }

        stage('Quality Gate') {
            steps {
                timeout(time: 5, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: true
                }
            }
        }

        stage('Build Docker') {
            steps {
                sh 'docker compose build --no-cache api frontend'
            }
        }

        stage('Deploy Staging') {
            steps {
                sh '''
                    docker compose down --remove-orphans || true
                    docker compose up -d
                    echo "Esperando que la app este lista..."
                    sleep 15
                    curl -f http://localhost:${STAGING_PORT} || exit 1
                    echo "App disponible en :${STAGING_PORT}"
                '''
            }
        }

        stage('DAST - OWASP ZAP') {
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

        stage('Deploy Produccion') {
            when {
                branch 'main'
            }
            steps {
                input message: 'Aprobar despliegue a produccion?', ok: 'Desplegar'
                sh '''
                    echo "Desplegando en produccion..."
                    docker compose up -d
                    echo "Desplegado exitosamente"
                '''
            }
        }
    }

    post {
        success {
            echo 'Pipeline completado exitosamente'
        }
        failure {
            echo 'Pipeline fallo - revisar logs'
            sh 'docker compose down || true'
        }
        always {
            echo 'Reportes disponibles en Jenkins UI'
        }
    }
}

# Explicacion del pipeline CI/CD

Este documento resume que hace cada etapa del pipeline de Jenkins del proyecto. La idea principal es validar automaticamente que el codigo actualizado funcione, tenga cobertura minima de pruebas y pase controles de seguridad antes de considerarlo correcto.

El pipeline se ejecuta sobre la rama configurada en Jenkins, en este caso `qa-quality-gates`. Esa rama contiene las actualizaciones traidas desde `main` y los ajustes propios de calidad/pipeline.

## Flujo general

1. Jenkins descarga el codigo desde GitHub.
2. Ejecuta pruebas automaticas de backend y frontend.
3. Valida que la cobertura de pruebas cumpla minimos definidos.
4. Ejecuta analisis estatico con SonarQube.
5. Ejecuta analisis de dependencias y contenedores con Trivy.
6. Levanta la aplicacion en contenedores para escanearla dinamicamente con OWASP ZAP.
7. Archiva reportes y limpia contenedores temporales.

## Etapas del pipeline

### 1. Declarative: Checkout SCM

Jenkins obtiene el repositorio desde GitHub y hace checkout de la rama configurada.

En esta etapa se asegura que el workspace tenga el codigo exacto que se va a evaluar. Si la rama es `qa-quality-gates`, Jenkins analiza esa rama y no otra.

### 2. CI: Backend Tests & Coverage

Ejecuta las pruebas automaticas del backend dentro de un contenedor Docker.

Usa `pytest` para probar la API Python y genera dos salidas importantes:

- `backend-junit_<build>.xml`: reporte de resultados de pruebas.
- `vuln-api/coverage.xml`: reporte de cobertura del backend.

Si una prueba falla, el pipeline se detiene. Esta etapa demuestra que la logica del backend sigue funcionando despues de los cambios.

### 3. GATE: Backend Coverage

Valida que la cobertura del backend cumpla el minimo configurado.

Actualmente el minimo es:

```text
BACKEND_MIN_COVERAGE = 70%
```

Si la cobertura queda bajo ese valor, Jenkins marca el build como fallido. Este gate evita aceptar cambios con poca cobertura de pruebas.

### 4. CI: Frontend Tests & Build

Ejecuta las pruebas del frontend y construye la aplicacion web.

Primero crea una imagen temporal para correr los tests del frontend con `npm run test:coverage`. Luego copia el reporte de cobertura generado en:

```text
frontend/coverage/lcov.info
```

Despues ejecuta el build Docker del frontend. Esta etapa confirma que la interfaz puede probarse y compilarse correctamente.

### 5. GATE: Frontend Coverage

Valida que la cobertura del frontend cumpla el minimo configurado.

Actualmente el minimo es:

```text
FRONTEND_MIN_COVERAGE = 60%
```

Si la cobertura del frontend queda bajo ese porcentaje, el pipeline falla. Este control asegura que el frontend tambien tenga pruebas suficientes.

### 6. SAST: Start SonarQube

Levanta SonarQube y su base de datos usando Docker Compose.

SonarQube se usa para analisis estatico de codigo, es decir, revisa el codigo sin ejecutarlo. La etapa espera hasta que SonarQube responda como disponible antes de continuar.

### 7. GATE: SonarQube Availability

Comprueba que SonarQube realmente este disponible.

Hace una consulta al endpoint de estado de SonarQube y solo continua si el servidor responde con estado `UP`. Este gate evita ejecutar el analisis si la herramienta no esta lista.

### 8. SAST: Configure SonarQube Quality Gate

Configura el Quality Gate de SonarQube para el proyecto.

El Quality Gate es el conjunto de reglas minimas que debe cumplir el codigo. En este pipeline se revisan condiciones como:

- Cobertura minima.
- Duplicacion de codigo.
- Rating de mantenibilidad.
- Rating de seguridad.
- Rating de confiabilidad.

Tambien asigna ese gate al proyecto `vuln-app`.

### 9. SAST: SonarQube Code Analysis

Ejecuta `sonar-scanner` sobre el proyecto.

SonarQube analiza codigo Python, JavaScript, CSS y HTML. Tambien recibe los reportes de cobertura generados antes por backend y frontend.

Esta etapa puede detectar:

- Bugs.
- Vulnerabilidades.
- Code smells.
- Duplicacion de codigo.
- Problemas de mantenibilidad.
- Cobertura insuficiente.

El resultado queda disponible en el dashboard de SonarQube.

### 10. GATE: SonarQube Quality Gate

Espera el resultado final del analisis de SonarQube y valida el Quality Gate.

Si SonarQube responde `OK`, el pipeline continua. Si responde con fallo, Jenkins detiene el build.

Esta etapa es importante porque convierte el analisis de SonarQube en una decision automatica: aprobar o rechazar el cambio.

### 11. SCA: Trivy Dependency Scan

Ejecuta Trivy en modo filesystem.

Este analisis revisa dependencias y configuraciones del repositorio, sin necesidad de escanear una imagen Docker final. Busca vulnerabilidades conocidas en paquetes y posibles problemas de configuracion.

Genera el reporte:

```text
reports/trivy_fs_<build>.json
```

### 12. GATE: Trivy SCA

Evalua el reporte anterior de Trivy.

El pipeline esta configurado para fallar si encuentra vulnerabilidades:

```text
CRITICAL,HIGH
```

Tambien ignora vulnerabilidades sin fix disponible cuando corresponde. Si no hay hallazgos bloqueantes, el gate queda en `OK`.

### 13. Container: Build Images for Trivy

Construye imagenes Docker limpias de la API y del frontend para poder analizarlas.

Usa:

```text
docker compose build --pull --no-cache api frontend
```

Esto fuerza a Docker a traer bases actualizadas y evita usar capas antiguas que podrian contener vulnerabilidades ya corregidas.

### 14. Container: Trivy Image Scan

Escanea las imagenes Docker construidas en la etapa anterior.

Trivy analiza el sistema operativo de cada imagen y sus paquetes internos. En este proyecto revisa:

- Imagen backend: `jenkins-security-api`.
- Imagen frontend: `jenkins-security-frontend`.

Genera reportes JSON separados para backend y frontend.

### 15. GATE: Trivy Containers

Evalua los reportes de Trivy sobre imagenes Docker.

Si encuentra vulnerabilidades `HIGH` o `CRITICAL`, el pipeline falla. Este gate asegura que las imagenes que se despliegan no tengan vulnerabilidades bloqueantes conocidas.

En este pipeline existe una excepcion controlada:

```text
TRIVY_IGNORE_IDS = GHSA-537c-gmf6-5ccf
```

Esa excepcion acepta un hallazgo especifico de `cryptography` porque no habia version nueva disponible para corregirlo directamente, y queda declarado de forma explicita.

### 16. DAST: OWASP ZAP Dynamic Scan

Levanta la aplicacion en contenedores y ejecuta OWASP ZAP contra la app funcionando.

A diferencia de SonarQube, que revisa codigo estatico, ZAP analiza la aplicacion en ejecucion. Esto permite detectar problemas visibles desde HTTP.

El pipeline escanea:

- API: usando el documento OpenAPI en `http://api:8000/openapi.json`.
- Frontend: usando `http://frontend:80`.

Tambien intenta obtener un token de login para ejecutar parte del escaneo de API de forma autenticada.

OWASP ZAP puede detectar problemas como:

- Headers de seguridad faltantes.
- Riesgos de XSS.
- Riesgos de inyeccion.
- Configuraciones inseguras.
- Exposicion de informacion.
- Problemas comunes en endpoints HTTP.

Para evitar conflictos de puertos en Jenkins, esta etapa usa puertos dinamicos para la base de datos y el frontend:

```text
DB_HOST_PORT=0
FRONTEND_HTTP_PORT=0
FRONTEND_HTTPS_PORT=0
```

La comunicacion entre contenedores se hace por la red interna de Docker.

### 17. GATE: OWASP ZAP

Evalua los reportes JSON generados por OWASP ZAP.

El pipeline esta configurado para fallar si ZAP encuentra alertas de riesgo:

```text
High
```

Si solo hay alertas no bloqueantes, el pipeline continua. Si hay una alerta `High`, Jenkins marca el build como fallido.

### 18. Declarative: Post Actions

Se ejecuta al final del pipeline, incluso si alguna etapa fallo.

Hace tres tareas principales:

- Archiva reportes generados durante el build.
- Elimina contenedores temporales.
- Baja entornos Docker usados por Jenkins.

Esto permite revisar evidencias despues del build y evita que queden contenedores ocupando recursos o puertos.

## Sintesis para presentar

El pipeline valida el proyecto de forma progresiva. Primero comprueba que backend y frontend funcionen con pruebas automaticas. Luego aplica gates de cobertura para asegurar calidad minima. Despues ejecuta SonarQube para detectar problemas en el codigo fuente. Mas adelante usa Trivy para revisar vulnerabilidades en dependencias y en imagenes Docker. Finalmente levanta la aplicacion y usa OWASP ZAP para hacer un escaneo dinamico contra la API y el frontend reales.

La ventaja de este flujo es que no solo confirma que la aplicacion compile o que los tests pasen, sino que tambien integra controles DevSecOps: calidad, cobertura, analisis estatico, analisis de dependencias, seguridad de contenedores y analisis dinamico antes de aceptar el resultado del build.

# Desarrollo y validación con Docker

Este flujo permite modificar frontend o backend, reconstruir solamente el servicio afectado y conservar la base de datos.

## 1. Levantar la aplicación

Desde la raíz del repositorio:

```bash
docker compose up -d
docker compose ps
```

Frontend: <http://localhost:18080>

Los datos permanecen en el volumen `postgres_api_data`. No usar `docker compose down -v`, porque `-v` elimina los volúmenes.

## 2. Cambiar el frontend

Editar archivos dentro de `frontend/`. Un `docker compose up -d` normal puede reutilizar la imagen existente y no incorporar esos cambios.

Reconstruir y reemplazar solamente el frontend:

```bash
docker compose up -d --build frontend
docker compose ps frontend
docker compose logs --tail=100 frontend
```

Después, recargar <http://localhost:18080>. Si el navegador conserva recursos antiguos, usar una recarga forzada (`Ctrl+Shift+R`).

## 3. Cambiar el backend

Reconstruir la API sin eliminar la base de datos:

```bash
docker compose up -d --build api
docker compose ps api
docker compose logs --tail=100 api
```

Si el cambio afecta también al contrato o consumo del frontend:

```bash
docker compose up -d --build api frontend
```

## 4. Revisar antes de publicar

```bash
git status
git diff --check
git diff
docker compose ps
```

Verificar manualmente el inicio de sesión, la pantalla modificada y las funciones relacionadas. La reconstrucción de servicios no elimina `postgres_api_data`.

## 5. Probar el pipeline completo

Jenkins obtiene el código desde GitHub; no puede evaluar modificaciones que existen solamente en el equipo local.

1. Crear el commit y subirlo a la rama correspondiente.
2. Abrir Jenkins en <http://localhost:8080>.
3. Ejecutar el job de la rama y comprobar todas sus etapas, incluido SonarQube y ZAP.
4. Consultar SonarQube en <http://localhost:9000> si una quality gate falla.

No es necesario reconstruir Jenkins por cambios normales del frontend, backend o `Jenkinsfile` almacenado en GitHub. Se reconstruye Jenkins sólo cuando cambia `dev-tools/jenkins/Dockerfile`, sus plugins o su configuración interna:

```bash
docker compose up -d --build jenkins
```

## 6. Detener sin perder datos

```bash
docker compose down
```

Para volver a iniciar:

```bash
docker compose up -d
```

Evitar `docker compose down -v` salvo que se quiera borrar deliberadamente la base de datos y los datos persistentes de Jenkins y SonarQube.

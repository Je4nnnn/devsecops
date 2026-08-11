# Despliegue offline en Kali Linux

Esta guía instala la aplicación completa —TimescaleDB/PostgreSQL, API FastAPI y frontend Nginx— sin descargar imágenes, paquetes Python ni paquetes npm en el equipo Kali.

El paquete es offline a partir del momento en que Kali ya tiene Docker Engine, Docker Compose v2 y OpenSSL. Si el equipo no los tiene y tampoco tendrá Internet, esos paquetes del sistema operativo deben prepararse previamente para la misma versión y arquitectura de Kali.

## 1. Resultado esperado

Después del despliegue estarán disponibles:

- Frontend HTTP: `http://IP_DE_KALI:18080`
- Frontend HTTPS: `https://IP_DE_KALI:18443`
- Documentación API: `https://IP_DE_KALI:18443/api/docs`
- PostgreSQL solo dentro de la red Docker; no se publica el puerto 5432/5433.
- Datos persistentes en un volumen Docker, incluso después de `docker compose down`.

Recursos recomendados para la prueba:

- CPU: 2 núcleos como mínimo; 4 recomendados.
- RAM: 4 GB como mínimo; 8 GB para sincronizaciones grandes.
- Disco libre: 12 GB como mínimo; 20 GB o más si se cargarán muchas detecciones.
- Arquitectura del paquete y Kali idénticas, normalmente `amd64`.

## 2. Contenido del paquete

El generador crea:

```text
devsecops-VERSION/
├── .env.example
├── VERSION
├── PLATFORM
├── SOURCE_COMMIT
├── README.md
├── docker-compose.offline.yml
├── images.tar.gz
├── images.tar.gz.sha256
├── image-manifest.json
├── deploy.sh
├── smoke-test.sh
├── backup-database.sh
└── restore-database.sh
```

`images.tar.gz` contiene las tres imágenes necesarias y Compose usa `pull_policy: never`; el despliegue falla de manera explícita si falta una imagen, en lugar de intentar acceder a Internet.

## 3. Preparar el paquete en un equipo con Internet

Esta fase se ejecuta una sola vez en el repositorio, sobre la rama portable:

```bash
git switch codex/entrega3-portable-qa
git status
docker version
docker compose version

./scripts/create-offline-bundle.sh entrega3-portable-v1
```

El build descarga las dependencias únicamente en este equipo. Al finalizar se generan:

```text
offline-dist/devsecops-entrega3-portable-v1.tar.gz
offline-dist/devsecops-entrega3-portable-v1.tar.gz.sha256
```

Conserve ambos archivos. El checksum permite detectar una copia incompleta o alterada.

### Prueba recomendada antes de transportar

```bash
sha256sum -c offline-dist/devsecops-entrega3-portable-v1.tar.gz.sha256
```

Si el equipo de preparación no tiene la misma arquitectura que Kali, genere el paquete en otra máquina/VM Linux de la arquitectura correcta. El instalador compara `PLATFORM` con el equipo destino y no permite mezclar `amd64` con `arm64`.

## 4. Preparar Kali

Si Kali tiene Internet temporalmente:

```bash
sudo apt update
sudo apt install -y docker.io docker-compose openssl ca-certificates
sudo systemctl enable --now docker

sudo docker run --rm hello-world
sudo docker compose version
```

Importante: en Kali el paquete de contenedores se llama `docker.io`; instalar un paquete llamado solamente `docker` puede instalar otra herramienta.

Si Kali no tiene Internet y Docker no está instalado, prepare los paquetes `.deb` de `docker.io`, `docker-compose` y sus dependencias desde otro Kali de la misma versión/arquitectura. Esa instalación pertenece al sistema operativo y no puede incluirse de forma universal en este paquete porque Kali Rolling cambia sus dependencias.

## 5. Transferir y verificar

Copie el `.tar.gz` y su `.sha256` por USB, SCP o el medio autorizado. En Kali:

```bash
mkdir -p ~/entrega3
cd ~/entrega3

sha256sum -c devsecops-entrega3-portable-v1.tar.gz.sha256
tar -xzf devsecops-entrega3-portable-v1.tar.gz
cd devsecops-entrega3-portable-v1
```

El checksum debe responder `OK`. No continúe si falla.

En este punto puede desconectar Kali de Internet para demostrar que el despliegue es realmente offline.

## 6. Instalar

Ejecute:

```bash
sudo ./deploy.sh
```

El instalador:

1. Comprueba arquitectura y checksum interno.
2. Carga las imágenes con `docker load`.
3. Genera contraseñas, JWT y clave Fernet diferentes para ese equipo.
4. Crea un certificado TLS autofirmado local.
5. Valida Compose.
6. Levanta base, API y frontend sin hacer `pull` ni `build`.
7. Espera hasta que los tres servicios estén saludables.

La primera ejecución crea:

- `.env`, con permisos `600`.
- `CREDENCIALES_INICIALES.txt`, con permisos `600`.
- `nginx/ssl/`, con el certificado específico del equipo.

Lea el usuario y contraseña inicial:

```bash
sudo cat CREDENCIALES_INICIALES.txt
```

La aplicación solicitará cambiar la contraseña inicial durante el primer ingreso.

## 7. Verificar backend, frontend y base

Ejecute la prueba automatizada:

```bash
sudo ./smoke-test.sh
```

Debe finalizar con:

```text
SMOKE TEST: OK
```

También puede revisar:

```bash
sudo docker compose --env-file .env -f docker-compose.offline.yml ps
sudo docker compose --env-file .env -f docker-compose.offline.yml logs --tail=100 api
```

Obtenga la IP de Kali:

```bash
hostname -I
```

Desde otro equipo de la misma red abra:

```text
http://IP_DE_KALI:18080
https://IP_DE_KALI:18443
```

El navegador advertirá que el certificado es autofirmado. Para una prueba en una LAN cerrada es esperado; no lo use como certificado público.

Si otro equipo no puede acceder, compruebe conectividad y reglas del firewall para TCP `18080` y `18443`.

## 8. Cargar datos desde Wazuh

En el frontend:

1. Inicie sesión y cambie la contraseña inicial.
2. Abra **Administrar conexiones Wazuh**.
3. Registre nombre, URL del Indexer, usuario y contraseña.
4. Presione **Probar conexión**.
5. Ejecute la sincronización.
6. Observe el progreso y luego valide Dashboard, Timeline, filtros, paquetes y grupos.

Use una URL alcanzable desde el contenedor API, por ejemplo:

```text
https://192.168.1.60:9200
```

No use `localhost` para un Wazuh instalado en el host Kali: dentro del contenedor, `localhost` identifica al propio contenedor. Use la IP real del host o un nombre DNS accesible desde Docker.

El paquete de laboratorio deja `WAZUH_VERIFY_TLS=false` para permitir Indexers con certificados autofirmados. Para un entorno real cambie a:

```env
WAZUH_VERIFY_TLS=true
```

o indique una ruta de CA válida dentro del contenedor.

Durante una carga:

```bash
sudo docker compose --env-file .env -f docker-compose.offline.yml logs -f api
```

Compruebe los registros cargados:

```bash
sudo docker compose --env-file .env -f docker-compose.offline.yml exec db-api \
  sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "
    SELECT COUNT(*) AS assets FROM assets;
    SELECT COUNT(*) AS findings FROM vulnerability_findings;
    SELECT COUNT(*) AS detections FROM vulnerability_detections;
    SELECT COUNT(*) AS packages FROM packages;
  "'
```

## 9. Casos mínimos de aceptación

Compruebe:

1. Login y cambio obligatorio de contraseña.
2. Alta y prueba de una conexión Wazuh.
3. Sincronización y progreso hasta estado completado.
4. Filtro resuelta/no resuelta.
5. Filtro numérico por puntaje.
6. Filtros de grupos, agentes, CVE, paquete y sistema operativo.
7. Dashboard con tortas, histograma y riesgo por grupo.
8. Timeline consolidado sin seleccionar conexión y rango mensual.
9. Hallazgos resueltos en verde.
10. Tabla de paquetes.
11. Reinicio conservando los datos.

Para probar persistencia:

```bash
sudo docker compose --env-file .env -f docker-compose.offline.yml restart
sudo ./smoke-test.sh
```

## 10. Respaldar y restaurar

Crear un respaldo:

```bash
sudo ./backup-database.sh
```

Se genera un `.dump` y su checksum en `backups/`.

Restaurar recrea por completo la base de datos de destino. Hágalo solo sobre el
equipo correcto y después de conservar un respaldo reciente:

```bash
sudo ./restore-database.sh backups/ARCHIVO.dump --confirmar-restauracion
```

El script valida el checksum, detiene la API, usa el modo de restauración de
TimescaleDB y vuelve a iniciar la API al finalizar.

## 11. Operación y limpieza

Detener conservando datos:

```bash
sudo docker compose --env-file .env -f docker-compose.offline.yml down
```

Volver a iniciar:

```bash
sudo docker compose --env-file .env -f docker-compose.offline.yml up -d
```

Ver logs:

```bash
sudo docker compose --env-file .env -f docker-compose.offline.yml logs -f
```

No ejecute `down -v` durante una prueba normal. Esa opción elimina el volumen y, por lo tanto, la base de datos.

## 12. Actualizar la aplicación

Genere un paquete con una versión nueva:

```bash
./scripts/create-offline-bundle.sh entrega3-portable-v2
```

Respalde la base en Kali antes de actualizar. Cada paquete mantiene su propio `.env`; no copie claves Fernet entre instalaciones sin considerar que las contraseñas Wazuh ya almacenadas fueron cifradas con esa clave.

## 13. Solución rápida de problemas

### Un servicio queda `unhealthy`

```bash
sudo docker compose --env-file .env -f docker-compose.offline.yml ps
sudo docker compose --env-file .env -f docker-compose.offline.yml logs --tail=200
```

### Puertos ocupados

Edite `.env`:

```env
FRONTEND_HTTP_PORT=28080
FRONTEND_HTTPS_PORT=28443
```

y vuelva a ejecutar:

```bash
sudo docker compose --env-file .env -f docker-compose.offline.yml up -d
```

### Wazuh no conecta

- No use `localhost`.
- Compruebe desde Kali: `curl -k https://IP_WAZUH:9200`.
- Confirme usuario, contraseña y reglas de red.
- Si usa un certificado válido, active `WAZUH_VERIFY_TLS=true`.

### La sincronización consume demasiada memoria

Observe el consumo:

```bash
sudo docker stats
```

Para cargas grandes, use al menos 8 GB de RAM y evite ejecutar simultáneamente Jenkins, SonarQube o escáneres QA en el mismo Kali destinado a la demostración.

# RestroFlux - Deploy en Portainer

## Opción 1: Portainer Repository (recomendada si Portainer puede buildar)

Usa [docker-compose.yml](docker-compose.yml).

1. En Portainer crea un stack desde Git repository.
2. Selecciona el repositorio y el archivo `docker-compose.yml`.
3. En la sección de variables carga, como mínimo:
   - `JWT_SECRET`
   - `DB_PASSWORD`
   - `PUBLIC_BASE_URL`
4. Si usarás integraciones, agrega también:
   - `GEMINI_API_KEY`
   - `MP_ACCESS_TOKEN`
   - `MP_WEBHOOK_SECRET`
   - `SMTP_HOST`
   - `SMTP_PORT`
   - `SMTP_USER`
   - `SMTP_PASS`
   - `SMTP_FROM`
5. Despliega el stack.

Notas:
- No uses `env_file` en Portainer Repository.
- El compose ya usa defaults seguros y variables inyectadas por Portainer.
- El hostname interno de PostgreSQL es `restroflux-postgres`.

## Opción 2: Portainer Stack en Swarm

Usa [stack.yml](stack.yml).

1. Publica antes una imagen del proyecto en un registry.
2. Define `RESTROFLUX_IMAGE` en Portainer con esa imagen.
3. Carga las mismas variables de entorno que en la opción Repository.
4. Despliega el stack.

Notas:
- Swarm no es la vía correcta para buildar desde el repo; por eso `stack.yml` usa `image` y no `build`.
- Si defines `DATABASE_URL`, debe usar como host `restroflux-postgres` o un host externo resolvible desde la red del stack.

## Variables mínimas de producción

- `JWT_SECRET`
- `DB_PASSWORD` o `DATABASE_URL`
- `PUBLIC_BASE_URL`

## Variables opcionales

- `GEMINI_API_KEY`
- `GLOBAL_ADMIN_BOOTSTRAP_TOKEN`
- `MP_ACCESS_TOKEN`
- `MP_WEBHOOK_SECRET`
- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USER`
- `SMTP_PASS`
- `SMTP_FROM`
- `MINIO_ROOT_USER`
- `MINIO_ROOT_PASSWORD`

## Verificación rápida

1. Confirmar que el contenedor/app responda en `http://TU_HOST:3000`.
2. Revisar logs de `restroflux-app`.
3. Confirmar que la app ya no busque `.env` en el host de Portainer.
4. Confirmar que PostgreSQL resuelva por `restroflux-postgres`.
5. Si usas PostgreSQL interno del stack, dejar `DATABASE_SSL=false`.

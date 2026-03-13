# RestroFlux - Deploy Cloud / Demo

## Objetivo

Este modo está pensado para demo pública o infraestructura cloud propia.

Características:

- imagen Docker publicada en GHCR
- compatible con Portainer Repository y Docker Swarm
- variables externas
- sin secretos en el repo
- apto para correr detrás de reverse proxy

## Archivos usados

- [docker-compose.cloud.yml](docker-compose.cloud.yml)
- [docker-compose.yml](docker-compose.yml): alias de compatibilidad
- [stack.yml](stack.yml): si prefieres stack Swarm
- [.github/workflows/publish-ghcr.yml](.github/workflows/publish-ghcr.yml)

## Imagen de la app

La app se publica en GHCR con este formato:

- `ghcr.io/<owner>/restroflux-app:latest`
- `ghcr.io/<owner>/restroflux-app:sha-<commit>`
- `ghcr.io/<owner>/restroflux-app:vX.Y.Z` cuando haces push de tags

## Variables mínimas

- `PUBLIC_BASE_URL`
- `JWT_SECRET`
- `DB_PASSWORD` y `POSTGRES_PASSWORD`, o bien `DATABASE_URL`

Variables opcionales:

- `GEMINI_API_KEY`
- `MP_ACCESS_TOKEN`
- `MP_WEBHOOK_SECRET`
- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USER`
- `SMTP_PASS`
- `SMTP_FROM`
- `RESTROFLUX_IMAGE`
- `MINIO_IMAGE`

## GHCR

El workflow publica automáticamente a GHCR usando `GITHUB_TOKEN` con permisos:

- `contents: read`
- `packages: write`

Si vas a desplegar desde Portainer sin credenciales extra, deja el paquete GHCR como público.
Si lo mantienes privado, configura el registry en Portainer con credenciales de GitHub.

## Portainer Repository

1. Publica la imagen con GitHub Actions.
2. En Portainer crea un stack desde Git repository.
3. Usa [docker-compose.cloud.yml](docker-compose.cloud.yml) o [docker-compose.yml](docker-compose.yml).
4. Carga las variables del entorno desde la UI de Portainer.
5. Despliega.

## Docker Swarm

1. Usa [stack.yml](stack.yml) o [docker-compose.cloud.yml](docker-compose.cloud.yml).
2. Si quieres congelar versión, define:

```env
RESTROFLUX_IMAGE=ghcr.io/<owner>/restroflux-app:sha-<commit>
```

3. Ejecuta el deploy desde Portainer o con `docker stack deploy`.

## Reverse proxy

- Publica solo el puerto HTTP de la app.
- Deja PostgreSQL y MinIO internos a la red del stack.
- Configura `PUBLIC_BASE_URL` con tu dominio público real.
- Si usas suscripciones o reseteo de contraseña, `PUBLIC_BASE_URL` debe estar bien definido.

## Actualización cloud

1. Espera a que GitHub Actions publique la nueva imagen.
2. Cambia `RESTROFLUX_IMAGE` a un nuevo tag si quieres control de versión.
3. Redeploya el stack en Portainer.

Más detalle en [UPDATE.md](UPDATE.md).
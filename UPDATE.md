# RestroFlux - Actualizaciones

## Cloud / Demo

1. Haz push a `main` o publica un tag.
2. Espera a que GitHub Actions publique la nueva imagen en GHCR.
3. En Portainer actualiza el stack:
   - dejando `latest`, o
   - fijando `RESTROFLUX_IMAGE=ghcr.io/<owner>/restroflux-app:sha-<commit>`
4. Redeploya.

Recomendación:

- usa `sha-<commit>` para producción más controlada
- usa `latest` para demo rápida

## Local / On-Premise

Antes de actualizar:

1. Haz backup siguiendo [BACKUP.md](BACKUP.md).
2. Guarda una copia de `./.env.local`.

Actualizar imagen y servicios:

```bash
docker compose --env-file .env.local -f docker-compose.local.yml pull
docker compose --env-file .env.local -f docker-compose.local.yml up -d
```

En PowerShell:

```powershell
docker compose --env-file .env.local -f docker-compose.local.yml pull
docker compose --env-file .env.local -f docker-compose.local.yml up -d
```

## Cambios de versión controlados

Si quieres congelar una versión en un cliente:

```env
RESTROFLUX_IMAGE=ghcr.io/<owner>/restroflux-app:sha-<commit>
```

## Si algo sale mal

1. Vuelve al tag o sha anterior.
2. Redeploya la imagen anterior.
3. Si hubo cambios de datos incompatibles, restaura backup.

## Buenas prácticas

- no actualices directo en horario crítico
- prueba primero en demo o staging
- conserva al menos una versión anterior y un backup reciente
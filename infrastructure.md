
# RestroFlux Infrastructure & Deployment

## Estado actual del repo

- El despliegue principal está en [docker-compose.yml](docker-compose.yml).
- El despliegue on-premise usa [infra/docker-compose.onprem.yml](infra/docker-compose.onprem.yml).
- El despliegue Docker Swarm/Portainer Stack usa [stack.yml](stack.yml).
- El repo no depende de un `.env` real versionado: Portainer inyecta variables y los ejemplos están en [.env.example](.env.example) e [infra/.env.onprem.example](infra/.env.onprem.example).

## Estrategia de variables

- Para Portainer Repository: define variables en la UI del stack usando [.env.example](.env.example) como checklist.
- Para Docker Compose local: puedes usar un `.env` local no versionado, pero el compose ya no lo requiere vía `env_file`.
- Para on-premise: el instalador usa `--env-file infra/.env.onprem` y toma como base [infra/.env.onprem.example](infra/.env.onprem.example).

## PostgreSQL en Docker

- El hostname interno estándar es `restroflux-postgres`.
- La app prioriza `DATABASE_URL`; si no existe, arma la conexión con `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER` y `DB_PASSWORD`.
- `DATABASE_SSL=false` es el default correcto para PostgreSQL interno del stack. Si usas un PostgreSQL gestionado con TLS, define `DATABASE_SSL=true`.

## Compatibilidad Portainer / Swarm

- [docker-compose.yml](docker-compose.yml) sirve para Portainer Repository en modo compose y puede construir desde el repo.
- [stack.yml](stack.yml) sirve para Swarm y usa una imagen preconstruida; Swarm no builda desde git de forma confiable, por eso ahí se usa `image`.
- El Dockerfile acepta build args `VITE_*` no sensibles para que Vite compile sin depender de un `.env` real.

## On-premise

1. Crear el archivo local:

```powershell
cd infra
Copy-Item .env.onprem.example .env.onprem
```

2. Editar variables reales en `infra/.env.onprem`.

3. Ejecutar el instalador:

```powershell
cd scripts
powershell -ExecutionPolicy Bypass -File .\install_onprem.ps1
```

## Notas operativas

- No subas secretos al repo.
- No expongas PostgreSQL o MinIO públicamente salvo que sea estrictamente necesario.
- Mantén backups de base de datos y uploads.


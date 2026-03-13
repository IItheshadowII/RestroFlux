# RestroFlux - Backups

## Qué respaldar

En modo local/on-premise respalda al menos:

- `./.env.local`
- `./local-data/postgres`
- `./local-data/minio`
- `./local-data/uploads`
- `./backups` si ya contiene históricos

En cloud/demo respalda:

- volúmenes de PostgreSQL
- volúmenes de MinIO si lo estás usando
- variables críticas del entorno

## Backup recomendado en modo local

### PostgreSQL

Linux:

```bash
mkdir -p backups
docker compose --env-file .env.local -f docker-compose.local.yml exec -T restroflux-postgres \
  pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" > backups/postgres_$(date +%Y%m%d_%H%M%S).sql
```

PowerShell:

```powershell
New-Item -ItemType Directory -Force -Path .\backups | Out-Null
$ts = Get-Date -Format yyyyMMdd_HHmmss
docker compose --env-file .env.local -f docker-compose.local.yml exec -T restroflux-postgres `
  pg_dump -U $env:POSTGRES_USER $env:POSTGRES_DB > ".\backups\postgres_$ts.sql"
```

### MinIO / archivos

Si estás usando MinIO o uploads locales, copia estas carpetas:

- `./local-data/minio`
- `./local-data/uploads`

Linux:

```bash
tar -czf backups/files_$(date +%Y%m%d_%H%M%S).tar.gz local-data/minio local-data/uploads
```

PowerShell:

```powershell
$ts = Get-Date -Format yyyyMMdd_HHmmss
Compress-Archive -Path .\local-data\minio, .\local-data\uploads -DestinationPath ".\backups\files_$ts.zip" -Force
```

## Restore

### PostgreSQL

Linux:

```bash
cat backups/postgres_YYYYMMDD_HHMMSS.sql | docker compose --env-file .env.local -f docker-compose.local.yml exec -T restroflux-postgres \
  psql -U "$POSTGRES_USER" "$POSTGRES_DB"
```

PowerShell:

```powershell
Get-Content .\backups\postgres_YYYYMMDD_HHMMSS.sql | docker compose --env-file .env.local -f docker-compose.local.yml exec -T restroflux-postgres `
  psql -U $env:POSTGRES_USER $env:POSTGRES_DB
```

### Archivos

- restaura `local-data/minio`
- restaura `local-data/uploads`

## Recomendación operativa

- Haz backup antes de cada actualización.
- Guarda una copia fuera del servidor.
- Verifica periódicamente que el restore funcione.
- Si el cliente depende fuerte del sistema, automatiza dump diario y rotación de backups.
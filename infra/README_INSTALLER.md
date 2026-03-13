# Instalador On-Premise Legacy

Estos archivos se conservan por compatibilidad con instalaciones anteriores.

El flujo recomendado actual está en la raíz del proyecto:

- [install-local.ps1](install-local.ps1)
- [install-local.sh](install-local.sh)
- [docker-compose.local.yml](docker-compose.local.yml)
- [.env.example](.env.example)

Documentación principal:

- [DEPLOY_LOCAL.md](DEPLOY_LOCAL.md)
- [BACKUP.md](BACKUP.md)
- [UPDATE.md](UPDATE.md)

Requisitos
- Windows 10/11 con Docker Desktop instalado y funcionando (WSL2 recomendado).
- PowerShell (ejecutar como Administrador).

Archivos principales
- `infra/scripts/install_onprem.ps1` — instala la stack, crea directorios y aplica migraciones.
- `infra/.env.onprem.example` — ejemplo de variables de entorno.
- `infra/docker-compose.onprem.yml` — override para on‑premise.
- `infra/scripts/backup.ps1` — realiza backup de la BBDD y uploads.
- `infra/scripts/restore.ps1` — restaura backup y uploads.

Uso rápido legacy
1. Copiar el ejemplo de variables:

```powershell
cd infra
Copy-Item .env.onprem.example .env.onprem
# Edita .env.onprem: coloca la licencia y otros valores
```

2. Ejecutar el instalador (PowerShell como Administrador):

```powershell
cd infra\scripts
powershell -ExecutionPolicy Bypass -File .\install_onprem.ps1 -LicenseKey "GF-XXXX-XXXX" -InstanceId "tienda-001"
```

3. Ver logs:

```powershell
docker compose -f ..\docker-compose.yml -f ..\docker-compose.onprem.yml logs -f restroflux-app
```

Backups

```powershell
# Crear backup
cd infra\scripts
powershell -ExecutionPolicy Bypass -File .\backup.ps1 -OutDir "..\backups"

# Restaurar
powershell -ExecutionPolicy Bypass -File .\restore.ps1 -BackupSql "..\backups\pg_backup_20230101010101.sql" -UploadsZip "..\backups\uploads_20230101010101.zip"
```

Notas
- Este flujo quedó como compatibilidad. Para nuevas instalaciones usa los scripts en raíz.
- El archivo `infra/.env.onprem` se puede seguir usando, pero la plantilla principal es ahora `.env.example`.
- Si necesitas empaquetado más cerrado para cliente final, puedes usar el instalador en Go de `infra/installer/` como base futura.

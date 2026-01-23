# Instalador On‑Premise (Windows)

Estos scripts permiten instalar GastroFlow en la máquina del cliente usando Docker Compose.

Requisitos
- Windows 10/11 con Docker Desktop instalado y funcionando (WSL2 recomendado).
- PowerShell (ejecutar como Administrador).

Archivos principales
- `infra/scripts/install_onprem.ps1` — instala la stack, crea directorios y aplica migraciones.
- `infra/.env.onprem.example` — ejemplo de variables de entorno.
- `infra/docker-compose.onprem.yml` — override para on‑premise.
- `infra/scripts/backup.ps1` — realiza backup de la BBDD y uploads.
- `infra/scripts/restore.ps1` — restaura backup y uploads.

Uso rápido
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
docker compose -f ..\docker-compose.yml -f ..\docker-compose.onprem.yml logs -f app
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
- El script asume que la stack usa la imagen `postgres:15` definida en `docker-compose.onprem.yml`.
- Si prefieres usar una base de datos Postgres instalada en el host en lugar del contenedor, el script puede adaptarse.
- Para convertir esto en un `.exe` se puede empaquetar el script con una herramienta de terceros o crear un pequeño instalador en Go/Node que ejecute estos pasos.

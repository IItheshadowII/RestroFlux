param(
  [string]$BackupSql,
  [string]$UploadsZip
)

if (-not $BackupSql) { Write-Host "Especifique la ruta al backup SQL (param BackupSql)." -ForegroundColor Red; exit 1 }

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptRoot '..\..')

# Encontrar contenedor Postgres
$pgContainer = & docker ps -qf "ancestor=postgres:15" | Select-Object -First 1
if (-not $pgContainer) { $pgContainer = & docker ps -qf "ancestor=postgres:15-alpine" | Select-Object -First 1 }
if (-not $pgContainer) { Write-Host "No se encontró contenedor Postgres. Abortando." -ForegroundColor Red; exit 1 }

Write-Host "Restaurando $BackupSql en la base de datos..." -ForegroundColor Cyan
& docker cp "$BackupSql" "$pgContainer:/tmp/restore.sql"
& docker exec -i $pgContainer psql -U gastroflow -d gastroflow -f /tmp/restore.sql

if ($UploadsZip) {
  $uploadsDir = Join-Path $repoRoot 'infra\data\uploads'
  Write-Host "Restaurando uploads desde $UploadsZip a $uploadsDir" -ForegroundColor Cyan
  if (-not (Test-Path $uploadsDir)) { New-Item -ItemType Directory -Force -Path $uploadsDir | Out-Null }
  Expand-Archive -Path $UploadsZip -DestinationPath $uploadsDir -Force
}

Write-Host "Restore completado." -ForegroundColor Green
exit 0

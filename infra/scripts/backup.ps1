param(
  [string]$OutDir = "..\backups"
)

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptRoot '..\..')
$out = Resolve-Path (Join-Path $repoRoot $OutDir)
New-Item -ItemType Directory -Force -Path $out | Out-Null

Write-Host "Realizando backup de la base de datos y uploads en: $out" -ForegroundColor Cyan

# Encontrar contenedor Postgres
$pgContainer = & docker ps -qf "ancestor=postgres:15" | Select-Object -First 1
if (-not $pgContainer) { $pgContainer = & docker ps -qf "ancestor=postgres:15-alpine" | Select-Object -First 1 }
if (-not $pgContainer) { Write-Host "No se encontró contenedor Postgres. Abortando." -ForegroundColor Red; exit 1 }

$timestamp = Get-Date -Format yyyyMMddHHmmss
$dumpFile = Join-Path $out "pg_backup_$timestamp.sql"

Write-Host "Dumping Postgres a $dumpFile" -ForegroundColor Cyan
& docker exec -t $pgContainer pg_dump -U gastroflow gastroflow > $dumpFile

# Comprimir uploads
$uploadsDir = Join-Path $repoRoot 'infra\data\uploads'
if (Test-Path $uploadsDir) {
  $zipFile = Join-Path $out "uploads_$timestamp.zip"
  Write-Host "Comprimiendo uploads a $zipFile" -ForegroundColor Cyan
  Compress-Archive -Path (Join-Path $uploadsDir '*') -DestinationPath $zipFile -Force
}

Write-Host "Backup completado." -ForegroundColor Green
exit 0

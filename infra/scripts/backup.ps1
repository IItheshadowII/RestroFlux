param(
  [string]$OutDir = "..\..\backups"
)

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptRoot '..\..')
$out = Join-Path $repoRoot $OutDir
New-Item -ItemType Directory -Force -Path $out | Out-Null
$envFile = Join-Path $repoRoot '.env.local'
$composeFile = Join-Path $repoRoot 'docker-compose.local.yml'

if (-not (Test-Path $envFile)) { Write-Host 'No se encontró .env.local. Abortando.' -ForegroundColor Red; exit 1 }

Write-Host "Realizando backup de la base de datos y uploads en: $out" -ForegroundColor Cyan

$timestamp = Get-Date -Format yyyyMMddHHmmss
$dumpFile = Join-Path $out "pg_backup_$timestamp.sql"

$postgresUser = 'restroflux'
$postgresDb = 'restroflux'
Get-Content $envFile | ForEach-Object {
  if ($_ -match '^POSTGRES_USER=(.+)$') { $postgresUser = $Matches[1] }
  if ($_ -match '^POSTGRES_DB=(.+)$') { $postgresDb = $Matches[1] }
}

Write-Host "Dumping Postgres a $dumpFile" -ForegroundColor Cyan
& docker compose --env-file "$envFile" -f "$composeFile" exec -T restroflux-postgres pg_dump -U $postgresUser $postgresDb > $dumpFile

# Comprimir uploads
$uploadsDir = Join-Path $repoRoot 'local-data\uploads'
if (Test-Path $uploadsDir) {
  $zipFile = Join-Path $out "uploads_$timestamp.zip"
  Write-Host "Comprimiendo uploads a $zipFile" -ForegroundColor Cyan
  Compress-Archive -Path (Join-Path $uploadsDir '*') -DestinationPath $zipFile -Force
}

$minioDir = Join-Path $repoRoot 'local-data\minio'
if (Test-Path $minioDir) {
  $zipFile = Join-Path $out "minio_$timestamp.zip"
  Write-Host "Comprimiendo MinIO a $zipFile" -ForegroundColor Cyan
  Compress-Archive -Path (Join-Path $minioDir '*') -DestinationPath $zipFile -Force
}

Write-Host "Backup completado." -ForegroundColor Green
exit 0

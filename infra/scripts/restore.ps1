param(
  [string]$BackupSql,
  [string]$UploadsZip,
  [string]$MinioZip
)

if (-not $BackupSql) { Write-Host "Especifique la ruta al backup SQL (param BackupSql)." -ForegroundColor Red; exit 1 }

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptRoot '..\..')
$envFile = Join-Path $repoRoot '.env.local'
$composeFile = Join-Path $repoRoot 'docker-compose.local.yml'

if (-not (Test-Path $envFile)) { Write-Host 'No se encontró .env.local. Abortando.' -ForegroundColor Red; exit 1 }

$postgresUser = 'restroflux'
$postgresDb = 'restroflux'
Get-Content $envFile | ForEach-Object {
  if ($_ -match '^POSTGRES_USER=(.+)$') { $postgresUser = $Matches[1] }
  if ($_ -match '^POSTGRES_DB=(.+)$') { $postgresDb = $Matches[1] }
}

Write-Host "Restaurando $BackupSql en la base de datos..." -ForegroundColor Cyan
Get-Content "$BackupSql" | & docker compose --env-file "$envFile" -f "$composeFile" exec -T restroflux-postgres psql -U $postgresUser -d $postgresDb

if ($UploadsZip) {
  $uploadsDir = Join-Path $repoRoot 'local-data\uploads'
  Write-Host "Restaurando uploads desde $UploadsZip a $uploadsDir" -ForegroundColor Cyan
  if (-not (Test-Path $uploadsDir)) { New-Item -ItemType Directory -Force -Path $uploadsDir | Out-Null }
  Expand-Archive -Path $UploadsZip -DestinationPath $uploadsDir -Force
}

if ($MinioZip) {
  $minioDir = Join-Path $repoRoot 'local-data\minio'
  Write-Host "Restaurando MinIO desde $MinioZip a $minioDir" -ForegroundColor Cyan
  if (-not (Test-Path $minioDir)) { New-Item -ItemType Directory -Force -Path $minioDir | Out-Null }
  Expand-Archive -Path $MinioZip -DestinationPath $minioDir -Force
}

Write-Host "Restore completado." -ForegroundColor Green
exit 0

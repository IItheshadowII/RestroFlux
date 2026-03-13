param()

$rootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$envFile = Join-Path $rootDir '.env.local'
$exampleFile = Join-Path $rootDir '.env.example'
$composeFile = Join-Path $rootDir 'docker-compose.local.yml'

function Fail($message) {
  Write-Host $message -ForegroundColor Red
  exit 1
}

try {
  & docker version *> $null
} catch {
  Fail 'Docker no está instalado o no responde. Instala Docker Desktop o Docker Engine antes de continuar.'
}

try {
  & docker compose version *> $null
} catch {
  Fail "Docker Compose no está disponible. Usa una versión que soporte 'docker compose'."
}

New-Item -ItemType Directory -Force -Path (Join-Path $rootDir 'local-data\postgres') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $rootDir 'local-data\minio') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $rootDir 'local-data\uploads') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $rootDir 'backups') | Out-Null

if (-not (Test-Path $envFile)) {
  Copy-Item $exampleFile $envFile -Force
  Write-Host "Se creó $envFile desde .env.example. Revisa los valores antes de pasar a producción." -ForegroundColor Yellow
}

$appPort = '3000'
$minioConsolePort = '9001'
Get-Content $envFile | ForEach-Object {
  if ($_ -match '^APP_HTTP_PORT=(.+)$') { $appPort = $Matches[1] }
  if ($_ -match '^MINIO_CONSOLE_PORT=(.+)$') { $minioConsolePort = $Matches[1] }
}

Write-Host 'Descargando imágenes...' -ForegroundColor Cyan
& docker compose --env-file "$envFile" -f "$composeFile" pull
if ($LASTEXITCODE -ne 0) { Fail 'Falló la descarga de imágenes.' }

Write-Host 'Levantando RestroFlux en modo local...' -ForegroundColor Cyan
& docker compose --env-file "$envFile" -f "$composeFile" up -d
if ($LASTEXITCODE -ne 0) { Fail 'Falló el arranque de RestroFlux.' }

Write-Host ''
Write-Host 'RestroFlux quedó instalado.' -ForegroundColor Green
Write-Host "Aplicación: http://localhost:$appPort" -ForegroundColor Green
Write-Host "Consola MinIO: http://127.0.0.1:$minioConsolePort" -ForegroundColor Green
Write-Host "Variables locales: $envFile" -ForegroundColor Green
Write-Host "Datos persistentes: $(Join-Path $rootDir 'local-data')" -ForegroundColor Green
Write-Host "Backups recomendados: $(Join-Path $rootDir 'backups')" -ForegroundColor Green
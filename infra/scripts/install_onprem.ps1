param(
  [string]$LicenseKey = '',
  [string]$InstanceId = 'local-instance',
  [switch]$UseHostPostgres = $false
)

# Installer on‑premise básico para Windows (PowerShell)
# Requisitos: Docker Desktop instalado y en ejecución.

function Ensure-RunAsAdmin {
  $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) {
    Write-Host "Se requieren privilegios de administrador. Reinicia PowerShell como Administrador." -ForegroundColor Yellow
    exit 1
  }
}

function Check-Command($cmd, $name) {
  try {
    & $cmd --version > $null 2>&1
    return $true
  } catch {
    Write-Host "$name no encontrado. Por favor instala $name y vuelve a ejecutar." -ForegroundColor Red
    return $false
  }
}

Ensure-RunAsAdmin

if (-not (Check-Command "docker" "Docker")) { exit 1 }
if (-not (Check-Command "docker" "Docker Compose")) { Write-Host "Comprueba que Docker Compose está disponible (docker compose)." -ForegroundColor Yellow }

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptRoot '..\..')

Write-Host "Repo raíz: $repoRoot"

# Preparar .env.onprem
$envExample = Join-Path $repoRoot 'infra\.env.onprem.example'
$envFile = Join-Path $repoRoot 'infra\.env.onprem'
if (-not (Test-Path $envFile)) {
  Copy-Item $envExample $envFile -Force
  Write-Host "Se creó infra\.env.onprem desde el ejemplo. Edita el archivo si necesitas ajustar valores." -ForegroundColor Green
}

if ($LicenseKey -ne '') {
  (Get-Content $envFile) -replace 'VITE_LICENSE_KEY=.*', "VITE_LICENSE_KEY=$LicenseKey" | Set-Content $envFile
  (Get-Content $envFile) -replace 'VITE_INSTANCE_ID=.*', "VITE_INSTANCE_ID=$InstanceId" | Set-Content $envFile
  Write-Host "License key escrita en infra\.env.onprem" -ForegroundColor Green
}

# Crear carpetas de datos
$dataUploads = Join-Path $repoRoot 'infra\data\uploads'
$pgdata = Join-Path $repoRoot 'infra\data\pgdata'
$miniodata = Join-Path $repoRoot 'infra\data\miniodata'
New-Item -ItemType Directory -Force -Path $dataUploads | Out-Null
New-Item -ItemType Directory -Force -Path $pgdata | Out-Null
New-Item -ItemType Directory -Force -Path $miniodata | Out-Null

Write-Host "Directorios de datos preparados." -ForegroundColor Cyan

# Levantar stack con docker compose
$compose1 = Join-Path $repoRoot 'docker-compose.yml'
$compose2 = Join-Path $repoRoot 'infra\docker-compose.onprem.yml'

Write-Host "Levantando contenedores con docker compose..." -ForegroundColor Cyan
Push-Location $repoRoot
try {
  & docker compose -f "$compose1" -f "$compose2" up -d --build
} catch {
  Write-Host "Error ejecutando docker compose: $_" -ForegroundColor Red
  Pop-Location
  exit 1
}
Pop-Location

# Esperar a Postgres
Write-Host "Esperando a que Postgres esté listo..." -ForegroundColor Cyan
Start-Sleep -Seconds 3
$pgContainer = & docker ps -qf "ancestor=postgres:15" | Select-Object -First 1
if (-not $pgContainer) { $pgContainer = & docker ps -qf "ancestor=postgres:15-alpine" | Select-Object -First 1 }
if (-not $pgContainer) { Write-Host "No se encontró contenedor Postgres basado en imagen postgres:15. Revisa 'docker ps'." -ForegroundColor Yellow }
else {
  $tries = 0
  while ($tries -lt 60) {
    $res = & docker exec $pgContainer pg_isready -U gastroflow 2>$null
    if ($LASTEXITCODE -eq 0) { break }
    Start-Sleep -Seconds 2
    $tries++
  }
  if ($tries -ge 60) { Write-Host "Postgres no respondió a tiempo." -ForegroundColor Red }
  else { Write-Host "Postgres listo." -ForegroundColor Green }

  # Ejecutar migraciones si existe db/init.sql
  $initSql = Join-Path $repoRoot 'db\init.sql'
  if (Test-Path $initSql) {
    Write-Host "Aplicando migraciones desde db/init.sql..." -ForegroundColor Cyan
    try {
      & docker cp "$initSql" "$pgContainer:/tmp/init.sql"
      & docker exec -i $pgContainer psql -U gastroflow -d gastroflow -f /tmp/init.sql
      Write-Host "Migraciones aplicadas." -ForegroundColor Green
    } catch {
      Write-Host "Error aplicando migraciones: $_" -ForegroundColor Yellow
    }
  }
}

Write-Host "Instalación finalizada. Revisa logs con: docker compose -f $compose1 -f $compose2 logs -f app" -ForegroundColor Green
Write-Host "Puedes ver estado de licencia desde la UI o forzar activación contra tu servidor central." -ForegroundColor Cyan

exit 0

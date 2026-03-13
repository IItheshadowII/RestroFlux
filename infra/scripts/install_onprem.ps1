param(
  [string]$LicenseKey = '',
  [string]$InstanceId = 'local-instance',
  [switch]$UseHostPostgres = $false
)

# Wrapper legacy.
# Reenvía al instalador actual de raíz y mantiene la opción de grabar licencia/instance id.

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptRoot '..\..')
$envFile = Join-Path $repoRoot '.env.local'
$envExample = Join-Path $repoRoot '.env.example'
$installer = Join-Path $repoRoot 'install-local.ps1'

if (-not (Test-Path $envFile)) {
  Copy-Item $envExample $envFile -Force
}

if ($LicenseKey -ne '') {
  (Get-Content $envFile) -replace '^VITE_LICENSE_KEY=.*', "VITE_LICENSE_KEY=$LicenseKey" | Set-Content $envFile
  (Get-Content $envFile) -replace '^VITE_INSTANCE_ID=.*', "VITE_INSTANCE_ID=$InstanceId" | Set-Content $envFile
  Write-Host "License key escrita en .env.local" -ForegroundColor Green
}

Write-Host 'El instalador infra/scripts/install_onprem.ps1 quedó como wrapper legacy.' -ForegroundColor Yellow
Write-Host 'Se ejecutará el instalador actual de raíz (install-local.ps1).' -ForegroundColor Yellow

& powershell -ExecutionPolicy Bypass -File "$installer"
exit $LASTEXITCODE

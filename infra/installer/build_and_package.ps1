param(
  [string]$OutputExe = "gastroflow-installer.exe",
  [string]$ZipOut = "..\gastroflow-installer-windows.zip",
  [string]$Readme = "..\README_INSTALLER.md"
)

function Check-Command($name, $cmd) {
  try { & $cmd --version > $null 2>&1; return $true } catch { Write-Host "$name no encontrado: $cmd" -ForegroundColor Red; return $false }
}

if (-not (Check-Command "Go" "go")) { Write-Host "Instala Go y vuelve a ejecutar."; exit 1 }

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $scriptRoot

Write-Host "Compilando instalador para Windows (amd64)..." -ForegroundColor Cyan
$env:GOOS = "windows"
$env:GOARCH = "amd64"

# main.go está en el mismo directorio del script
$build = & go build -o $OutputExe main.go
if ($LASTEXITCODE -ne 0) { Write-Host "Error en go build" -ForegroundColor Red; Pop-Location; exit 1 }

Write-Host "Creando ZIP: $ZipOut" -ForegroundColor Cyan
if (Test-Path $ZipOut) { Remove-Item $ZipOut -Force }
Compress-Archive -Path $OutputExe, $Readme -DestinationPath $ZipOut -Force

Write-Host "Empaquetado completado: $ZipOut" -ForegroundColor Green
Pop-Location
exit 0

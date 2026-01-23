Compilar y empaquetar el instalador (Windows)

Requisitos:
- Go 1.20+ instalado y en PATH
- PowerShell (Windows)

Pasos (desde la máquina donde vayas a compilar):

1. Abrir PowerShell en `e:\gastroflow-saas-pro\infra\installer`

2. Ejecutar el script de build:

```powershell
# compila y genera gastroflow-installer.exe y crea infra\gastroflow-installer-windows.zip
powershell -ExecutionPolicy Bypass -File .\build_and_package.ps1
```

3. El ZIP contiene:
- `gastroflow-installer.exe` — ejecutable instalador
- `README_INSTALLER.md` — instrucciones para el cliente

Notas:
- Alternativa cross‑compile desde Linux/macOS con Go instalado:
  ```bash
  GOOS=windows GOARCH=amd64 go build -o gastroflow-installer.exe main.go
  ```
- El instalador requiere Docker Desktop en la máquina destino.

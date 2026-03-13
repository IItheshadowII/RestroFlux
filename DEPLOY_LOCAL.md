# RestroFlux - Deploy Local / On-Premise

## Objetivo

Este modo está pensado para clientes que instalan el sistema en su propio servidor Linux o Windows con Docker.

Características:

- no compila código en el cliente
- usa imagen publicada en GHCR
- variables editables sin tocar código
- datos persistentes en carpeta local clara
- operación simple para técnico

## Archivos usados

- [docker-compose.local.yml](docker-compose.local.yml)
- [install-local.sh](install-local.sh)
- [install-local.ps1](install-local.ps1)
- [.env.example](.env.example)

## Estructura local recomendada

La instalación usa estas rutas dentro de la carpeta del proyecto:

- `./.env.local`
- `./local-data/postgres`
- `./local-data/minio`
- `./local-data/uploads`
- `./backups`

## Instalación en Linux

1. Copia el paquete/proyecto al servidor.
2. Ejecuta:

```bash
chmod +x ./install-local.sh
./install-local.sh
```

3. Revisa `./.env.local` y ajusta contraseñas, dominio o SMTP si hace falta.
4. Si cambias variables sensibles, vuelve a ejecutar:

```bash
docker compose --env-file .env.local -f docker-compose.local.yml up -d
```

## Instalación en Windows

1. Copia el paquete/proyecto al servidor o PC del cliente.
2. Abre PowerShell.
3. Ejecuta:

```powershell
powershell -ExecutionPolicy Bypass -File .\install-local.ps1
```

4. Revisa `./.env.local` y ajusta valores reales.

## Operación diaria

Iniciar o recrear servicios:

```bash
docker compose --env-file .env.local -f docker-compose.local.yml up -d
```

Detener servicios:

```bash
docker compose --env-file .env.local -f docker-compose.local.yml down
```

Ver logs:

```bash
docker compose --env-file .env.local -f docker-compose.local.yml logs -f restroflux-app
```

## Variables importantes

- `PUBLIC_BASE_URL`: para instalación local simple puede ser `http://localhost:3000`
- `JWT_SECRET`: obligatorio
- `DB_PASSWORD` y `POSTGRES_PASSWORD`: obligatorios
- `SMTP_*`: opcional
- `GEMINI_API_KEY`: opcional

## Dependencia de GitHub

La operación diaria no depende de GitHub.

- El sistema sigue funcionando aunque GitHub no esté disponible.
- GitHub/GHCR solo se necesita para descargar la imagen en la primera instalación o en futuras actualizaciones.
- Si necesitas operar 100% offline, puedes exportar la imagen a tar y llevarla al servidor del cliente como paso adicional.

## Migrar a otro servidor

Para mover una instalación:

1. Copia `./.env.local`.
2. Copia `./local-data`.
3. Copia los backups de `./backups` si existen.
4. Instala Docker en el nuevo servidor.
5. Levanta con [docker-compose.local.yml](docker-compose.local.yml).

Más detalle en [BACKUP.md](BACKUP.md) y [UPDATE.md](UPDATE.md).
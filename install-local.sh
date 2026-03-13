#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ENV_FILE="$ROOT_DIR/.env.local"
EXAMPLE_FILE="$ROOT_DIR/.env.example"
COMPOSE_FILE="$ROOT_DIR/docker-compose.local.yml"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker no está instalado o no está en PATH."
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose no está disponible. Usa Docker Engine / Docker Desktop con 'docker compose'."
  exit 1
fi

mkdir -p "$ROOT_DIR/local-data/postgres" "$ROOT_DIR/local-data/minio" "$ROOT_DIR/local-data/uploads" "$ROOT_DIR/backups"

if [ ! -f "$ENV_FILE" ]; then
  cp "$EXAMPLE_FILE" "$ENV_FILE"
  echo "Se creó $ENV_FILE desde .env.example. Revisa los valores antes de pasar a producción."
fi

APP_PORT=$(grep '^APP_HTTP_PORT=' "$ENV_FILE" 2>/dev/null | tail -n 1 | cut -d '=' -f 2-)
MINIO_CONSOLE_PORT=$(grep '^MINIO_CONSOLE_PORT=' "$ENV_FILE" 2>/dev/null | tail -n 1 | cut -d '=' -f 2-)
[ -n "$APP_PORT" ] || APP_PORT=3000
[ -n "$MINIO_CONSOLE_PORT" ] || MINIO_CONSOLE_PORT=9001

echo "Descargando imágenes..."
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" pull

echo "Levantando RestroFlux en modo local..."
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d

echo
echo "RestroFlux quedó instalado."
echo "Aplicación: http://localhost:$APP_PORT"
echo "Consola MinIO: http://127.0.0.1:$MINIO_CONSOLE_PORT"
echo "Variables locales: $ENV_FILE"
echo "Datos persistentes: $ROOT_DIR/local-data"
echo "Backups recomendados: $ROOT_DIR/backups"
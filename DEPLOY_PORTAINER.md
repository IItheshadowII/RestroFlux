# RestroFlux - Nota de compatibilidad Portainer

La documentación principal de despliegue cloud ahora está en [DEPLOY_CLOUD.md](DEPLOY_CLOUD.md).

Resumen rápido:

1. Usa [docker-compose.cloud.yml](docker-compose.cloud.yml) o [docker-compose.yml](docker-compose.yml) como alias de compatibilidad.
2. La app se descarga desde GHCR, no desde una imagen local.
3. PostgreSQL y MinIO quedan internos al stack por defecto.
4. Los secretos y dominios se cargan como variables externas.
5. Si usas Docker Swarm, puedes usar [stack.yml](stack.yml).

# ====================================
# RestoFlux SaaS - Dockerfile
# Para despliegue en EasyPanel
# BUILD: 2026-01-23 v2.1.1
# ====================================

# Etapa 1: Build del Frontend
FROM node:20-alpine AS builder

WORKDIR /app

# Copiar archivos de dependencias
COPY package.json package-lock.json* ./

# Instalar TODAS las dependencias (incluyendo devDependencies para build)
RUN npm ci

# Copiar el código fuente
COPY . .

# Build args no sensibles para que Portainer Repository pueda construir
# sin depender de un .env real versionado.
ARG VITE_APP_MODE=CLOUD
ARG VITE_API_URL=/api
ARG VITE_CLOUD_URL=https://app.restroflux.example.com
ARG VITE_LICENSE_KEY=
ARG VITE_INSTANCE_ID=
ARG VITE_LICENSE_CHECK_INTERVAL_DAYS=1
ARG VITE_LICENSE_GRACE_DAYS=7

ENV VITE_APP_MODE=$VITE_APP_MODE
ENV VITE_API_URL=$VITE_API_URL
ENV VITE_CLOUD_URL=$VITE_CLOUD_URL
ENV VITE_LICENSE_KEY=$VITE_LICENSE_KEY
ENV VITE_INSTANCE_ID=$VITE_INSTANCE_ID
ENV VITE_LICENSE_CHECK_INTERVAL_DAYS=$VITE_LICENSE_CHECK_INTERVAL_DAYS
ENV VITE_LICENSE_GRACE_DAYS=$VITE_LICENSE_GRACE_DAYS

# Construir el frontend (Vite)
RUN npm run build

# ====================================
# Etapa 2: Producción
# ====================================
FROM node:20-alpine AS production

WORKDIR /app

# Copiar package.json y lock
COPY package.json package-lock.json* ./

# Instalar solo dependencias de producción
RUN npm ci --only=production

# Copiar el servidor Node.js
COPY server.js ./

# Copiar el build del frontend desde la etapa anterior
COPY --from=builder /app/dist ./dist

# Puerto expuesto (EasyPanel lo detecta)
EXPOSE 3000

# Variables de entorno por defecto
ENV NODE_ENV=production
ENV PORT=3000

# Comando de inicio
CMD ["node", "server.js"]

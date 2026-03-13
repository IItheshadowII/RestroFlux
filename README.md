<div align="center">
   <h1>RestroFlux</h1>
   <p>Panel de control multi-tenant para restaurantes, con backend Node.js + PostgreSQL e IA (Gemini).</p>
</div>

---

## Descripción

RestroFlux es una aplicación multi-tenant para la gestión integral de restaurantes, bares y negocios gastronómicos.

El proyecto queda preparado con dos modos de despliegue operativos:

- Cloud / Demo: imagen publicada en GHCR, lista para Portainer y Docker Swarm.
- Local / On-Premise: instalación simple con Docker Compose y variables editables, pensada para servidor de cliente.

Capacidades principales:

- Plano de mesas, cuentas abiertas y cobros.
- Pantalla de cocina en tiempo real (Socket.IO).
- Catálogo y stock de productos.
- Caja, turnos y reportes.
- Gestión de usuarios, roles y permisos (RBAC).
- Módulo de facturación y suscripciones (Mercado Pago).
- Panel de Admin Global para gestión de tenants e IA (Gemini).

El frontend está hecho en React + Vite y el backend en Node.js/Express con PostgreSQL, empaquetados en el mismo repositorio.

## Estructura de despliegue

- [docker-compose.cloud.yml](docker-compose.cloud.yml): despliegue cloud/demo con imagen publicada.
- [docker-compose.local.yml](docker-compose.local.yml): instalación local/on-premise para cliente.
- [docker-compose.yml](docker-compose.yml): alias de compatibilidad del modo cloud.
- [stack.yml](stack.yml): variante para stack Swarm.
- [install-local.sh](install-local.sh): instalador Linux para cliente/técnico.
- [install-local.ps1](install-local.ps1): instalador Windows para cliente/técnico.
- [.env.example](.env.example): plantilla única de variables.

## Arquitectura

- Frontend SPA en React (Vite) — ver `App.tsx`, carpeta `pages/`, `components/`.
- Backend REST + WebSockets en Node.js/Express — ver `server.js`.
- Base de datos PostgreSQL — esquema detallado en `PRODUCTION_GUIDE.md`.
- Realtime con Socket.IO — servidor en `server.js`, cliente en `services/realtime.ts`.
- Servicio de datos híbrido — `services/db.ts` permite modo **LOCAL** (localStorage) o **CLOUD** (API) según variables Vite.

Para una guía más profunda de despliegue y migración a producción, consulta `PRODUCTION_GUIDE.md`.

## Requisitos

- Node.js 18 o superior.
- PostgreSQL 15+ (o compatible).
- npm (o pnpm/yarn si lo adaptas).

Opcional (para funcionalidades completas):

- Cuenta de Mercado Pago con token productivo.
- Servidor SMTP para recuperación de contraseña y notificaciones.

## Variables de entorno

### Backend

Las principales variables usadas por `server.js` son:

- `PORT` — Puerto HTTP (por defecto `3000`).
- `DATABASE_URL` — Cadena de conexión PostgreSQL.
- `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD` — alternativa a `DATABASE_URL` para despliegues Docker/Portainer.
- `DATABASE_SSL`, `DATABASE_SSL_REJECT_UNAUTHORIZED` — control explícito de SSL para PostgreSQL.
- `JWT_SECRET` — Clave para firmar JWT.
- `MP_ACCESS_TOKEN` — Token de acceso de Mercado Pago.
- `PUBLIC_BASE_URL` — URL pública base para generar links (reset de password, etc.).
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM` — SMTP para emails.
- `GLOBAL_ADMIN_BOOTSTRAP_TOKEN` — Token para bootstrap de admin global.

Más detalles y notas de producción en `PRODUCTION_GUIDE.md`.

### Frontend (Vite `VITE_*`)

Las variables leídas en `services/db.ts` son:

- `VITE_APP_MODE` — `LOCAL` o `CLOUD` (por defecto `LOCAL` si no se define y no hay `VITE_API_URL`).
- `VITE_API_URL` — URL base del backend en modo CLOUD (por ejemplo `https://api.tudominio.com`).
- `VITE_CLOUD_URL` — URL de la nube central (licencias on-premise).
- `VITE_LICENSE_KEY`, `VITE_INSTANCE_ID`, `VITE_LICENSE_CHECK_INTERVAL_DAYS`, `VITE_LICENSE_GRACE_DAYS` — gestión de licencias en instalaciones on-premise.

La imagen publicada en GHCR ya sale compilada en modo API (`VITE_APP_MODE=CLOUD`, `VITE_API_URL=/api`). Para despliegues normales cloud y local no hace falta recompilar frontend en cliente.

## Desarrollo

1. Instalar dependencias:

   ```bash
   npm install
   ```

2. Levantar PostgreSQL (puedes usar el compose que prefieras o una base existente):

   ```bash
   docker compose up -d postgres
   ```

3. Crear base y aplicar migraciones iniciales

   Revisa la carpeta `db/` y `PRODUCTION_GUIDE.md` para el esquema. En un entorno local simple basta con ejecutar los scripts SQL necesarios sobre la DB apuntada por `DATABASE_URL`.

4. Configurar variables del backend (mínimo):

   ```env
   DATABASE_URL=postgresql://restroflux:tu_password@localhost:5432/restroflux
   JWT_SECRET=dev_secret_key
   ```

5. Iniciar backend:

   ```bash
   npm start
   ```

   Esto levanta `server.js` en el puerto definido por `PORT` (3000 por defecto) y sirve tanto la API como los archivos estáticos del build.

6. Para desarrollo de frontend con HMR, en otra terminal puedes usar:

   ```bash
   npm run dev
   ```

   En este flujo el backend y Vite corren por separado; ajusta `VITE_API_URL` para que el frontend apunte al backend correcto.

## Build y despliegue

1. Build de frontend + TypeScript:

   ```bash
   npm run build
   ```

   Esto ejecuta `tsc` y luego `vite build`, generando el artefacto estático en `dist/`.

2. Iniciar servidor en modo producción:

   ```bash
   npm start
   ```

   `server.js` sirve el contenido de `dist/` y expone la API REST y Socket.IO en el mismo puerto.

## Despliegue

### Cloud / Demo

Usa [DEPLOY_CLOUD.md](DEPLOY_CLOUD.md).

### Local / On-Premise

Usa [DEPLOY_LOCAL.md](DEPLOY_LOCAL.md).

### Backup y actualización

- [BACKUP.md](BACKUP.md)
- [UPDATE.md](UPDATE.md)

## Modo CLOUD vs LOCAL

En el producto desplegado, tanto cloud como on-premise usan backend + PostgreSQL.

- `APP_MODE=CLOUD` o `APP_MODE=LOCAL` identifica el tipo de despliegue.
- El frontend productivo se ejecuta en modo API (`VITE_APP_MODE=CLOUD`) para ambos escenarios.
- El modo `VITE_APP_MODE=LOCAL` queda como capacidad legacy/dev basada en localStorage, no como despliegue recomendado para clientes.

El archivo `services/db.ts` actúa como **adaptador de datos**:

- En **modo LOCAL** (por defecto), persiste en `localStorage` y simula toda la lógica de negocio en el cliente.
- En **modo CLOUD**, habla con el backend mediante HTTP (`VITE_API_URL`, por defecto `/api` en despliegues Docker), manteniendo la misma interfaz que usa el frontend.

Gracias a este diseño, para pasar de MVP local a SaaS en producción no es necesario reescribir la UI; basta con implementar los endpoints equivalentes en el backend y configurar las variables de entorno adecuadas (ver `PRODUCTION_GUIDE.md`).

## IA (Gemini)

La integración con IA (Gemini) se realiza desde el backend (`server.js`) utilizando `@google/genai`. La configuración (API key, modelos, límites) se gestiona desde el panel de **Admin Global** (`/admin`, botón **IA**) y se guarda en la base de datos. La clave nunca se expone al frontend.

## Recursos adicionales

- Guía de migración y arquitectura de producción: `PRODUCTION_GUIDE.md`.
- Infraestructura legacy/on-premise y empaquetado: carpeta `infra/`.
- Scripts de base de datos y migraciones: carpeta `db/`.
- Despliegue cloud: [DEPLOY_CLOUD.md](DEPLOY_CLOUD.md).
- Despliegue local: [DEPLOY_LOCAL.md](DEPLOY_LOCAL.md).
- Backup: [BACKUP.md](BACKUP.md).
- Update: [UPDATE.md](UPDATE.md).


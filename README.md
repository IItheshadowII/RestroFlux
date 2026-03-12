<div align="center">
   <h1>RestoFlux SaaS</h1>
   <p>Panel de control multi-tenant para restaurantes, con backend Node.js + PostgreSQL e IA (Gemini).</p>
</div>

---

## Descripción

RestoFlux es una aplicación SaaS multi-tenant para la gestión integral de restaurantes:

- Plano de mesas, cuentas abiertas y cobros.
- Pantalla de cocina en tiempo real (Socket.IO).
- Catálogo y stock de productos.
- Caja, turnos y reportes.
- Gestión de usuarios, roles y permisos (RBAC).
- Módulo de facturación y suscripciones (Mercado Pago).
- Panel de Admin Global para gestión de tenants e IA (Gemini).

El frontend está hecho en React + Vite y el backend en Node.js/Express con PostgreSQL, empaquetados en el mismo repositorio.

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

En Docker/Portainer, las variables `VITE_*` se pasan como build args. El repo ya no depende de un `.env` real para desplegar.

## Ejecutar en desarrollo (local)

1. Instalar dependencias:

   ```bash
   npm install
   ```

2. Levantar PostgreSQL (puedes usar el `docker-compose.yml` incluido):

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

3. Alternativamente, puedes usar Docker Compose (app + Postgres + MinIO):

   ```bash
   docker compose up -d
   ```

   El compose raíz ya no usa `env_file`. Para Portainer Repository, carga las variables en la UI usando [.env.example](.env.example) como referencia. Para Swarm usa [stack.yml](stack.yml) con una imagen ya publicada.

## Modo CLOUD vs LOCAL

El archivo `services/db.ts` actúa como **adaptador de datos**:

- En **modo LOCAL** (por defecto), persiste en `localStorage` y simula toda la lógica de negocio en el cliente.
- En **modo CLOUD**, habla con el backend mediante HTTP (`VITE_API_URL`, por defecto `/api` en despliegues Docker), manteniendo la misma interfaz que usa el frontend.

Gracias a este diseño, para pasar de MVP local a SaaS en producción no es necesario reescribir la UI; basta con implementar los endpoints equivalentes en el backend y configurar las variables de entorno adecuadas (ver `PRODUCTION_GUIDE.md`).

## IA (Gemini)

La integración con IA (Gemini) se realiza desde el backend (`server.js`) utilizando `@google/genai`. La configuración (API key, modelos, límites) se gestiona desde el panel de **Admin Global** (`/admin`, botón **IA**) y se guarda en la base de datos. La clave nunca se expone al frontend.

## Recursos adicionales

- Guía de migración y arquitectura de producción: `PRODUCTION_GUIDE.md`.
- Infraestructura on-premise y empaquetado: carpeta `infra/`.
- Scripts de base de datos y migraciones: carpeta `db/`.
- Despliegue Portainer/Swarm: [DEPLOY_PORTAINER.md](DEPLOY_PORTAINER.md).



# GastroFlow Infrastructure & Deployment

## 1. Local Infrastructure (Docker Compose)

Create a `docker-compose.yml` in the project root:

```yaml
version: '3.8'
services:
  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: gastroflow
      POSTGRES_USER: admin
      POSTGRES_PASSWORD: password123
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data

  backend:
    build: ./backend
    environment:
      DATABASE_URL: postgresql://admin:password123@db:5432/gastroflow
      JWT_SECRET: your_ultra_secret_key
      MP_ACCESS_TOKEN: your_mercadopago_token
    ports:
      - "4000:4000"
    depends_on:
      - db

  frontend:
    build: .
    ports:
      - "3000:3000"
    environment:
      VITE_API_URL: http://localhost:4000
```

## 2. Cloud Deployment (Google Cloud Run / Railway)

### Backend
1. Containerize the Express/Node app using a `Dockerfile`.
2. Deploy to Cloud Run:
   ```bash
   gcloud run deploy gastroflow-api --image gcr.io/project/api --platform managed
   ```
3. Set Env Vars: `DATABASE_URL`, `JWT_SECRET`, `MP_WEBHOOK_SECRET`.

### Database
- Use **Managed PostgreSQL** (Cloud SQL or Railway DB).
- Run migrations: `npx prisma migrate deploy`.

### Mercado Pago Webhooks
1. Configure your endpoint in MP Dashboard: `https://api.gastroflow.com/v1/webhooks/mercadopago`.
2. Secure the endpoint verifying the IP and token.

## 3. RBAC & Multi-tenant isolation
The system enforces `tenant_id` at the Prisma level using a middleware or by always including it in queries:
`prisma.product.findMany({ where: { tenantId: currentUser.tenantId } })`.

## 4. On‑Premise Deployment (recommended flow)

Use the provided `infra/docker-compose.onprem.yml` together with a `.env.onprem` file.

Quick steps:

1. Copiar el ejemplo y editar valores:

```powershell
cd infra
cp .env.onprem.example .env.onprem
# Editar .env.onprem con tus credenciales locales
```

2. Levantar la stack on‑premise (misma imagen/artifact que en cloud):

```bash
# Desde la carpeta raiz o infra
docker compose -f docker-compose.yml -f infra/docker-compose.onprem.yml up -d --build
```

3. Migraciones y seeds (si aplica):

```bash
# Ejecutar migraciones contra la BBDD local
docker exec -i $(docker ps -qf "ancestor=postgres:15") psql -U gastroflow -d gastroflow -f db/init.sql
```

4. Activación de licencia (opcional):

Usa el endpoint central o provee la `VITE_LICENSE_KEY` en `.env.onprem`. También puedes activar manualmente via curl:

```bash
curl -X POST $VITE_CLOUD_URL/api/license/activate \
  -H "Content-Type: application/json" \
  -d '{"licenseKey":"GF-XXXX","instanceId":"mi-instancia-001"}'
```

Notas operativas:
- No expongas Postgres o MinIO públicamente; usa un reverse proxy (nginx/Caddy) para TLS.
- Mantén backups periódicos de la BBDD y del directorio `infra/data/uploads`.
- La app usa las mismas imágenes en cloud y on‑prem; el comportamiento se controla por env vars (`VITE_APP_MODE`, `VITE_API_URL`, `VITE_LICENSE_KEY`).



import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import pg from 'pg';
import cors from 'cors';
import dotenv from 'dotenv';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Database Connection
const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Mercado Pago Initialization
import { MercadoPagoConfig, PreApproval, Payment } from 'mercadopago';
const mpClient = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN || '' });
const preapproval = new PreApproval(mpClient);
const payment = new Payment(mpClient);

const MP_LOG_PREFIX = '[MP]';

const isUuid = (value) => {
  if (typeof value !== 'string') return false;
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
};

const safeJson = (value) => {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
};

const withQueryParams = (urlString, params) => {
  try {
    const url = new URL(urlString);
    Object.entries(params).forEach(([key, val]) => {
      if (val === undefined || val === null || val === '') return;
      url.searchParams.set(key, String(val));
    });
    return url.toString();
  } catch {
    // Fallback si viene una URL relativa o inválida
    const glue = urlString.includes('?') ? '&' : '?';
    const query = Object.entries(params)
      .filter(([, val]) => val !== undefined && val !== null && val !== '')
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
      .join('&');
    return query ? `${urlString}${glue}${query}` : urlString;
  }
};

const inferPlanIdFromReason = (reason) => {
  if (typeof reason !== 'string') return 'BASIC';
  const m = reason.match(/\b(BASIC|PRO|ENTERPRISE)\b/i);
  return m ? m[1].toUpperCase() : 'BASIC';
};

const verifyWebhookSignaturePlaceholder = (req) => {
  // TODO: Implementar verificación real de firma MercadoPago.
  // Requiere capturar rawBody (bodyParser raw) y validar header de firma.
  // Por ahora dejamos placeholder para no romper webhooks en producción.
  const secret = process.env.MP_WEBHOOK_SECRET;
  if (!secret) return { ok: true, reason: 'MP_WEBHOOK_SECRET no configurado (placeholder)' };
  return { ok: true, reason: 'Placeholder (TODO firma)' };
};

const extractWebhookTypeAndId = (req) => {
  const body = req.body || {};
  const query = req.query || {};

  const rawType = body.type || query.type || body.topic || query.topic;
  const type = typeof rawType === 'string' ? rawType : undefined;

  const id =
    body?.data?.id ||
    body?.id ||
    query.data_id ||
    query['data.id'] ||
    query.id;

  return {
    type: typeof type === 'string' ? type : undefined,
    id: typeof id === 'string' || typeof id === 'number' ? String(id) : undefined,
  };
};

const ensureSchema = async () => {
  const client = await pool.connect();
  try {
    await client.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp";');

    // Tenants: asegurar columnas necesarias
    await client.query(`
      ALTER TABLE tenants
        ADD COLUMN IF NOT EXISTS plan VARCHAR(50) DEFAULT 'BASIC',
        ADD COLUMN IF NOT EXISTS subscription_status VARCHAR(50) DEFAULT 'TRIAL',
        ADD COLUMN IF NOT EXISTS mercadopago_preapproval_id VARCHAR(255),
        ADD COLUMN IF NOT EXISTS next_billing_date TIMESTAMP;
    `);

    // Billing history: tabla + columnas requeridas
    await client.query(`
      CREATE TABLE IF NOT EXISTS billing_history (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
        amount DECIMAL(10,2) NOT NULL,
        currency VARCHAR(3) DEFAULT 'ARS',
        status VARCHAR(50) DEFAULT 'paid',
        payment_id VARCHAR(255),
        mp_subscription_id VARCHAR(255),
        created_at TIMESTAMP DEFAULT NOW(),
        description VARCHAR(255),
        invoice_url VARCHAR(500)
      );

      ALTER TABLE billing_history
        ADD COLUMN IF NOT EXISTS mp_subscription_id VARCHAR(255),
        ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW();

      CREATE INDEX IF NOT EXISTS idx_billing_tenant ON billing_history(tenant_id);
      CREATE INDEX IF NOT EXISTS idx_billing_date ON billing_history(created_at DESC);
      CREATE UNIQUE INDEX IF NOT EXISTS ux_billing_mp_subscription_id ON billing_history(mp_subscription_id);
    `);

    console.log('✅ DB schema verificado (tenants + billing_history)');
  } finally {
    client.release();
  }
};

const ensureTenantExists = async (tenantId) => {
  // En este repo el frontend puede ser demo/localStorage; garantizamos que exista el tenant
  // para que los updates del webhook/refresh no queden sin efecto.
  await pool.query(
    `INSERT INTO tenants (id, name) VALUES ($1, $2)
     ON CONFLICT (id) DO NOTHING`,
    [tenantId, `Tenant ${tenantId}`]
  );
};

const syncTenantFromPreapproval = async (subscription) => {
  const status = subscription?.status;
  const tenantId = subscription?.external_reference;
  const preapprovalId = subscription?.id;
  const reason = subscription?.reason || '';
  const amount = subscription?.auto_recurring?.transaction_amount;
  const planId = inferPlanIdFromReason(reason);

  if (!isUuid(tenantId)) {
    console.warn(`${MP_LOG_PREFIX} external_reference inválido; no se puede sincronizar`, {
      external_reference: tenantId,
      status,
      preapprovalId,
      reason,
    });
    return null;
  }

  await ensureTenantExists(tenantId);

  if (status === 'authorized') {
    await pool.query(
      `UPDATE tenants SET
        plan = $1,
        subscription_status = 'ACTIVE',
        mercadopago_preapproval_id = $2,
        next_billing_date = NOW() + INTERVAL '1 month'
       WHERE id = $3`,
      [planId, preapprovalId, tenantId]
    );

    // Idempotencia: un registro por preapproval autorizado (MP reintenta webhooks)
    await pool.query(
      `INSERT INTO billing_history (tenant_id, amount, status, payment_id, mp_subscription_id, description, created_at)
       VALUES ($1, $2, 'paid', $3, $4, $5, NOW())
       ON CONFLICT (mp_subscription_id) DO NOTHING`,
      [tenantId, Number(amount ?? 0), null, preapprovalId, reason]
    );
  } else if (status === 'cancelled') {
    await pool.query(
      `UPDATE tenants SET
        subscription_status = 'CANCELED'
       WHERE id = $1`,
      [tenantId]
    );
  } else {
    console.log(`${MP_LOG_PREFIX} Evento ignorado por status`, { status, tenantId, preapprovalId });
  }

  const tenantResult = await pool.query(
    `SELECT id, name, slug, plan, subscription_status, mercadopago_preapproval_id, next_billing_date, created_at
     FROM tenants WHERE id = $1`,
    [tenantId]
  );
  return tenantResult.rows[0] || null;
};

// Test DB Connection & Ensure Schema
ensureSchema()
  .then(() => console.log('✅ Connected to PostgreSQL database'))
  .catch((err) => console.error('Error verifying DB schema:', err));

// --- VALID RESOURCES (Security) ---
const VALID_TABLES = ['tenants', 'users', 'roles', 'products', 'categories', 'tables', 'orders', 'order_items', 'shifts', 'audit_logs', 'billing_history'];

// Helper: Sanitize table name
const isValidTable = (table) => VALID_TABLES.includes(table);


// --- MERCADO PAGO ROUTES ---

app.post('/api/subscriptions', async (req, res) => {
  const { tenantId, planId, price, email, backUrl } = req.body;
  console.log('--- NEW SUBSCRIPTION REQUEST ---');
  console.log('Data:', { tenantId, planId, price, email, backUrl });

  try {
    if (!isUuid(tenantId)) {
      return res.status(400).json({ error: 'tenantId inválido (se requiere UUID)' });
    }
    if (!planId || typeof planId !== 'string') {
      return res.status(400).json({ error: 'planId requerido' });
    }
    if (typeof price !== 'number' || Number.isNaN(price) || price <= 0) {
      return res.status(400).json({ error: 'price inválido' });
    }
    if (!email || typeof email !== 'string') {
      return res.status(400).json({ error: 'email requerido' });
    }

    await ensureTenantExists(tenantId);

    const computedBackUrl = withQueryParams(
      backUrl || 'https://gastroflow.accesoit.com.ar/billing',
      { tenantId, mp: 1 }
    );

    const response = await preapproval.create({
      body: {
        reason: `Suscripción GastroFlow ${planId}`,
        auto_recurring: {
          frequency: 1,
          frequency_type: "months",
          transaction_amount: price,
          currency_id: "ARS"
        },
        back_url: computedBackUrl,
        payer_email: email,
        external_reference: tenantId, // IMPORTANTE: tenant UUID real
        status: "pending"
      }
    });

    res.json({ init_point: response.init_point, preapproval_id: response.id, id: response.id });
  } catch (error) {
    console.error('Error creating subscription:', error);
    res.status(500).json({ error: 'Failed to create subscription', details: error.message });
  }
});

app.post('/api/webhooks/mercadopago', async (req, res) => {
  const extracted = extractWebhookTypeAndId(req);
  const signatureCheck = verifyWebhookSignaturePlaceholder(req);

  console.log(`${MP_LOG_PREFIX} Webhook recibido`, {
    type: extracted.type,
    id: extracted.id,
    signature: signatureCheck.reason,
    query: req.query,
    body: req.body,
  });

  // Reglas: responder 200 siempre (evita reintentos infinitos), pero loguear problemas.
  if (!extracted.type || !extracted.id) {
    console.warn(`${MP_LOG_PREFIX} Webhook sin type/id. Se responde 200.`, {
      type: extracted.type,
      id: extracted.id,
      query: safeJson(req.query),
      body: safeJson(req.body),
    });
    return res.sendStatus(200);
  }

  const type = extracted.type;
  const id = extracted.id;

  try {
    if (type === 'subscription_preapproval' || type === 'preapproval') {
      const subscription = await preapproval.get({ id });
      await syncTenantFromPreapproval(subscription);
      return res.sendStatus(200);
    }

    if (type === 'payment') {
      const paymentData = await payment.get({ id });
      const preapprovalId = paymentData?.preapproval_id || paymentData?.metadata?.preapproval_id;

      if (!preapprovalId) {
        console.warn(`${MP_LOG_PREFIX} Payment sin preapproval_id; no se puede reconciliar`, {
          paymentId: id,
          paymentStatus: paymentData?.status,
        });
        return res.sendStatus(200);
      }

      const subscription = await preapproval.get({ id: String(preapprovalId) });
      await syncTenantFromPreapproval(subscription);
      return res.sendStatus(200);
    }

    console.log(`${MP_LOG_PREFIX} Webhook type no manejado`, { type, id });
    return res.sendStatus(200);
  } catch (error) {
    console.error(`${MP_LOG_PREFIX} Error en webhook (se responde 200 igualmente)`, error);
    return res.sendStatus(200);
  }
});

// Forzar sincronización al volver de MP
app.post('/api/subscriptions/refresh', async (req, res) => {
  const { tenantId, preapprovalId } = req.body || {};

  try {
    const resolvedTenantId = tenantId && typeof tenantId === 'string' ? tenantId : undefined;
    const resolvedPreapprovalId = preapprovalId && typeof preapprovalId === 'string' ? preapprovalId : undefined;

    if (!resolvedPreapprovalId && !resolvedTenantId) {
      return res.status(400).json({ error: 'Se requiere tenantId y/o preapprovalId' });
    }
    if (resolvedTenantId && !isUuid(resolvedTenantId)) {
      return res.status(400).json({ error: 'tenantId inválido (UUID requerido)' });
    }

    let finalPreapprovalId = resolvedPreapprovalId;
    if (!finalPreapprovalId && resolvedTenantId) {
      const r = await pool.query(
        `SELECT mercadopago_preapproval_id FROM tenants WHERE id = $1`,
        [resolvedTenantId]
      );
      finalPreapprovalId = r.rows[0]?.mercadopago_preapproval_id || undefined;
    }

    if (!finalPreapprovalId) {
      console.warn(`${MP_LOG_PREFIX} Refresh sin preapprovalId resoluble`, { tenantId: resolvedTenantId });
      const tenantRow = resolvedTenantId
        ? (await pool.query(
          `SELECT id, name, slug, plan, subscription_status, mercadopago_preapproval_id, next_billing_date, created_at
           FROM tenants WHERE id = $1`,
          [resolvedTenantId]
        )).rows[0]
        : null;
      return res.json({ ok: true, tenant: tenantRow });
    }

    const subscription = await preapproval.get({ id: String(finalPreapprovalId) });
    const tenantRow = await syncTenantFromPreapproval(subscription);
    return res.json({ ok: true, tenant: tenantRow });
  } catch (error) {
    console.error(`${MP_LOG_PREFIX} Error en refresh`, error);
    return res.status(500).json({ error: 'Refresh failed', details: error.message });
  }
});


// --- GENERIC API ROUTES (Backend for Frontend) ---

// Get All
app.get('/api/:resource', async (req, res) => {
  const { resource } = req.params;
  const { tenantId } = req.query;

  try {
    if (!isValidTable(resource)) return res.status(400).json({ error: 'Invalid resource' });

    let query = `SELECT * FROM ${resource}`;
    const params = [];

    // Multi-tenancy filter
    if (tenantId && resource !== 'tenants') {
      query += ` WHERE tenant_id = $1`;
      params.push(tenantId);
    }

    // Default sorting
    if (resource === 'orders' || resource === 'audit_logs') {
      query += params.length ? ` ORDER BY created_at DESC` : ` ORDER BY created_at DESC`;
    }

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Create
app.post('/api/:resource', async (req, res) => {
  const { resource } = req.params;
  const data = req.body;

  try {
    if (!isValidTable(resource)) return res.status(400).json({ error: 'Invalid resource' });

    const keys = Object.keys(data);
    const values = Object.values(data);
    const placeholders = keys.map((_, i) => `$${i + 1}`).join(', ');

    const query = `INSERT INTO ${resource} (${keys.join(', ')}) VALUES (${placeholders}) RETURNING *`;
    const result = await pool.query(query, values);

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Update
app.put('/api/:resource/:id', async (req, res) => {
  const { resource, id } = req.params;
  const data = req.body;

  try {
    if (!isValidTable(resource)) return res.status(400).json({ error: 'Invalid resource' });

    const updates = Object.keys(data).map((key, i) => `${key} = $${i + 2}`).join(', ');
    const values = [id, ...Object.values(data)];

    const query = `UPDATE ${resource} SET ${updates} WHERE id = $1 RETURNING *`;
    const result = await pool.query(query, values);

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Delete with Business Logic Validation
app.delete('/api/:resource/:id', async (req, res) => {
  const { resource, id } = req.params;
  const { tenantId } = req.query;

  try {
    if (!isValidTable(resource)) return res.status(400).json({ error: 'Invalid resource' });

    // --- BUSINESS VALIDATIONS ---

    // Tables: Check for open orders
    if (resource === 'tables') {
      const openOrders = await pool.query(
        `SELECT 1 FROM orders WHERE table_id = $1 AND status = 'OPEN' LIMIT 1`,
        [id]
      );
      if (openOrders.rows.length > 0) {
        return res.status(400).json({ error: 'No se puede eliminar una mesa con pedidos abiertos' });
      }

      // Soft delete if has history
      const hasHistory = await pool.query(`SELECT 1 FROM orders WHERE table_id = $1 LIMIT 1`, [id]);
      if (hasHistory.rows.length > 0) {
        await pool.query(`UPDATE tables SET is_active = false WHERE id = $1`, [id]);
        return res.json({ success: true, softDelete: true });
      }
    }

    // Products: Check if in active orders
    if (resource === 'products') {
      const inActiveOrder = await pool.query(
        `SELECT 1 FROM order_items oi 
         JOIN orders o ON oi.order_id = o.id 
         WHERE oi.product_id = $1 AND o.status = 'OPEN' LIMIT 1`,
        [id]
      );
      if (inActiveOrder.rows.length > 0) {
        return res.status(400).json({ error: 'El producto está en pedidos activos' });
      }

      const hasHistory = await pool.query(`SELECT 1 FROM order_items WHERE product_id = $1 LIMIT 1`, [id]);
      if (hasHistory.rows.length > 0) {
        await pool.query(`UPDATE products SET is_active = false WHERE id = $1`, [id]);
        return res.json({ success: true, softDelete: true });
      }
    }

    // Categories: Check for products
    if (resource === 'categories') {
      const hasProducts = await pool.query(
        `SELECT COUNT(*) as count FROM products WHERE category_id = $1 AND is_active = true`,
        [id]
      );
      if (parseInt(hasProducts.rows[0].count) > 0) {
        return res.status(400).json({
          error: `La categoría tiene ${hasProducts.rows[0].count} productos activos`
        });
      }
    }

    // Users: Prevent deleting last admin
    if (resource === 'users') {
      const user = await pool.query(`SELECT role_id, tenant_id FROM users WHERE id = $1`, [id]);
      if (user.rows[0]) {
        const role = await pool.query(`SELECT name FROM roles WHERE id = $1`, [user.rows[0].role_id]);
        if (role.rows[0]?.name === 'Administrador') {
          const adminCount = await pool.query(
            `SELECT COUNT(*) as count FROM users u 
             JOIN roles r ON u.role_id = r.id 
             WHERE u.tenant_id = $1 AND r.name = 'Administrador' AND u.is_active = true`,
            [user.rows[0].tenant_id]
          );
          if (parseInt(adminCount.rows[0].count) <= 1) {
            return res.status(400).json({ error: 'No puedes eliminar al único Administrador' });
          }
        }
      }
      // Soft delete users
      await pool.query(`UPDATE users SET is_active = false WHERE id = $1`, [id]);
      return res.json({ success: true, softDelete: true });
    }

    // Roles: Prevent deleting system roles or roles with users
    if (resource === 'roles') {
      const role = await pool.query(`SELECT name, tenant_id FROM roles WHERE id = $1`, [id]);
      if (role.rows[0]?.name === 'Administrador') {
        return res.status(400).json({ error: 'El rol Administrador es de sistema' });
      }
      const usersWithRole = await pool.query(
        `SELECT COUNT(*) as count FROM users WHERE role_id = $1 AND is_active = true`,
        [id]
      );
      if (parseInt(usersWithRole.rows[0].count) > 0) {
        return res.status(400).json({
          error: `Hay ${usersWithRole.rows[0].count} usuarios con este rol`
        });
      }
    }

    // Default: Hard delete
    await pool.query(`DELETE FROM ${resource} WHERE id = $1`, [id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// --- SPECIAL ROUTES ---

// License Check Endpoint (For On-Premise Clients)
app.post('/api/license/verify', async (req, res) => {
  const { licenseKey, tenantId } = req.body;

  // Logic: Buscar el tenant por ID o alguna Key y verificar subscription_status
  try {
    const result = await pool.query('SELECT * FROM tenants WHERE id = $1', [tenantId]);
    const tenant = result.rows[0];

    if (!tenant) return res.status(404).json({ valid: false, message: 'Tenant not found' });

    if (tenant.subscription_status === 'ACTIVE') {
      return res.json({ valid: true, plan: tenant.plan, status: 'ACTIVE' });
    } else {
      return res.json({ valid: false, status: tenant.subscription_status, message: 'Subscription inactive' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Verification failed' });
  }
});

// Obtener un tenant por ID (para refrescar estado en frontend)
app.get('/api/tenants/:id', async (req, res) => {
  const { id } = req.params;
  try {
    if (!isUuid(id)) return res.status(400).json({ error: 'tenantId inválido (UUID requerido)' });

    const result = await pool.query(
      `SELECT id, name, slug, plan, subscription_status, mercadopago_preapproval_id, next_billing_date, created_at, settings
       FROM tenants WHERE id = $1`,
      [id]
    );

    const row = result.rows[0];
    if (!row) return res.status(404).json({ error: 'Tenant not found' });

    return res.json({
      id: row.id,
      name: row.name,
      slug: row.slug || '',
      plan: row.plan,
      subscriptionStatus: row.subscription_status,
      mercadoPagoPreapprovalId: row.mercadopago_preapproval_id || undefined,
      nextBillingDate: row.next_billing_date ? new Date(row.next_billing_date).toISOString() : undefined,
      createdAt: row.created_at ? new Date(row.created_at).toISOString() : new Date().toISOString(),
      settings: row.settings || {},
    });
  } catch (error) {
    console.error('Error fetching tenant:', error);
    return res.status(500).json({ error: 'Failed to fetch tenant' });
  }
});


// Serve Static Files (Vite Build)
app.use(express.static(path.join(__dirname, 'dist')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

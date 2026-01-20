
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
import { MercadoPagoConfig, PreApproval } from 'mercadopago';
const mpClient = new MercadoPagoConfig({ accessToken: process.env.MP_ACCESS_TOKEN || '' });
const preapproval = new PreApproval(mpClient);

// Test DB Connection
pool.connect((err, client, release) => {
  if (err) {
    console.error('Error acquiring client', err.stack);
  } else {
    console.log('✅ Connected to PostgreSQL database');
    release();
  }
});

// --- VALID RESOURCES (Security) ---
const VALID_TABLES = ['tenants', 'users', 'roles', 'products', 'categories', 'tables', 'orders', 'order_items', 'shifts', 'audit_logs'];

// Helper: Sanitize table name
const isValidTable = (table) => VALID_TABLES.includes(table);

// --- MERCADO PAGO ROUTES ---

app.post('/api/subscriptions', async (req, res) => {
  const { tenantId, planId, price, email, backUrl } = req.body;
  console.log('--- NEW SUBSCRIPTION REQUEST ---');
  console.log('Data:', { tenantId, planId, price, email, backUrl });

  try {
    const response = await preapproval.create({
      body: {
        reason: `Suscripción GastroFlow ${planId}`,
        auto_recurring: {
          frequency: 1,
          frequency_type: "months",
          transaction_amount: price,
          currency_id: "ARS"
        },
        back_url: backUrl || "https://gastroflow.accesoit.com.ar/billing",
        payer_email: email || "test_user_123456@testuser.com",
        external_reference: tenantId,
        status: "pending"
      }
    });

    res.json({ init_point: response.init_point, id: response.id });
  } catch (error) {
    console.error('Error creating subscription:', error);
    res.status(500).json({ error: 'Failed to create subscription', details: error.message });
  }
});

app.post('/api/webhooks/mercadopago', async (req, res) => {
  const { type, data } = req.body;
  const { id } = data || {};

  console.log('Webhook received:', type, id);

  try {
    if (type === 'subscription_preapproval') {
      // Logic to update tenant status would go here
      // For now we just log it as we need to fetch the preapproval details
    }
    res.sendStatus(200);
  } catch (error) {
    console.error('Webhook error:', error);
    res.sendStatus(500);
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


// Serve Static Files (Vite Build)
app.use(express.static(path.join(__dirname, 'dist')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

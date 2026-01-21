
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import pg from 'pg';
import cors from 'cors';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import nodemailer from 'nodemailer';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET || '';
const GLOBAL_ADMIN_BOOTSTRAP_TOKEN = process.env.GLOBAL_ADMIN_BOOTSTRAP_TOKEN || '';
const ENFORCE_AUTH = process.env.MULTI_TENANT_ENFORCE_AUTH
  ? process.env.MULTI_TENANT_ENFORCE_AUTH === 'true'
  : process.env.NODE_ENV === 'production';

const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || '';

const SMTP_HOST = process.env.SMTP_HOST || '';
const SMTP_PORT = process.env.SMTP_PORT ? Number(process.env.SMTP_PORT) : 587;
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
const SMTP_FROM = process.env.SMTP_FROM || SMTP_USER || '';

let mailTransporter = null;
const getMailer = () => {
  if (mailTransporter) return mailTransporter;
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) return null;
  mailTransporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: false,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
    requireTLS: true,
  });
  return mailTransporter;
};

const sendEmail = async ({ to, subject, html, text }) => {
  const transporter = getMailer();
  if (!transporter) {
    throw new Error('SMTP no configurado (SMTP_HOST/SMTP_USER/SMTP_PASS)');
  }
  await transporter.sendMail({
    from: SMTP_FROM,
    to,
    subject,
    html,
    text,
  });
};

const getBaseUrlForLinks = (req) => {
  if (PUBLIC_BASE_URL) return PUBLIC_BASE_URL.replace(/\/$/, '');
  const origin = req.get('origin');
  if (origin) return String(origin).replace(/\/$/, '');
  const proto = req.get('x-forwarded-proto') || req.protocol || 'http';
  const host = req.get('x-forwarded-host') || req.get('host');
  return host ? `${proto}://${host}` : '';
};

const slugify = (value) => {
  return String(value || '')
    .trim()
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '')
    .slice(0, 80);
};

const sha256Hex = (value) => crypto.createHash('sha256').update(value).digest('hex');

const createPasswordReset = async ({ scope, email, tenantUserId, tenantId, adminId, req }) => {
  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = sha256Hex(rawToken);
  const ttlMinutes = process.env.RESET_TOKEN_TTL_MINUTES ? Number(process.env.RESET_TOKEN_TTL_MINUTES) : 60;
  const expiresAt = new Date(Date.now() + Math.max(5, ttlMinutes) * 60 * 1000);

  await pool.query(
    `INSERT INTO password_resets (scope, email, tenant_id, user_id, admin_id, token_hash, expires_at, created_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
    [scope, email, tenantId || null, tenantUserId || null, adminId || null, tokenHash, expiresAt]
  );

  const baseUrl = getBaseUrlForLinks(req);
  const path = scope === 'global' ? '/admin/reset-password' : '/app/reset-password';
  const resetUrl = baseUrl ? `${baseUrl}${path}?token=${encodeURIComponent(rawToken)}&email=${encodeURIComponent(email)}` : '';
  return { rawToken, resetUrl, expiresAt };
};

const consumePasswordReset = async ({ scope, email, token, newPassword }) => {
  const tokenHash = sha256Hex(token);

  const r = await pool.query(
    `SELECT id, scope, email, tenant_id, user_id, admin_id, expires_at, used_at
     FROM password_resets
     WHERE token_hash = $1 AND scope = $2 AND email = $3
     LIMIT 1`,
    [tokenHash, scope, email]
  );
  const row = r.rows[0];
  if (!row) return { ok: false, error: 'Token inválido' };
  if (row.used_at) return { ok: false, error: 'Token ya utilizado' };
  if (row.expires_at && new Date(row.expires_at).getTime() < Date.now()) return { ok: false, error: 'Token expirado' };

  const passwordHash = await hashPassword(newPassword);
  if (scope === 'global') {
    if (!row.admin_id) return { ok: false, error: 'Token inválido' };
    await pool.query('UPDATE global_admins SET password_hash = $1 WHERE id = $2', [passwordHash, row.admin_id]);
  } else {
    if (!row.user_id || !row.tenant_id) return { ok: false, error: 'Token inválido' };
    await pool.query(
      'UPDATE users SET password_hash = $1 WHERE id = $2 AND tenant_id = $3',
      [passwordHash, row.user_id, row.tenant_id]
    );
  }

  await pool.query('UPDATE password_resets SET used_at = NOW() WHERE id = $1', [row.id]);
  return { ok: true };
};

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

    // Global admins (fuera del ámbito tenant)
    await client.query(`
      CREATE TABLE IF NOT EXISTS global_admins (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL,
        is_active BOOLEAN DEFAULT TRUE,
        last_login TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Roles / Users: asegurar columnas y constraints
    await client.query(`
      ALTER TABLE roles
        ADD COLUMN IF NOT EXISTS permissions TEXT[] DEFAULT '{}'::text[],
        ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW();

      CREATE UNIQUE INDEX IF NOT EXISTS ux_roles_tenant_name ON roles(tenant_id, name);
      CREATE INDEX IF NOT EXISTS idx_roles_tenant ON roles(tenant_id);

      ALTER TABLE users
        ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255),
        ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE,
        ADD COLUMN IF NOT EXISTS last_login TIMESTAMP,
        ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW();

      CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    `);

    // Trigger: user.role_id debe pertenecer al mismo tenant
    await client.query(`
      CREATE OR REPLACE FUNCTION ensure_user_role_same_tenant()
      RETURNS TRIGGER AS $$
      DECLARE
        role_tenant UUID;
      BEGIN
        IF NEW.role_id IS NULL THEN
          RETURN NEW;
        END IF;

        SELECT tenant_id INTO role_tenant FROM roles WHERE id = NEW.role_id;

        IF role_tenant IS NULL THEN
          RAISE EXCEPTION 'Role % no existe', NEW.role_id;
        END IF;

        IF role_tenant <> NEW.tenant_id THEN
          RAISE EXCEPTION 'Role % pertenece a otro tenant (role.tenant_id=%, user.tenant_id=%)', NEW.role_id, role_tenant, NEW.tenant_id;
        END IF;

        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;

      DO $$
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_users_role_same_tenant') THEN
          CREATE TRIGGER trg_users_role_same_tenant
          BEFORE INSERT OR UPDATE OF role_id, tenant_id ON users
          FOR EACH ROW
          EXECUTE FUNCTION ensure_user_role_same_tenant();
        END IF;
      END $$;
    `);

    // Tenants: asegurar columnas necesarias
    await client.query(`
      ALTER TABLE tenants
        ADD COLUMN IF NOT EXISTS slug VARCHAR(255),
        ADD COLUMN IF NOT EXISTS plan VARCHAR(50) DEFAULT 'BASIC',
        ADD COLUMN IF NOT EXISTS subscription_status VARCHAR(50) DEFAULT 'TRIAL',
        ADD COLUMN IF NOT EXISTS trial_ends_at TIMESTAMP,
        ADD COLUMN IF NOT EXISTS mercadopago_preapproval_id VARCHAR(255),
        ADD COLUMN IF NOT EXISTS next_billing_date TIMESTAMP,
        ADD COLUMN IF NOT EXISTS settings JSONB DEFAULT '{}'::jsonb;
    `);

    // Trial: backfill + expiración automática (idempotente)
    await client.query(`
      UPDATE tenants
      SET trial_ends_at = created_at + INTERVAL '15 days'
      WHERE trial_ends_at IS NULL AND subscription_status = 'TRIAL' AND created_at IS NOT NULL;

      UPDATE tenants
      SET subscription_status = 'INACTIVE'
      WHERE subscription_status = 'TRIAL' AND trial_ends_at IS NOT NULL AND trial_ends_at <= NOW();
    `);

    // Password reset tokens
    await client.query(`
      CREATE TABLE IF NOT EXISTS password_resets (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        scope VARCHAR(10) NOT NULL,
        email VARCHAR(255) NOT NULL,
        tenant_id UUID,
        user_id UUID,
        admin_id UUID,
        token_hash VARCHAR(64) UNIQUE NOT NULL,
        expires_at TIMESTAMP,
        used_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_password_resets_email ON password_resets(email);
      CREATE INDEX IF NOT EXISTS idx_password_resets_created ON password_resets(created_at DESC);
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

    // Trial history: rastrear emails que ya tuvieron trial (anti-abuso)
    await client.query(`
      CREATE TABLE IF NOT EXISTS trial_history (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        email VARCHAR(255) NOT NULL,
        tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
        started_at TIMESTAMP DEFAULT NOW(),
        ended_at TIMESTAMP,
        reason VARCHAR(100) DEFAULT 'expired'
      );

      CREATE UNIQUE INDEX IF NOT EXISTS ux_trial_history_email ON trial_history(email);
      CREATE INDEX IF NOT EXISTS idx_trial_history_tenant ON trial_history(tenant_id);
    `);

    console.log('✅ DB schema verificado (tenants + billing_history + trial_history)');
  } finally {
    client.release();
  }
};

const hashPassword = async (plain) => {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(String(plain), salt);
};

const verifyPassword = async (plain, hashed) => {
  if (!hashed) return false;
  return bcrypt.compare(String(plain), String(hashed));
};

const signToken = (payload) => {
  if (!JWT_SECRET) throw new Error('JWT_SECRET no configurado');
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '12h' });
};

const authMiddleware = (req, res, next) => {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    req.auth = null;
    return next();
  }

  const token = header.slice('Bearer '.length);
  try {
    if (!JWT_SECRET) {
      return res.status(500).json({ error: 'JWT_SECRET no configurado' });
    }
    const decoded = jwt.verify(token, JWT_SECRET);
    req.auth = decoded;
    return next();
  } catch (e) {
    return res.status(401).json({ error: 'Token inválido' });
  }
};

const requireAuth = (req, res, next) => {
  if (!req.auth) return res.status(401).json({ error: 'Auth requerida' });
  return next();
};

const requireGlobalAdmin = (req, res, next) => {
  if (!req.auth) return res.status(401).json({ error: 'Auth requerida' });
  if (req.auth.scope !== 'global') return res.status(403).json({ error: 'Solo admin global' });
  return next();
};

const requireTenantUser = (req, res, next) => {
  if (!req.auth) return res.status(401).json({ error: 'Auth requerida' });
  if (req.auth.scope !== 'tenant') return res.status(403).json({ error: 'Solo usuario tenant' });
  return next();
};

const requireTenantAccess = (req, res, next) => {
  const { tenantId } = req.params;
  if (!req.auth) return res.status(401).json({ error: 'Auth requerida' });
  if (req.auth.scope === 'global') return next();
  if (!tenantId || req.auth.tenantId !== tenantId) return res.status(403).json({ error: 'Acceso denegado al tenant' });
  return next();
};

const requirePermission = (perm) => (req, res, next) => {
  if (!req.auth) return res.status(401).json({ error: 'Auth requerida' });
  if (req.auth.scope === 'global') return next();
  const perms = Array.isArray(req.auth.permissions) ? req.auth.permissions : [];
  if (!perms.includes(perm)) return res.status(403).json({ error: `Permiso requerido: ${perm}` });
  return next();
};

app.use(authMiddleware);

const DEFAULT_PERMISSIONS = [
  'tables.view', 'tables.edit', 'tables.manage',
  'kitchen.view', 'kitchen.manage',
  'cash.view', 'cash.manage',
  'dashboard.view', 'reports.view',
  'menu.view', 'menu.edit',
  'stock.view', 'stock.adjust',
  'users.view', 'users.manage',
  'roles.manage', 'settings.manage',
  'billing.manage'
];

const seedDefaultRolesForTenant = async (tenantId) => {
  // Admin
  await pool.query(
    `INSERT INTO roles (tenant_id, name, permissions)
     VALUES ($1, $2, $3)
     ON CONFLICT (tenant_id, name) DO NOTHING`,
    [tenantId, 'Administrador', DEFAULT_PERMISSIONS]
  );

  // Encargado
  await pool.query(
    `INSERT INTO roles (tenant_id, name, permissions)
     VALUES ($1, $2, $3)
     ON CONFLICT (tenant_id, name) DO NOTHING`,
    [tenantId, 'Encargado', [
      'tables.view', 'tables.edit',
      'kitchen.view', 'kitchen.manage',
      'cash.view', 'cash.manage',
      'dashboard.view', 'reports.view',
      'menu.view', 'stock.view'
    ]]
  );

  // Mozo/Camarero
  await pool.query(
    `INSERT INTO roles (tenant_id, name, permissions)
     VALUES ($1, $2, $3)
     ON CONFLICT (tenant_id, name) DO NOTHING`,
    [tenantId, 'Mozo', ['tables.view', 'tables.edit', 'menu.view']]
  );
};

const getTenantAdminRoleId = async (tenantId) => {
  const r = await pool.query(
    `SELECT id FROM roles WHERE tenant_id = $1 AND name = 'Administrador' LIMIT 1`,
    [tenantId]
  );
  return r.rows[0]?.id || null;
};

// ==========================================
// AUTH ENDPOINTS
// ==========================================

// Bootstrap global admin: deshabilitado por seguridad (usar migración/seed manual).

// Deprecated (no mezclar sesiones): usar /api/admin/auth/login o /api/app/auth/login
app.post('/api/auth/login', (_req, res) => {
  return res.status(410).json({
    error: 'Endpoint deprecated. Usar /api/admin/auth/login (owner) o /api/app/auth/login (clientes).'
  });
});

// ============ ADMIN (GLOBAL OWNER) ============
app.post('/api/admin/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  try {
    if (!email || !password) return res.status(400).json({ error: 'email/password requeridos' });

    const r = await pool.query(
      `SELECT id, email, password_hash, name, is_active FROM global_admins WHERE email = $1 LIMIT 1`,
      [email]
    );
    const admin = r.rows[0];
    if (!admin || !admin.is_active) return res.status(401).json({ error: 'Credenciales inválidas' });

    const ok = await verifyPassword(password, admin.password_hash);
    if (!ok) return res.status(401).json({ error: 'Credenciales inválidas' });

    await pool.query('UPDATE global_admins SET last_login = NOW() WHERE id = $1', [admin.id]);
    const token = signToken({ scope: 'global', sub: admin.id, email: admin.email });
    return res.json({ ok: true, token, scope: 'global', user: { id: admin.id, email: admin.email, name: admin.name } });
  } catch (error) {
    console.error('admin login error:', error);
    return res.status(500).json({ error: 'login failed' });
  }
});

app.post('/api/admin/auth/forgot-password', async (req, res) => {
  const { email } = req.body || {};
  try {
    if (!email) return res.status(400).json({ error: 'email requerido' });

    const r = await pool.query(
      `SELECT id, email, is_active, name FROM global_admins WHERE email = $1 LIMIT 1`,
      [email]
    );
    const admin = r.rows[0];

    // Responder siempre OK para evitar enumeración de usuarios
    if (!admin || !admin.is_active) {
      return res.json({ ok: true, message: 'Si el email existe, enviaremos un link de recuperación.' });
    }

    const { resetUrl, expiresAt } = await createPasswordReset({
      scope: 'global',
      email: admin.email,
      adminId: admin.id,
      req,
    });

    const safeUrl = resetUrl || '';
    await sendEmail({
      to: admin.email,
      subject: 'GastroFlow - Recuperación de contraseña (Admin)',
      text: `Hola ${admin.name || ''}\n\nUsá este link para cambiar tu contraseña (expira ${expiresAt.toISOString()}):\n${safeUrl}\n\nSi no lo solicitaste, ignorá este correo.`,
      html: `<p>Hola ${admin.name || ''}</p><p>Usá este link para cambiar tu contraseña (expira ${expiresAt.toISOString()}):</p><p><a href="${safeUrl}">${safeUrl}</a></p><p>Si no lo solicitaste, ignorá este correo.</p>`,
    });

    return res.json({ ok: true, message: 'Si el email existe, enviaremos un link de recuperación.' });
  } catch (error) {
    console.error('admin forgot-password error:', error);
    return res.status(500).json({ error: 'No se pudo enviar el email de recuperación' });
  }
});

app.post('/api/admin/auth/reset-password', async (req, res) => {
  const { email, token, newPassword } = req.body || {};
  try {
    if (!email || !token || !newPassword) return res.status(400).json({ error: 'email/token/newPassword requeridos' });
    if (typeof newPassword !== 'string' || newPassword.length < 8) return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres' });
    const result = await consumePasswordReset({ scope: 'global', email, token, newPassword });
    if (!result.ok) return res.status(400).json({ error: result.error || 'Token inválido' });
    return res.json({ ok: true });
  } catch (error) {
    console.error('admin reset-password error:', error);
    return res.status(500).json({ error: 'No se pudo resetear la contraseña' });
  }
});

app.get('/api/admin/me', requireGlobalAdmin, async (req, res) => {
  try {
    const r = await pool.query('SELECT id, email, name FROM global_admins WHERE id = $1', [req.auth.sub]);
    return res.json({ scope: 'global', user: r.rows[0] || null });
  } catch (error) {
    console.error('admin me error:', error);
    return res.status(500).json({ error: 'failed' });
  }
});

// ============ APP (TENANT CLIENTS) ============
app.post('/api/app/auth/login', async (req, res) => {
  const { email, password, tenantId } = req.body || {};
  try {
    if (!email || !password) return res.status(400).json({ error: 'email/password requeridos' });

    const ensureTrialForTenant = async (resolvedTenantId) => {
      if (!isUuid(resolvedTenantId)) return;

      // Si no tiene trial_ends_at (tenants viejos), lo derivamos de created_at + 15 días.
      await pool.query(
        `UPDATE tenants
         SET trial_ends_at = COALESCE(trial_ends_at, created_at + INTERVAL '15 days')
         WHERE id = $1 AND subscription_status = 'TRIAL'`,
        [resolvedTenantId]
      );

      // Si el trial ya venció, lo marcamos INACTIVE.
      await pool.query(
        `UPDATE tenants
         SET subscription_status = 'INACTIVE'
         WHERE id = $1 AND subscription_status = 'TRIAL' AND trial_ends_at IS NOT NULL AND trial_ends_at <= NOW()`,
        [resolvedTenantId]
      );
    };

    // Si viene tenantId (ej: selector), autenticamos directo.
    if (tenantId) {
      if (!isUuid(tenantId)) return res.status(400).json({ error: 'tenantId inválido (UUID requerido)' });
      const r = await pool.query(
        `SELECT u.id, u.email, u.password_hash, u.name, u.is_active, u.role_id,
                COALESCE(r.permissions, '{}'::text[]) AS permissions
         FROM users u
         LEFT JOIN roles r ON r.id = u.role_id
         WHERE u.tenant_id = $1 AND u.email = $2
         LIMIT 1`,
        [tenantId, email]
      );
      const user = r.rows[0];
      if (!user || !user.is_active) return res.status(401).json({ error: 'Credenciales inválidas' });
      const ok = await verifyPassword(password, user.password_hash);
      if (!ok) return res.status(401).json({ error: 'Credenciales inválidas' });

      await ensureTrialForTenant(tenantId);

      await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);
      const token = signToken({
        scope: 'tenant',
        sub: user.id,
        tenantId,
        roleId: user.role_id,
        permissions: user.permissions,
        email: user.email,
      });
      return res.json({
        ok: true,
        token,
        scope: 'tenant',
        user: { id: user.id, tenantId, email: user.email, name: user.name, roleId: user.role_id, permissions: user.permissions }
      });
    }

    // Resolver tenant automáticamente por email+password.
    const candidatesRes = await pool.query(
      `SELECT u.id, u.tenant_id, u.email, u.password_hash, u.name, u.is_active, u.role_id,
              COALESCE(r.permissions, '{}'::text[]) AS permissions,
              t.name AS tenant_name, t.slug AS tenant_slug
       FROM users u
       JOIN tenants t ON t.id = u.tenant_id
       LEFT JOIN roles r ON r.id = u.role_id
       WHERE u.email = $1`,
      [email]
    );

    const candidates = (candidatesRes.rows || []).filter((u) => u && u.is_active);
    if (candidates.length === 0) {
      console.warn('[AUTH] no candidates for email=', email);
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    // Diagnostics: log candidate tenants and whether they have a password_hash
    try {
      console.info('[AUTH] candidates count=', candidates.length, 'email=', email, 'tenants=', candidates.map(c => ({ tenant_id: c.tenant_id, tenant_name: c.tenant_name || null, has_hash: !!c.password_hash })) );
    } catch (e) {
      console.info('[AUTH] candidates diagnostic error', e?.message || e);
    }

    const matches = [];
    for (const u of candidates) {
      // eslint-disable-next-line no-await-in-loop
      const ok = await verifyPassword(password, u.password_hash);
      if (ok) matches.push(u);
      else {
        if (!u.password_hash) {
          console.warn('[AUTH] candidate without password_hash', { email: u.email, tenant_id: u.tenant_id, user_id: u.id });
        }
      }
    }

    if (matches.length === 0) {
      console.warn('[AUTH] password did not match any candidate for email=', email, 'candidates=', candidates.map(c => c.tenant_id));
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    if (matches.length > 1) {
      return res.status(409).json({
        error: 'El email existe en múltiples empresas. Seleccioná una para continuar.',
        code: 'MULTI_TENANT_EMAIL',
        tenants: matches.map((m) => ({ id: m.tenant_id, name: m.tenant_name, slug: m.tenant_slug || '' })),
      });
    }

    const user = matches[0];
    const resolvedTenantId = user.tenant_id;

    await ensureTrialForTenant(resolvedTenantId);
    await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);
    const token = signToken({
      scope: 'tenant',
      sub: user.id,
      tenantId: resolvedTenantId,
      roleId: user.role_id,
      permissions: user.permissions,
      email: user.email,
    });

    return res.json({
      ok: true,
      token,
      scope: 'tenant',
      user: { id: user.id, tenantId: resolvedTenantId, email: user.email, name: user.name, roleId: user.role_id, permissions: user.permissions }
    });
  } catch (error) {
    console.error('app login error:', error);
    return res.status(500).json({ error: 'login failed' });
  }
});

app.post('/api/app/auth/register', async (req, res) => {
  const { tenantName, tenantSlug, name, email, password } = req.body || {};
  try {
    if (!tenantName || !name || !email || !password) {
      return res.status(400).json({ error: 'tenantName/name/email/password requeridos' });
    }
    if (typeof password !== 'string' || password.length < 8) {
      return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres' });
    }

    // Evitar colisiones con admin global
    const ga = await pool.query('SELECT 1 FROM global_admins WHERE email = $1 LIMIT 1', [email]);
    if (ga.rows.length > 0) return res.status(409).json({ error: 'El email ya está reservado para el owner' });

    // Verificar si el email ya existe como usuario en algún tenant
    const existingUser = await pool.query('SELECT 1 FROM users WHERE email = $1 LIMIT 1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ error: 'Este email ya está registrado. Si olvidaste tu contraseña, usá "Recuperar contraseña".' });
    }

    // Anti-abuso de trial: verificar si este email ya tuvo trial antes
    const trialCheck = await pool.query('SELECT 1 FROM trial_history WHERE email = $1 LIMIT 1', [email.toLowerCase()]);
    const hadTrialBefore = trialCheck.rows.length > 0;

    let slug = tenantSlug ? slugify(tenantSlug) : slugify(tenantName);
    if (!slug) slug = `tenant-${crypto.randomBytes(4).toString('hex')}`;

    // Asegurar unicidad de slug
    const slugCheck = await pool.query('SELECT 1 FROM tenants WHERE slug = $1 LIMIT 1', [slug]);
    if (slugCheck.rows.length > 0) {
      slug = `${slug}-${crypto.randomBytes(3).toString('hex')}`;
    }

    // Si ya tuvo trial, crear como INACTIVE (debe pagar para usar)
    const subscriptionStatus = hadTrialBefore ? 'INACTIVE' : 'TRIAL';
    const trialEndsClause = hadTrialBefore ? 'NULL' : "NOW() + INTERVAL '15 days'";

    const createdTenant = await pool.query(
      `INSERT INTO tenants (name, slug, plan, subscription_status, trial_ends_at)
       VALUES ($1, $2, 'BASIC', $3, ${trialEndsClause})
       RETURNING id, name, slug, plan, subscription_status, trial_ends_at, mercadopago_preapproval_id, next_billing_date, created_at`,
      [tenantName, slug, subscriptionStatus]
    );
    const tenant = createdTenant.rows[0];

    // Si es trial nuevo, registrar en trial_history
    if (!hadTrialBefore) {
      await pool.query(
        `INSERT INTO trial_history (email, tenant_id, started_at) VALUES ($1, $2, NOW())
         ON CONFLICT (email) DO NOTHING`,
        [email.toLowerCase(), tenant.id]
      );
    }

    await seedDefaultRolesForTenant(tenant.id);
    const adminRoleId = await getTenantAdminRoleId(tenant.id);
    const permsRes = await pool.query(
      `SELECT COALESCE(permissions, '{}'::text[]) AS permissions
       FROM roles WHERE id = $1 AND tenant_id = $2 LIMIT 1`,
      [adminRoleId, tenant.id]
    );
    const rolePermissions = permsRes.rows[0]?.permissions || DEFAULT_PERMISSIONS;

    const passwordHash = await hashPassword(password);
    const createdUser = await pool.query(
      `INSERT INTO users (tenant_id, email, password_hash, name, role_id, is_active)
       VALUES ($1, $2, $3, $4, $5, TRUE)
       RETURNING id, tenant_id, email, name, role_id`,
      [tenant.id, email, passwordHash, name, adminRoleId]
    );
    const user = createdUser.rows[0];

    const token = signToken({
      scope: 'tenant',
      sub: user.id,
      tenantId: tenant.id,
      roleId: user.role_id,
      permissions: rolePermissions,
      email: user.email,
    });

    // Email opcional de bienvenida
    try {
      await sendEmail({
        to: email,
        subject: 'Bienvenido a GastroFlow',
        text: `Hola ${name}!\n\nTu cuenta fue creada para la empresa: ${tenantName}.\n\nIngresá a tu panel para completar la suscripción.`,
        html: `<p>Hola ${name}!</p><p>Tu cuenta fue creada para la empresa: <b>${tenantName}</b>.</p><p>Ingresá a tu panel para completar la suscripción.</p>`,
      });
    } catch (e) {
      console.warn('No se pudo enviar email de bienvenida (continúa):', e?.message || e);
    }

    return res.status(201).json({
      ok: true,
      token,
      scope: 'tenant',
      user: { id: user.id, tenantId: tenant.id, email: user.email, name: user.name, roleId: user.role_id, permissions: rolePermissions },
      tenant: {
        id: tenant.id,
        name: tenant.name,
        slug: tenant.slug || '',
        plan: tenant.plan,
        subscriptionStatus: tenant.subscription_status,
        trialEndsAt: tenant.trial_ends_at ? new Date(tenant.trial_ends_at).toISOString() : undefined,
        mercadoPagoPreapprovalId: tenant.mercadopago_preapproval_id || undefined,
        nextBillingDate: tenant.next_billing_date ? new Date(tenant.next_billing_date).toISOString() : undefined,
        createdAt: tenant.created_at ? new Date(tenant.created_at).toISOString() : new Date().toISOString(),
      }
    });
  } catch (error) {
    console.error('app register error:', error);
    return res.status(500).json({ error: 'No se pudo registrar' });
  }
});

app.post('/api/app/auth/forgot-password', async (req, res) => {
  const { email, tenantId } = req.body || {};
  try {
    if (!email) return res.status(400).json({ error: 'email requerido' });

    if (tenantId) {
      if (!isUuid(tenantId)) return res.status(400).json({ error: 'tenantId inválido (UUID requerido)' });
      const r = await pool.query(
        `SELECT u.id, u.tenant_id, u.email, u.name, u.is_active
         FROM users u
         WHERE u.email = $1 AND u.tenant_id = $2
         LIMIT 1`,
        [email, tenantId]
      );
      const user = r.rows[0];
      if (!user || !user.is_active) {
        return res.json({ ok: true, message: 'Si el email existe, enviaremos un link de recuperación.' });
      }

      const { resetUrl, expiresAt } = await createPasswordReset({
        scope: 'tenant',
        email: user.email,
        tenantUserId: user.id,
        tenantId: user.tenant_id,
        req,
      });

      const safeUrl = resetUrl || '';
      await sendEmail({
        to: user.email,
        subject: 'GastroFlow - Recuperación de contraseña',
        text: `Hola ${user.name || ''}\n\nUsá este link para cambiar tu contraseña (expira ${expiresAt.toISOString()}):\n${safeUrl}\n\nSi no lo solicitaste, ignorá este correo.`,
        html: `<p>Hola ${user.name || ''}</p><p>Usá este link para cambiar tu contraseña (expira ${expiresAt.toISOString()}):</p><p><a href="${safeUrl}">${safeUrl}</a></p><p>Si no lo solicitaste, ignorá este correo.</p>`,
      });

      return res.json({ ok: true, message: 'Si el email existe, enviaremos un link de recuperación.' });
    }

    const candidatesRes = await pool.query(
      `SELECT u.id, u.tenant_id, u.email, u.name, u.is_active, t.name AS tenant_name, t.slug AS tenant_slug
       FROM users u
       JOIN tenants t ON t.id = u.tenant_id
       WHERE u.email = $1`,
      [email]
    );

    const candidates = (candidatesRes.rows || []).filter((u) => u && u.is_active);

    // Responder siempre OK para evitar enumeración
    if (candidates.length === 0) {
      return res.json({ ok: true, message: 'Si el email existe, enviaremos un link de recuperación.' });
    }

    if (candidates.length > 1) {
      return res.status(409).json({
        ok: false,
        error: 'El email existe en múltiples empresas. Seleccioná una para continuar.',
        code: 'MULTI_TENANT_EMAIL',
        tenants: candidates.map((m) => ({ id: m.tenant_id, name: m.tenant_name, slug: m.tenant_slug || '' })),
      });
    }

    const user = candidates[0];

    const { resetUrl, expiresAt } = await createPasswordReset({
      scope: 'tenant',
      email: user.email,
      tenantUserId: user.id,
      tenantId: user.tenant_id,
      req,
    });

    const safeUrl = resetUrl || '';
    await sendEmail({
      to: user.email,
      subject: 'GastroFlow - Recuperación de contraseña',
      text: `Hola ${user.name || ''}\n\nUsá este link para cambiar tu contraseña (expira ${expiresAt.toISOString()}):\n${safeUrl}\n\nSi no lo solicitaste, ignorá este correo.`,
      html: `<p>Hola ${user.name || ''}</p><p>Usá este link para cambiar tu contraseña (expira ${expiresAt.toISOString()}):</p><p><a href="${safeUrl}">${safeUrl}</a></p><p>Si no lo solicitaste, ignorá este correo.</p>`,
    });

    return res.json({ ok: true, message: 'Si el email existe, enviaremos un link de recuperación.' });
  } catch (error) {
    console.error('app forgot-password error:', error);
    return res.status(500).json({ error: 'No se pudo enviar el email de recuperación' });
  }
});

app.post('/api/app/auth/reset-password', async (req, res) => {
  const { email, token, newPassword } = req.body || {};
  try {
    if (!email || !token || !newPassword) return res.status(400).json({ error: 'email/token/newPassword requeridos' });
    if (typeof newPassword !== 'string' || newPassword.length < 8) return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres' });
    const result = await consumePasswordReset({ scope: 'tenant', email, token, newPassword });
    if (!result.ok) return res.status(400).json({ error: result.error || 'Token inválido' });
    return res.json({ ok: true });
  } catch (error) {
    console.error('app reset-password error:', error);
    return res.status(500).json({ error: 'No se pudo resetear la contraseña' });
  }
});

app.get('/api/app/me', requireTenantUser, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT u.id, u.tenant_id, u.email, u.name, u.role_id,
              COALESCE(r.permissions, '{}'::text[]) AS permissions
       FROM users u
       LEFT JOIN roles r ON r.id = u.role_id
       WHERE u.id = $1`,
      [req.auth.sub]
    );
    const u = r.rows[0];
    return res.json({
      scope: 'tenant',
      user: u ? { id: u.id, tenantId: u.tenant_id, email: u.email, name: u.name, roleId: u.role_id, permissions: u.permissions } : null
    });
  } catch (error) {
    console.error('app me error:', error);
    return res.status(500).json({ error: 'failed' });
  }
});

// Perfil actual
app.get('/api/me', requireAuth, async (req, res) => {
  try {
    if (req.auth.scope === 'global') {
      const r = await pool.query('SELECT id, email, name FROM global_admins WHERE id = $1', [req.auth.sub]);
      return res.json({ scope: 'global', user: r.rows[0] || null });
    }

    const r = await pool.query(
      `SELECT u.id, u.tenant_id, u.email, u.name, u.role_id,
              COALESCE(r.permissions, '{}'::text[]) AS permissions
       FROM users u
       LEFT JOIN roles r ON r.id = u.role_id
       WHERE u.id = $1`,
      [req.auth.sub]
    );
    const u = r.rows[0];
    return res.json({
      scope: 'tenant',
      user: u ? { id: u.id, tenantId: u.tenant_id, email: u.email, name: u.name, roleId: u.role_id, permissions: u.permissions } : null
    });
  } catch (error) {
    console.error('me error:', error);
    return res.status(500).json({ error: 'failed' });
  }
});

// ==========================================
// GLOBAL ADMIN: TENANT MANAGEMENT
// ==========================================

app.get('/api/admin/tenants', requireGlobalAdmin, async (_req, res) => {
  const r = await pool.query('SELECT id, name, slug, plan, subscription_status, trial_ends_at, created_at FROM tenants ORDER BY created_at DESC');
  return res.json(r.rows);
});

app.post('/api/admin/tenants', requireGlobalAdmin, async (req, res) => {
  const { name, slug, adminEmail, adminPassword, adminName } = req.body || {};
  try {
    if (!name) return res.status(400).json({ error: 'name requerido' });

    const createdTenant = await pool.query(
      `INSERT INTO tenants (name, slug, subscription_status, trial_ends_at)
       VALUES ($1, $2, 'TRIAL', NOW() + INTERVAL '15 days')
       RETURNING id, name, slug, plan, subscription_status, trial_ends_at, created_at`,
      [name, slug || null]
    );
    const tenant = createdTenant.rows[0];

    await seedDefaultRolesForTenant(tenant.id);
    const adminRoleId = await getTenantAdminRoleId(tenant.id);

    let adminUser = null;
    if (adminEmail && adminPassword && adminName) {
      const passwordHash = await hashPassword(adminPassword);
      const createdUser = await pool.query(
        `INSERT INTO users (tenant_id, email, password_hash, name, role_id, is_active)
         VALUES ($1, $2, $3, $4, $5, TRUE)
         RETURNING id, tenant_id, email, name, role_id`,
        [tenant.id, adminEmail, passwordHash, adminName, adminRoleId]
      );
      adminUser = createdUser.rows[0];
    }

    return res.json({ ok: true, tenant, adminUser });
  } catch (error) {
    console.error('create tenant error:', error);
    return res.status(500).json({ error: 'failed to create tenant' });
  }
});

// Detalle de tenant con usuarios (admin global)
app.get('/api/admin/tenants/:tenantId', requireGlobalAdmin, async (req, res) => {
  const { tenantId } = req.params;
  try {
    if (!isUuid(tenantId)) return res.status(400).json({ error: 'tenantId inválido' });

    const tenantRes = await pool.query(
      `SELECT id, name, slug, plan, subscription_status, trial_ends_at, mercadopago_preapproval_id, next_billing_date, created_at
       FROM tenants WHERE id = $1`,
      [tenantId]
    );
    const tenant = tenantRes.rows[0];
    if (!tenant) return res.status(404).json({ error: 'Tenant no encontrado' });

    const usersRes = await pool.query(
      `SELECT u.id, u.email, u.name, u.is_active, u.last_login, u.created_at,
              r.name AS role_name
       FROM users u
       LEFT JOIN roles r ON r.id = u.role_id
       WHERE u.tenant_id = $1
       ORDER BY u.created_at DESC`,
      [tenantId]
    );

    return res.json({
      ...tenant,
      subscriptionStatus: tenant.subscription_status,
      trialEndsAt: tenant.trial_ends_at,
      nextBillingDate: tenant.next_billing_date,
      mercadoPagoPreapprovalId: tenant.mercadopago_preapproval_id,
      users: usersRes.rows,
    });
  } catch (error) {
    console.error('admin tenant detail error:', error);
    return res.status(500).json({ error: 'failed' });
  }
});

// Resumen de todos los tenants con conteo de usuarios (admin global dashboard)
app.get('/api/admin/dashboard', requireGlobalAdmin, async (_req, res) => {
  try {
    const tenantsRes = await pool.query(`
      SELECT t.id, t.name, t.slug, t.plan, t.subscription_status, t.trial_ends_at,
             t.mercadopago_preapproval_id, t.next_billing_date, t.created_at,
             COUNT(u.id)::int AS user_count
      FROM tenants t
      LEFT JOIN users u ON u.tenant_id = t.id AND u.is_active = true
      GROUP BY t.id
      ORDER BY t.created_at DESC
    `);

    const totals = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM tenants)::int AS total_tenants,
        (SELECT COUNT(*) FROM tenants WHERE subscription_status = 'TRIAL')::int AS trial_tenants,
        (SELECT COUNT(*) FROM tenants WHERE subscription_status = 'ACTIVE')::int AS active_tenants,
        (SELECT COUNT(*) FROM users WHERE is_active = true)::int AS total_users
    `);

    return res.json({
      tenants: tenantsRes.rows.map(t => ({
        ...t,
        subscriptionStatus: t.subscription_status,
        trialEndsAt: t.trial_ends_at,
        nextBillingDate: t.next_billing_date,
        mercadoPagoPreapprovalId: t.mercadopago_preapproval_id,
        userCount: t.user_count,
      })),
      totals: totals.rows[0],
    });
  } catch (error) {
    console.error('admin dashboard error:', error);
    return res.status(500).json({ error: 'failed' });
  }
});

// Modificar trial de un tenant (admin global)
app.patch('/api/admin/tenants/:tenantId/trial', requireGlobalAdmin, async (req, res) => {
  const { tenantId } = req.params;
  const { action, days } = req.body || {};
  try {
    if (!isUuid(tenantId)) return res.status(400).json({ error: 'tenantId inválido' });

    const tenantRes = await pool.query('SELECT * FROM tenants WHERE id = $1', [tenantId]);
    const tenant = tenantRes.rows[0];
    if (!tenant) return res.status(404).json({ error: 'Tenant no encontrado' });

    if (action === 'extend') {
      // Extender trial: agregar días a partir de ahora o de trial_ends_at si aún es futuro
      const daysToAdd = parseInt(days, 10);
      if (!daysToAdd || daysToAdd < 1 || daysToAdd > 365) {
        return res.status(400).json({ error: 'days debe ser entre 1 y 365' });
      }

      const baseDate = tenant.trial_ends_at && new Date(tenant.trial_ends_at) > new Date()
        ? tenant.trial_ends_at
        : new Date();

      await pool.query(
        `UPDATE tenants SET 
           subscription_status = 'TRIAL',
           trial_ends_at = $2::timestamp + ($3 || ' days')::interval
         WHERE id = $1`,
        [tenantId, baseDate, daysToAdd]
      );

      const updated = await pool.query('SELECT * FROM tenants WHERE id = $1', [tenantId]);
      return res.json({ ok: true, message: `Trial extendido ${daysToAdd} días`, tenant: updated.rows[0] });

    } else if (action === 'end') {
      // Terminar trial inmediatamente
      await pool.query(
        `UPDATE tenants SET subscription_status = 'INACTIVE', trial_ends_at = NOW() WHERE id = $1`,
        [tenantId]
      );

      // Registrar fin de trial en historial
      const usersRes = await pool.query('SELECT email FROM users WHERE tenant_id = $1', [tenantId]);
      for (const u of usersRes.rows) {
        await pool.query(
          `INSERT INTO trial_history (email, tenant_id, started_at, ended_at, reason)
           VALUES ($1, $2, COALESCE($3, NOW()), NOW(), 'admin_ended')
           ON CONFLICT (email) DO UPDATE SET ended_at = NOW(), reason = 'admin_ended'`,
          [u.email.toLowerCase(), tenantId, tenant.created_at]
        );
      }

      return res.json({ ok: true, message: 'Trial terminado' });

    } else if (action === 'set') {
      // Establecer fecha exacta de fin de trial
      const newEndDate = new Date(days);
      if (isNaN(newEndDate.getTime())) {
        return res.status(400).json({ error: 'Fecha inválida. Usar formato ISO (YYYY-MM-DD)' });
      }

      await pool.query(
        `UPDATE tenants SET subscription_status = 'TRIAL', trial_ends_at = $2 WHERE id = $1`,
        [tenantId, newEndDate]
      );

      const updated = await pool.query('SELECT * FROM tenants WHERE id = $1', [tenantId]);
      return res.json({ ok: true, message: `Trial establecido hasta ${newEndDate.toISOString()}`, tenant: updated.rows[0] });

    } else {
      return res.status(400).json({ error: 'action debe ser: extend, end, o set' });
    }
  } catch (error) {
    console.error('admin trial modify error:', error);
    return res.status(500).json({ error: 'failed' });
  }
});

// ==========================================
// TENANT-SCOPED: USERS & ROLES
// ==========================================

// Listar usuarios del tenant (incluye el admin)
app.get('/api/tenants/:tenantId/users', requireAuth, requireTenantAccess, async (req, res) => {
  const { tenantId } = req.params;
  try {
    const r = await pool.query(
      `SELECT u.id, u.tenant_id, u.email, u.name, u.role_id, u.is_active, u.last_login, u.created_at,
              r.name AS role_name, r.permissions
       FROM users u
       LEFT JOIN roles r ON r.id = u.role_id
       WHERE u.tenant_id = $1
       ORDER BY u.created_at ASC`,
      [tenantId]
    );
    return res.json(r.rows.map(u => ({
      id: u.id,
      tenantId: u.tenant_id,
      email: u.email,
      name: u.name,
      roleId: u.role_id,
      roleName: u.role_name,
      permissions: u.permissions || [],
      isActive: u.is_active,
      lastLogin: u.last_login,
      createdAt: u.created_at,
    })));
  } catch (error) {
    console.error('list users error:', error);
    return res.status(500).json({ error: 'failed' });
  }
});

// Crear nuevo usuario en el tenant
app.post('/api/tenants/:tenantId/users', requireAuth, requireTenantAccess, requirePermission('users.manage'), async (req, res) => {
  const { tenantId } = req.params;
  const { name, email, password, roleId } = req.body || {};
  try {
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'name/email/password requeridos' });
    }
    if (typeof password !== 'string' || password.length < 8) {
      return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres' });
    }

    // Verificar límite de usuarios
    const countRes = await pool.query(
      'SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND is_active = true',
      [tenantId]
    );
    const tenantRes = await pool.query('SELECT plan FROM tenants WHERE id = $1', [tenantId]);
    const plan = tenantRes.rows[0]?.plan || 'BASIC';
    const limits = { BASIC: 1, PRO: 5, ENTERPRISE: 999 };
    const userLimit = limits[plan] || 1;
    if (parseInt(countRes.rows[0].count, 10) >= userLimit) {
      return res.status(403).json({ error: `Límite de usuarios alcanzado (${userLimit})` });
    }

    // Verificar email único
    const existing = await pool.query('SELECT 1 FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'El email ya está registrado' });
    }

    const passwordHash = await hashPassword(password);
    const r = await pool.query(
      `INSERT INTO users (tenant_id, email, password_hash, name, role_id, is_active)
       VALUES ($1, $2, $3, $4, $5, TRUE)
       RETURNING id, tenant_id, email, name, role_id, is_active, created_at`,
      [tenantId, email, passwordHash, name, roleId || null]
    );
    return res.status(201).json(r.rows[0]);
  } catch (error) {
    console.error('create user error:', error);
    return res.status(500).json({ error: 'failed' });
  }
});

// Actualizar usuario (nombre, rol, estado)
app.put('/api/tenants/:tenantId/users/:userId', requireAuth, requireTenantAccess, requirePermission('users.manage'), async (req, res) => {
  const { tenantId, userId } = req.params;
  const { name, roleId, isActive } = req.body || {};
  try {
    if (!isUuid(userId)) return res.status(400).json({ error: 'userId inválido' });

    const updates = [];
    const values = [tenantId, userId];
    let idx = 3;

    if (name !== undefined) { updates.push(`name = $${idx++}`); values.push(name); }
    if (roleId !== undefined) { updates.push(`role_id = $${idx++}`); values.push(roleId); }
    if (isActive !== undefined) { updates.push(`is_active = $${idx++}`); values.push(isActive); }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'Nada que actualizar' });
    }

    const r = await pool.query(
      `UPDATE users SET ${updates.join(', ')} WHERE tenant_id = $1 AND id = $2
       RETURNING id, tenant_id, email, name, role_id, is_active, created_at`,
      values
    );
    if (r.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
    return res.json(r.rows[0]);
  } catch (error) {
    console.error('update user error:', error);
    return res.status(500).json({ error: 'failed' });
  }
});

// Cambiar contraseña de usuario (admin del tenant o el propio usuario)
app.patch('/api/tenants/:tenantId/users/:userId/password', requireAuth, requireTenantAccess, async (req, res) => {
  const { tenantId, userId } = req.params;
  const { newPassword, currentPassword } = req.body || {};
  try {
    if (!isUuid(userId)) return res.status(400).json({ error: 'userId inválido' });
    if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 8) {
      return res.status(400).json({ error: 'newPassword debe tener al menos 8 caracteres' });
    }

    // Verificar permisos: solo el propio usuario o alguien con users.manage
    const isSelf = req.auth.sub === userId;
    const hasPermission = (req.auth.permissions || []).includes('users.manage');

    if (!isSelf && !hasPermission) {
      return res.status(403).json({ error: 'No tenés permiso para cambiar esta contraseña' });
    }

    // Si es el propio usuario, verificar contraseña actual
    if (isSelf && currentPassword) {
      const userRes = await pool.query('SELECT password_hash FROM users WHERE id = $1 AND tenant_id = $2', [userId, tenantId]);
      if (userRes.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
      const valid = await verifyPassword(currentPassword, userRes.rows[0].password_hash);
      if (!valid) return res.status(401).json({ error: 'Contraseña actual incorrecta' });
    }

    const passwordHash = await hashPassword(newPassword);
    await pool.query(
      'UPDATE users SET password_hash = $1 WHERE id = $2 AND tenant_id = $3',
      [passwordHash, userId, tenantId]
    );

    return res.json({ ok: true, message: 'Contraseña actualizada' });
  } catch (error) {
    console.error('change password error:', error);
    return res.status(500).json({ error: 'failed' });
  }
});

// Eliminar usuario (soft delete)
app.delete('/api/tenants/:tenantId/users/:userId', requireAuth, requireTenantAccess, requirePermission('users.manage'), async (req, res) => {
  const { tenantId, userId } = req.params;
  try {
    if (!isUuid(userId)) return res.status(400).json({ error: 'userId inválido' });

    // No permitir auto-eliminación
    if (req.auth.sub === userId) {
      return res.status(400).json({ error: 'No podés eliminarte a vos mismo' });
    }

    await pool.query(
      'UPDATE users SET is_active = false WHERE id = $1 AND tenant_id = $2',
      [userId, tenantId]
    );
    return res.json({ ok: true, message: 'Usuario desactivado' });
  } catch (error) {
    console.error('delete user error:', error);
    return res.status(500).json({ error: 'failed' });
  }
});

app.get('/api/tenants/:tenantId/roles', requireAuth, requireTenantAccess, async (req, res) => {
  const { tenantId } = req.params;
  const r = await pool.query(
    `SELECT id, tenant_id, name, permissions, created_at
     FROM roles WHERE tenant_id = $1 ORDER BY name ASC`,
    [tenantId]
  );
  return res.json(r.rows);
});

app.post('/api/tenants/:tenantId/roles', requireAuth, requireTenantAccess, requirePermission('roles.manage'), async (req, res) => {
  const { tenantId } = req.params;
  const { name, permissions } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name requerido' });
  const perms = Array.isArray(permissions) ? permissions : [];
  const r = await pool.query(
    `INSERT INTO roles (tenant_id, name, permissions)
     VALUES ($1, $2, $3)
     RETURNING id, tenant_id, name, permissions, created_at`,
    [tenantId, name, perms]
  );
  return res.status(201).json(r.rows[0]);
});

app.put('/api/tenants/:tenantId/roles/:roleId', requireAuth, requireTenantAccess, requirePermission('roles.manage'), async (req, res) => {
  const { tenantId, roleId } = req.params;
  const { name, permissions } = req.body || {};
  const perms = Array.isArray(permissions) ? permissions : undefined;

  const r = await pool.query(
    `UPDATE roles SET
       name = COALESCE($3, name),
       permissions = COALESCE($4, permissions)
     WHERE id = $1 AND tenant_id = $2
     RETURNING id, tenant_id, name, permissions, created_at`,
    [roleId, tenantId, name || null, perms || null]
  );
  if (!r.rows[0]) return res.status(404).json({ error: 'Role not found' });
  return res.json(r.rows[0]);
});

app.delete('/api/tenants/:tenantId/roles/:roleId', requireAuth, requireTenantAccess, requirePermission('roles.manage'), async (req, res) => {
  const { tenantId, roleId } = req.params;
  // Evitar borrar el rol Administrador
  const role = await pool.query('SELECT name FROM roles WHERE id = $1 AND tenant_id = $2', [roleId, tenantId]);
  if (!role.rows[0]) return res.status(404).json({ error: 'Role not found' });
  if (role.rows[0].name === 'Administrador') return res.status(400).json({ error: 'No se puede eliminar el rol Administrador' });

  // Validar que no haya usuarios activos
  const usersWithRole = await pool.query(
    `SELECT COUNT(*)::int AS c FROM users WHERE tenant_id = $1 AND role_id = $2 AND is_active = true`,
    [tenantId, roleId]
  );
  if ((usersWithRole.rows[0]?.c || 0) > 0) return res.status(400).json({ error: 'Hay usuarios activos con este rol' });

  await pool.query('DELETE FROM roles WHERE id = $1 AND tenant_id = $2', [roleId, tenantId]);
  return res.json({ ok: true });
});

app.get('/api/tenants/:tenantId/users', requireAuth, requireTenantAccess, requirePermission('users.view'), async (req, res) => {
  const { tenantId } = req.params;
  const r = await pool.query(
    `SELECT id, tenant_id, email, name, role_id, is_active, last_login, created_at
     FROM users WHERE tenant_id = $1
     ORDER BY created_at DESC`,
    [tenantId]
  );
  return res.json(r.rows);
});

app.post('/api/tenants/:tenantId/users', requireAuth, requireTenantAccess, requirePermission('users.manage'), async (req, res) => {
  const { tenantId } = req.params;
  const { email, password, name, roleId } = req.body || {};
  if (!email || !password || !name || !roleId) return res.status(400).json({ error: 'email/password/name/roleId requeridos' });

  const passwordHash = await hashPassword(password);
  const created = await pool.query(
    `INSERT INTO users (tenant_id, email, password_hash, name, role_id, is_active)
     VALUES ($1, $2, $3, $4, $5, TRUE)
     RETURNING id, tenant_id, email, name, role_id, is_active, created_at`,
    [tenantId, email, passwordHash, name, roleId]
  );
  return res.status(201).json(created.rows[0]);
});

app.put('/api/tenants/:tenantId/users/:userId', requireAuth, requireTenantAccess, requirePermission('users.manage'), async (req, res) => {
  const { tenantId, userId } = req.params;
  const { name, roleId, isActive } = req.body || {};

  const r = await pool.query(
    `UPDATE users SET
       name = COALESCE($3, name),
       role_id = COALESCE($4, role_id),
       is_active = COALESCE($5, is_active)
     WHERE id = $1 AND tenant_id = $2
     RETURNING id, tenant_id, email, name, role_id, is_active, last_login, created_at`,
    [userId, tenantId, name || null, roleId || null, typeof isActive === 'boolean' ? isActive : null]
  );
  if (!r.rows[0]) return res.status(404).json({ error: 'User not found' });
  return res.json(r.rows[0]);
});

app.delete('/api/tenants/:tenantId/users/:userId', requireAuth, requireTenantAccess, requirePermission('users.manage'), async (req, res) => {
  const { tenantId, userId } = req.params;

  // Evitar dar de baja al último admin activo
  const adminRole = await pool.query(
    `SELECT id FROM roles WHERE tenant_id = $1 AND name = 'Administrador' LIMIT 1`,
    [tenantId]
  );
  const adminRoleId = adminRole.rows[0]?.id;

  if (adminRoleId) {
    const target = await pool.query(
      `SELECT role_id, is_active FROM users WHERE id = $1 AND tenant_id = $2`,
      [userId, tenantId]
    );
    if (target.rows[0]?.role_id === adminRoleId && target.rows[0]?.is_active) {
      const adminCount = await pool.query(
        `SELECT COUNT(*)::int AS c FROM users WHERE tenant_id = $1 AND role_id = $2 AND is_active = true`,
        [tenantId, adminRoleId]
      );
      if ((adminCount.rows[0]?.c || 0) <= 1) {
        return res.status(400).json({ error: 'No puedes desactivar al único Administrador del tenant' });
      }
    }
  }

  await pool.query(
    `UPDATE users SET is_active = false WHERE id = $1 AND tenant_id = $2`,
    [userId, tenantId]
  );
  return res.json({ ok: true });
});

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
        trial_ends_at = NULL,
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
    `SELECT id, name, slug, plan, subscription_status, trial_ends_at, mercadopago_preapproval_id, next_billing_date, created_at
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

const TENANT_SCOPED_TABLES = new Set([
  'users', 'roles', 'products', 'categories', 'tables', 'orders', 'shifts', 'audit_logs', 'billing_history'
]);

const resolveTenantIdForRequest = (req) => {
  if (req.auth?.scope === 'tenant') return req.auth.tenantId;
  // global admin puede operar un tenant específico explicitándolo
  const t = req.query?.tenantId || req.body?.tenantId || req.body?.tenant_id;
  return typeof t === 'string' ? t : undefined;
};


// --- MERCADO PAGO ROUTES ---

app.post('/api/subscriptions', requireAuth, async (req, res) => {
  const { tenantId, planId, price, email, backUrl } = req.body;
  console.log('--- NEW SUBSCRIPTION REQUEST ---');
  console.log('Data:', { tenantId, planId, price, email, backUrl });

  try {
    // Clientes nunca son global admins: este endpoint es de la app tenant.
    if (req.auth?.scope !== 'tenant') {
      return res.status(403).json({ error: 'Solo usuarios tenant pueden iniciar suscripción' });
    }
    if (tenantId && req.auth.tenantId !== tenantId) {
      return res.status(403).json({ error: 'tenantId no coincide con tu sesión' });
    }

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

    // Si el cliente paga, se convierte en Tenant Admin dentro de su tenant.
    try {
      await seedDefaultRolesForTenant(tenantId);
      const adminRoleId = await getTenantAdminRoleId(tenantId);
      if (adminRoleId) {
        await pool.query(
          `UPDATE users SET role_id = $1 WHERE id = $2 AND tenant_id = $3`,
          [adminRoleId, req.auth.sub, tenantId]
        );
      }
    } catch (e) {
      console.warn('No se pudo promover a tenant admin (continúa):', e?.message || e);
    }

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
          `SELECT id, name, slug, plan, subscription_status, trial_ends_at, mercadopago_preapproval_id, next_billing_date, created_at
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

    if (ENFORCE_AUTH) {
      if (!req.auth) return res.status(401).json({ error: 'Auth requerida' });
    }

    let query = `SELECT * FROM ${resource}`;
    const params = [];

    const resolvedTenantId = ENFORCE_AUTH ? resolveTenantIdForRequest(req) : (typeof tenantId === 'string' ? tenantId : undefined);

    if (resource === 'tenants') {
      if (ENFORCE_AUTH) {
        if (req.auth?.scope === 'global') {
          // global: puede listar todos
        } else {
          // tenant user: solo su tenant
          query += ` WHERE id = $1`;
          params.push(req.auth.tenantId);
        }
      }
    } else if (resource === 'order_items') {
      // order_items no tiene tenant_id: filtrar vía orders.tenant_id
      if (!resolvedTenantId) return res.status(400).json({ error: 'tenantId requerido' });
      query = `SELECT oi.*
               FROM order_items oi
               JOIN orders o ON oi.order_id = o.id
               WHERE o.tenant_id = $1`;
      params.push(resolvedTenantId);
    } else if (TENANT_SCOPED_TABLES.has(resource)) {
      if (!resolvedTenantId) return res.status(400).json({ error: 'tenantId requerido' });
      query += ` WHERE tenant_id = $1`;
      params.push(resolvedTenantId);
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

    if (ENFORCE_AUTH) {
      if (!req.auth) return res.status(401).json({ error: 'Auth requerida' });
      if (resource === 'tenants' && req.auth.scope !== 'global') {
        return res.status(403).json({ error: 'Solo admin global puede crear tenants' });
      }
    }

    // Forzar tenant_id en tablas tenant-scoped
    if (TENANT_SCOPED_TABLES.has(resource)) {
      const resolvedTenantId = resolveTenantIdForRequest(req);
      if (!resolvedTenantId) return res.status(400).json({ error: 'tenantId requerido' });
      data.tenant_id = resolvedTenantId;
      // No permitir crear roles/users fuera del ámbito usando la ruta genérica en modo enforce
      if (ENFORCE_AUTH && (resource === 'users' || resource === 'roles')) {
        return res.status(400).json({ error: 'Usa /api/tenants/:tenantId/users o /api/tenants/:tenantId/roles' });
      }
    }

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

    if (ENFORCE_AUTH) {
      if (!req.auth) return res.status(401).json({ error: 'Auth requerida' });
      if (resource === 'tenants' && req.auth.scope !== 'global') {
        return res.status(403).json({ error: 'Solo admin global puede editar tenants' });
      }
      if (resource === 'users' || resource === 'roles') {
        return res.status(400).json({ error: 'Usa /api/tenants/:tenantId/users o /api/tenants/:tenantId/roles' });
      }
    }

    const keys = Object.keys(data);
    if (keys.length === 0) return res.status(400).json({ error: 'No hay campos para actualizar' });

    const tenantScoped = TENANT_SCOPED_TABLES.has(resource);
    const resolvedTenantId = tenantScoped ? resolveTenantIdForRequest(req) : undefined;
    if (tenantScoped && !resolvedTenantId) return res.status(400).json({ error: 'tenantId requerido' });

    const updates = keys.map((key, i) => `${key} = $${i + 2}`).join(', ');
    const values = [id, ...Object.values(data)];

    const query = tenantScoped
      ? `UPDATE ${resource} SET ${updates} WHERE id = $1 AND tenant_id = $${values.length + 1} RETURNING *`
      : `UPDATE ${resource} SET ${updates} WHERE id = $1 RETURNING *`;

    if (tenantScoped) values.push(resolvedTenantId);
    const result = await pool.query(query, values);

    if (!result.rows[0]) return res.status(404).json({ error: 'Not found' });
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

    if (ENFORCE_AUTH) {
      if (!req.auth) return res.status(401).json({ error: 'Auth requerida' });
      if (resource === 'tenants' && req.auth.scope !== 'global') {
        return res.status(403).json({ error: 'Solo admin global puede eliminar tenants' });
      }
      if (resource === 'users' || resource === 'roles') {
        return res.status(400).json({ error: 'Usa /api/tenants/:tenantId/users o /api/tenants/:tenantId/roles' });
      }
    }

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
    if (TENANT_SCOPED_TABLES.has(resource)) {
      const resolvedTenantId = ENFORCE_AUTH ? resolveTenantIdForRequest(req) : (typeof tenantId === 'string' ? tenantId : undefined);
      if (!resolvedTenantId) return res.status(400).json({ error: 'tenantId requerido' });
      await pool.query(`DELETE FROM ${resource} WHERE id = $1 AND tenant_id = $2`, [id, resolvedTenantId]);
      return res.json({ success: true });
    }

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
    }

    if (tenant.subscription_status === 'TRIAL') {
      const trialEndsAt = tenant.trial_ends_at ? new Date(tenant.trial_ends_at) : null;
      const isTrialActive = !trialEndsAt || trialEndsAt.getTime() > Date.now();
      return res.json({ valid: isTrialActive, plan: tenant.plan, status: isTrialActive ? 'TRIAL' : 'INACTIVE' });
    }

    return res.json({ valid: false, status: tenant.subscription_status, message: 'Subscription inactive' });
  } catch (error) {
    res.status(500).json({ error: 'Verification failed' });
  }
});

// Obtener un tenant por ID (para refrescar estado en frontend)
app.get('/api/tenants/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  try {
    if (!isUuid(id)) return res.status(400).json({ error: 'tenantId inválido (UUID requerido)' });

    if (req.auth.scope !== 'global' && req.auth.tenantId !== id) {
      return res.status(403).json({ error: 'Acceso denegado al tenant' });
    }

    const result = await pool.query(
      `SELECT id, name, slug, plan, subscription_status, trial_ends_at, mercadopago_preapproval_id, next_billing_date, created_at, settings
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
      trialEndsAt: row.trial_ends_at ? new Date(row.trial_ends_at).toISOString() : undefined,
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

// Obtener un tenant por ID (ámbito APP tenant) - separación de endpoints
app.get('/api/app/tenants/:id', requireTenantUser, async (req, res) => {
  const { id } = req.params;
  try {
    if (!isUuid(id)) return res.status(400).json({ error: 'tenantId inválido (UUID requerido)' });
    if (req.auth.tenantId !== id) return res.status(403).json({ error: 'Acceso denegado al tenant' });

    const result = await pool.query(
      `SELECT id, name, slug, plan, subscription_status, trial_ends_at, mercadopago_preapproval_id, next_billing_date, created_at, settings
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
      trialEndsAt: row.trial_ends_at ? new Date(row.trial_ends_at).toISOString() : undefined,
      mercadoPagoPreapprovalId: row.mercadopago_preapproval_id || undefined,
      nextBillingDate: row.next_billing_date ? new Date(row.next_billing_date).toISOString() : undefined,
      createdAt: row.created_at ? new Date(row.created_at).toISOString() : new Date().toISOString(),
      settings: row.settings || {},
    });
  } catch (error) {
    console.error('Error fetching tenant (app):', error);
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

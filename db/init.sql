-- ====================================
-- GastroFlow SaaS - Schema PostgreSQL
-- Ejecutar en EasyPanel > PostgreSQL > Terminal
-- ====================================

-- Habilitar UUIDs
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ====================================
-- 1. TENANTS (Multi-tenancy / SaaS Isolation)
-- ====================================
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE,
    plan VARCHAR(50) DEFAULT 'BASIC', -- 'BASIC', 'PRO', 'ENTERPRISE'
    subscription_status VARCHAR(50) DEFAULT 'TRIAL', -- 'TRIAL', 'ACTIVE', 'PAST_DUE', 'CANCELED', 'INACTIVE'
    mercadopago_preapproval_id VARCHAR(255),
    next_billing_date TIMESTAMP,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ====================================
-- 2. ROLES & USERS (RBAC)
-- ====================================
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    permissions TEXT[], -- Array: ['tables.view', 'kitchen.manage', ...]
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255),
    name VARCHAR(255) NOT NULL,
    role_id UUID REFERENCES roles(id),
    is_active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(tenant_id, email)
);

-- ====================================
-- 3. CATALOG (Categories & Products)
-- ====================================
CREATE TABLE IF NOT EXISTS categories (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    sort_order INT DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS products (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    category_id UUID REFERENCES categories(id) ON DELETE SET NULL,
    sku VARCHAR(50),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    price DECIMAL(10,2) NOT NULL DEFAULT 0,
    cost DECIMAL(10,2) DEFAULT 0,
    stock_enabled BOOLEAN DEFAULT FALSE,
    stock_quantity INT DEFAULT 0,
    stock_min INT DEFAULT 5,
    is_active BOOLEAN DEFAULT TRUE,
    image_url TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- ====================================
-- 4. OPERATIONS (Tables & Orders)
-- ====================================
CREATE TABLE IF NOT EXISTS tables (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    number VARCHAR(20) NOT NULL,
    capacity INT DEFAULT 4,
    zone VARCHAR(50) DEFAULT 'Interior', -- 'Interior', 'Exterior', 'Terraza'
    status VARCHAR(20) DEFAULT 'AVAILABLE', -- 'AVAILABLE', 'OCCUPIED', 'RESERVED'
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS orders (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    table_id UUID REFERENCES tables(id),
    status VARCHAR(20) DEFAULT 'OPEN', -- 'OPEN', 'PAID', 'CANCELLED'
    total DECIMAL(10,2) DEFAULT 0,
    payment_method VARCHAR(20), -- 'CASH', 'CARD', 'TRANSFER'
    opened_at TIMESTAMP DEFAULT NOW(),
    closed_at TIMESTAMP,
    closed_by UUID REFERENCES users(id),
    notes TEXT
);

CREATE TABLE IF NOT EXISTS order_items (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    order_id UUID REFERENCES orders(id) ON DELETE CASCADE,
    product_id UUID REFERENCES products(id),
    product_name VARCHAR(255), -- Snapshot del nombre al momento de la orden
    quantity INT NOT NULL DEFAULT 1,
    price_at_moment DECIMAL(10,2) NOT NULL,
    status VARCHAR(20) DEFAULT 'PENDING', -- 'PENDING', 'PREPARING', 'READY', 'DELIVERED'
    sent_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

-- ====================================
-- 5. SHIFTS (Cash Control)
-- ====================================
CREATE TABLE IF NOT EXISTS shifts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id),
    opened_at TIMESTAMP DEFAULT NOW(),
    closed_at TIMESTAMP,
    starting_cash DECIMAL(10,2) DEFAULT 0,
    final_cash DECIMAL(10,2),
    expected_cash DECIMAL(10,2),
    cash_difference DECIMAL(10,2),
    total_sales DECIMAL(10,2) DEFAULT 0,
    total_orders INT DEFAULT 0,
    notes TEXT
);

-- ====================================
-- 6. AUDIT LOGS
-- ====================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id),
    user_name VARCHAR(255),
    action VARCHAR(100) NOT NULL, -- 'CREATE', 'UPDATE', 'DELETE', 'LOGIN', 'CLOSE_SHIFT'
    entity_type VARCHAR(50), -- 'product', 'order', 'table', 'user'
    entity_id UUID,
    payload JSONB,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT NOW()
);

-- ====================================
-- 7. BILLING HISTORY (SaaS)
-- ====================================
CREATE TABLE IF NOT EXISTS billing_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    amount DECIMAL(10,2) NOT NULL,
    currency VARCHAR(3) DEFAULT 'ARS',
    status VARCHAR(50) DEFAULT 'paid', -- 'paid', 'pending', 'failed'
    payment_id VARCHAR(255),
    mp_subscription_id VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW(),
    description VARCHAR(255),
    invoice_url VARCHAR(500)
);

CREATE INDEX IF NOT EXISTS idx_billing_tenant ON billing_history(tenant_id);
CREATE INDEX IF NOT EXISTS idx_billing_date ON billing_history(created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS ux_billing_mp_subscription_id ON billing_history(mp_subscription_id);

-- ====================================
-- 8. INDEXES (Performance)
-- ====================================
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_products_tenant ON products(tenant_id);
CREATE INDEX IF NOT EXISTS idx_products_category ON products(category_id);
CREATE INDEX IF NOT EXISTS idx_orders_tenant ON orders(tenant_id);
CREATE INDEX IF NOT EXISTS idx_orders_table ON orders(table_id);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
CREATE INDEX IF NOT EXISTS idx_order_items_order ON order_items(order_id);
CREATE INDEX IF NOT EXISTS idx_order_items_status ON order_items(status);
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_logs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(created_at DESC);

-- ====================================
-- 8. DEFAULT DATA (Opcional)
-- ====================================

-- Crear tenant de demo (Opcional - comentar en producción real)
-- INSERT INTO tenants (id, name, slug, plan, subscription_status) 
-- VALUES ('00000000-0000-0000-0000-000000000001', 'Demo Restaurant', 'demo', 'PRO', 'ACTIVE')
-- ON CONFLICT DO NOTHING;

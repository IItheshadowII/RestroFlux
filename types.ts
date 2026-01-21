
export enum SubscriptionStatus {
  TRIAL = 'TRIAL',
  ACTIVE = 'ACTIVE',
  PAST_DUE = 'PAST_DUE',
  CANCELED = 'CANCELED',
  INACTIVE = 'INACTIVE'
}

export enum PlanTier {
  BASIC = 'BASIC',
  PRO = 'PRO',
  ENTERPRISE = 'ENTERPRISE'
}

export interface TenantSettings {
  geminiApiKey?: string;
  geminiModel?: string;
}

export interface Tenant {
  id: string;
  name: string;
  slug: string;
  plan: PlanTier;
  subscriptionStatus: SubscriptionStatus;
  mercadoPagoPreapprovalId?: string;
  nextBillingDate?: string;
  createdAt: string;
  settings?: TenantSettings;
}

export interface User {
  id: string;
  tenantId: string;
  email: string;
  name: string;
  roleId: string;
  isActive: boolean;
  lastLogin?: string;
  permissions?: string[];
}

export interface Role {
  id: string;
  tenantId: string;
  name: string;
  permissions: string[];
}

export interface Category {
  id: string;
  tenantId: string;
  name: string;
  order: number;
}

export interface Product {
  id: string;
  tenantId: string;
  categoryId: string;
  name: string;
  description: string;
  price: number;
  cost?: number;
  sku?: string;
  stockEnabled: boolean;
  stockQuantity: number;
  stockMin: number;
  isActive: boolean;
  imageUrl?: string;
}

export interface Table {
  id: string;
  tenantId: string;
  number: string;
  capacity: number;
  zone: string;
  status: 'AVAILABLE' | 'OCCUPIED' | 'RESERVED';
  isActive: boolean;
}

export type OrderItemStatus = 'PENDING' | 'PREPARING' | 'READY' | 'DELIVERED';

export interface OrderItem {
  productId: string;
  name: string;
  quantity: number;
  price: number;
  status: OrderItemStatus;
  sentAt?: string;
}

export interface Order {
  id: string;
  tenantId: string;
  tableId: string;
  items: OrderItem[];
  status: 'OPEN' | 'PAID' | 'CANCELLED';
  total: number;
  paymentMethod?: 'CASH' | 'CARD' | 'TRANSFER';
  openedAt: string;
  closedAt?: string;
  closedBy?: string;
}

export interface Shift {
  id: string;
  tenantId: string;
  openedAt: string;
  closedAt?: string;
  openedBy: string;
  closedBy?: string;
  initialCash: number;
  finalCash?: number;
  totalSales: number;
  cashSales: number;
  cardSales: number;
  ordersCount: number;
  status: 'OPEN' | 'CLOSED';
}

export interface AuditLog {
  id: string;
  tenantId: string;
  userId: string;
  action: string;
  entityType: string;
  entityId: string;
  before: any;
  after: any;
  timestamp: string;
}

export interface PlanDetails {
  id: PlanTier;
  name: string;
  price: number;
  features: string[];
  limits: {
    users: number;
    tables: number;
    products: number;
  };
}


import { Tenant, User, Role, Category, Product, Table, AuditLog, PlanTier, SubscriptionStatus, Order, OrderItem, Shift, OrderItemStatus, TenantSettings } from '../types';
import { PLANS } from '../constants';
import { getEffectivePlan } from '../utils/subscription';

// Configuración de entorno
const env = (import.meta as any).env || {};
const APP_MODE = env.VITE_APP_MODE || 'LOCAL'; // 'LOCAL' or 'CLOUD'
const API_URL = env.VITE_API_URL || ''; // URL del backend en modo Cloud
const CLOUD_URL = env.VITE_CLOUD_URL || 'https://app.gastroflow.cloud'; // URL para verificar licencia en modo Local

// ==========================================
// API HELPER PARA MODO CLOUD
// ==========================================
class ApiClient {
  private baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  private async request<T>(endpoint: string, options?: RequestInit): Promise<T> {
    const token = localStorage.getItem('gastroflow_token');
    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
        ...options?.headers,
      },
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Request failed' }));
      throw new Error(error.error || `HTTP ${response.status}`);
    }

    return response.json();
  }

  async get<T>(endpoint: string): Promise<T> {
    return this.request<T>(endpoint, { method: 'GET' });
  }

  async post<T>(endpoint: string, data: any): Promise<T> {
    return this.request<T>(endpoint, { method: 'POST', body: JSON.stringify(data) });
  }

  async put<T>(endpoint: string, data: any): Promise<T> {
    return this.request<T>(endpoint, { method: 'PUT', body: JSON.stringify(data) });
  }

  async delete<T>(endpoint: string): Promise<T> {
    return this.request<T>(endpoint, { method: 'DELETE' });
  }
}

const apiClient = new ApiClient(API_URL || '/api');

const DEFAULT_ROLES = [
  {
    id: 'role-admin',
    name: 'Administrador',
    permissions: [
      'tables.view', 'tables.edit', 'tables.manage', 'kitchen.view', 'kitchen.manage',
      'cash.view', 'cash.manage', 'dashboard.view', 'reports.view',
      'menu.view', 'menu.edit', 'stock.view', 'stock.adjust',
      'users.view', 'users.manage', 'roles.manage', 'settings.manage', 'billing.manage'
    ]
  },
  {
    id: 'role-manager',
    name: 'Encargado',
    permissions: [
      'tables.view', 'tables.edit', 'kitchen.view', 'kitchen.manage',
      'cash.view', 'cash.manage', 'dashboard.view', 'reports.view',
      'menu.view', 'stock.view'
    ]
  },
  {
    id: 'role-kitchen',
    name: 'Cocina',
    permissions: [
      'kitchen.view', 'kitchen.manage', 'menu.view', 'stock.view'
    ]
  },
  {
    id: 'role-staff',
    name: 'Mozo',
    permissions: [
      'tables.view', 'tables.edit', 'menu.view'
    ]
  },
];

class DBService {
  // ==========================================
  // CORE DATA ACCESS (Hybrid Switch)
  // ==========================================

  private getLocalData<T>(key: string): T[] {
    const data = localStorage.getItem(`gastroflow_${key}`);
    return data ? JSON.parse(data) : [];
  }

  private setLocalData<T>(key: string, data: T[]): void {
    localStorage.setItem(`gastroflow_${key}`, JSON.stringify(data));
  }

  /**
   * Generic Query Method - HÍBRIDO
   * En modo CLOUD: Hace fetch al API
   * En modo LOCAL: Usa localStorage
   */
  query<T extends { tenantId: string }>(key: string, tenantId: string): T[] {
    // Modo LOCAL: Usar localStorage
    return this.getLocalData<T>(key).filter(item => item.tenantId === tenantId);
  }

  /**
   * Async Query para modo CLOUD
   */
  async queryAsync<T extends { tenantId: string }>(key: string, tenantId: string): Promise<T[]> {
    if (APP_MODE === 'CLOUD') {
      try {
        return await apiClient.get<T[]>(`/api/${key}?tenantId=${tenantId}`);
      } catch (error) {
        console.error(`Error fetching ${key}:`, error);
        // Fallback a localStorage si el API falla
        return this.getLocalData<T>(key).filter(item => item.tenantId === tenantId);
      }
    }
    return this.getLocalData<T>(key).filter(item => item.tenantId === tenantId);
  }

  getById<T extends { id: string; tenantId: string }>(key: string, id: string, tenantId: string): T | undefined {
    return this.getLocalData<T>(key).find(item => item.id === id && item.tenantId === tenantId);
  }

  async getByIdAsync<T extends { id: string; tenantId: string }>(key: string, id: string, tenantId: string): Promise<T | undefined> {
    if (APP_MODE === 'CLOUD') {
      try {
        const items = await apiClient.get<T[]>(`/api/${key}?tenantId=${tenantId}`);
        return items.find(item => item.id === id);
      } catch {
        return this.getById<T>(key, id, tenantId);
      }
    }
    return this.getById<T>(key, id, tenantId);
  }

  insert<T extends { id: string; tenantId: string }>(key: string, item: T): T {
    if (APP_MODE === 'CLOUD') {
      // Fire and forget en modo síncrono, pero también guardar localmente
      apiClient.post<T>(`/api/${key}`, item).catch(err => console.error('Insert failed:', err));
    }
    const items = this.getLocalData<T>(key);
    items.push(item);
    this.setLocalData(key, items);
    return item;
  }

  async insertAsync<T extends { id: string; tenantId: string }>(key: string, item: T): Promise<T> {
    if (APP_MODE === 'CLOUD') {
      try {
        const result = await apiClient.post<T>(`/api/${key}`, item);
        // También guardar localmente para cache
        const items = this.getLocalData<T>(key);
        items.push(result);
        this.setLocalData(key, items);
        return result;
      } catch (error) {
        console.error('Insert failed, saving locally:', error);
      }
    }
    const items = this.getLocalData<T>(key);
    items.push(item);
    this.setLocalData(key, items);
    return item;
  }

  update<T extends { id: string; tenantId: string }>(key: string, id: string, tenantId: string, updates: Partial<T>): T {
    if (APP_MODE === 'CLOUD') {
      // Fire and forget en modo síncrono
      apiClient.put<T>(`/api/${key}/${id}`, updates).catch(err => console.error('Update failed:', err));
    }
    const items = this.getLocalData<T>(key);
    const index = items.findIndex(i => i.id === id && i.tenantId === tenantId);
    if (index === -1) throw new Error('Item no encontrado');

    items[index] = { ...items[index], ...updates };
    this.setLocalData(key, items);
    return items[index];
  }

  async updateAsync<T extends { id: string; tenantId: string }>(key: string, id: string, tenantId: string, updates: Partial<T>): Promise<T> {
    if (APP_MODE === 'CLOUD') {
      try {
        const result = await apiClient.put<T>(`/api/${key}/${id}`, updates);
        // Actualizar cache local
        const items = this.getLocalData<T>(key);
        const index = items.findIndex(i => i.id === id && i.tenantId === tenantId);
        if (index !== -1) {
          items[index] = { ...items[index], ...result };
          this.setLocalData(key, items);
        }
        return result;
      } catch (error) {
        console.error('Update failed, updating locally:', error);
      }
    }
    return this.update<T>(key, id, tenantId, updates);
  }

  private _hardDelete(key: string, id: string, tenantId: string): void {
    if (APP_MODE === 'CLOUD') {
      apiClient.delete(`/api/${key}/${id}`).catch(err => console.error('Delete failed:', err));
    }
    const items = this.getLocalData<any>(key);
    const filtered = items.filter((i: any) => !(i.id === id && i.tenantId === tenantId));
    this.setLocalData(key, filtered);
  }

  // ==========================================
  // SPECIAL: ON-PREMISE LICENSE CHECK
  // ==========================================

  /**
   * Verifica la suscripción contra la nube.
   * Si es Cloud: Retorna true (ya estás en la nube).
   * Si es Local: Hace fetch a la URL central para validar estado.
   */
  async validateSubscription(tenantId: string): Promise<boolean> {
    if (APP_MODE === 'CLOUD') return true;

    try {
      console.log('Verificando licencia on-premise...');
      const licenseKey = env.VITE_LICENSE_KEY || '';
      const res = await fetch(`${CLOUD_URL}/api/license/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tenantId, licenseKey })
      });

      if (!res.ok) {
        console.warn('Licencia no válida o servidor no disponible');
        return false;
      }

      const data = await res.json();
      if (data.valid) {
        // Actualizar estado local con los datos de la nube
        const tenants = this.getLocalData<Tenant>('tenants');
        const index = tenants.findIndex(t => t.id === tenantId);
        if (index !== -1) {
          tenants[index] = {
            ...tenants[index],
            subscriptionStatus: data.status as SubscriptionStatus,
            plan: data.plan as PlanTier
          };
          this.setLocalData('tenants', tenants);
        }
        return true;
      }
      return false;
    } catch (e) {
      console.error("No se pudo verificar la licencia online", e);
      // En modo offline, dar un período de gracia (ej: 7 días sin conexión)
      const lastCheck = localStorage.getItem('gastroflow_last_license_check');
      if (lastCheck) {
        const daysSinceCheck = (Date.now() - parseInt(lastCheck)) / (1000 * 60 * 60 * 24);
        if (daysSinceCheck < 7) {
          console.log('Período de gracia offline activo');
          return true;
        }
      }
      return false;
    }
  }

  // ==========================================
  // BUSINESS LOGIC
  // ==========================================

  removeTable(tableId: string, tenantId: string): void {
    const orders = this.getLocalData<Order>('orders').filter(o => o.tableId === tableId && o.tenantId === tenantId);
    const hasOpenOrders = orders.some(o => o.status === 'OPEN');
    if (hasOpenOrders) throw new Error("No se puede eliminar una mesa con cuentas abiertas.");

    const hasHistory = orders.length > 0;
    if (hasHistory) {
      this.update<Table>('tables', tableId, tenantId, { isActive: false, status: 'AVAILABLE' });
    } else {
      this._hardDelete('tables', tableId, tenantId);
    }
  }

  removeProduct(productId: string, tenantId: string): void {
    const orders = this.getLocalData<Order>('orders').filter(o => o.tenantId === tenantId);
    const isInActiveOrder = orders.some(o => o.status === 'OPEN' && o.items.some(i => i.productId === productId));
    if (isInActiveOrder) throw new Error("El producto está presente en mesas activas.");

    const isInHistory = orders.some(o => o.items.some(i => i.productId === productId));
    if (isInHistory) {
      this.update<Product>('products', productId, tenantId, { isActive: false });
    } else {
      this._hardDelete('products', productId, tenantId);
    }
  }

  removeCategory(categoryId: string, tenantId: string): void {
    const products = this.getLocalData<Product>('products').filter(p => p.tenantId === tenantId && p.categoryId === categoryId);
    if (products.length > 0) throw new Error(`La categoría contiene ${products.length} productos.`);
    this._hardDelete('categories', categoryId, tenantId);
  }

  removeUser(userId: string, tenantId: string): void {
    const user = this.getById<User>('users', userId, tenantId);
    const role = this.getById<Role>('roles', user?.roleId || '', tenantId);
    if (role?.name === 'Administrador') {
      const allUsers = this.query<User>('users', tenantId).filter(u => u.isActive);
      const adminCount = allUsers.filter(u => {
        const r = this.getById<Role>('roles', u.roleId, tenantId);
        return r?.name === 'Administrador';
      }).length;
      if (adminCount <= 1) throw new Error("No puedes eliminar al único Administrador activo.");
    }
    this.update<User>('users', userId, tenantId, { isActive: false });
  }

  removeRole(roleId: string, tenantId: string): void {
    const role = this.getById<Role>('roles', roleId, tenantId);
    if (role?.name === 'Administrador') throw new Error("El rol Administrador es de sistema.");
    const users = this.query<User>('users', tenantId).filter(u => u.roleId === roleId && u.isActive);
    if (users.length > 0) throw new Error("Hay usuarios activos asignados a este rol.");
    this._hardDelete('roles', roleId, tenantId);
  }

  canAddUser(tenantId: string): boolean {
    const tenant = this.getTenant(tenantId);
    if (!tenant) return false;
    const currentActiveUsers = this.query<User>('users', tenantId).filter(u => u.isActive).length;
    const effectivePlan = getEffectivePlan(tenant);
    const limit = PLANS[effectivePlan].limits.users;
    return currentActiveUsers < limit;
  }

  private reconcileUsers(tenantId: string, newPlan: PlanTier) {
    const users = this.getLocalData<User>('users');
    const roles = this.getLocalData<Role>('roles');
    const tenantUsers = users.filter(u => u.tenantId === tenantId);
    const limit = PLANS[newPlan].limits.users;
    const activeUsers = tenantUsers.filter(u => u.isActive);

    if (activeUsers.length > limit) {
      const adminRoles = roles.filter(r => r.tenantId === tenantId && r.name === 'Administrador').map(r => r.id);
      const sortedUsers = [...activeUsers].sort((a, b) => {
        const aIsAdmin = adminRoles.includes(a.roleId);
        const bIsAdmin = adminRoles.includes(b.roleId);
        if (aIsAdmin && !bIsAdmin) return -1;
        if (!aIsAdmin && bIsAdmin) return 1;
        return 0;
      });
      const usersToKeep = sortedUsers.slice(0, limit).map(u => u.id);
      const updatedAllUsers = users.map(u => {
        if (u.tenantId === tenantId && u.isActive && !usersToKeep.includes(u.id)) {
          return { ...u, isActive: false };
        }
        return u;
      });
      this.setLocalData('users', updatedAllUsers);
    }
  }

  updateTenantSubscription(tenantId: string, updates: { plan?: PlanTier, status?: SubscriptionStatus, preapprovalId?: string }) {
    const tenants = this.getLocalData<Tenant>('tenants');
    const index = tenants.findIndex(t => t.id === tenantId);
    if (index === -1) throw new Error('Tenant not found');

    const oldPlan = tenants[index].plan;
    const newPlan = updates.plan ?? oldPlan;

    tenants[index] = {
      ...tenants[index],
      plan: newPlan,
      subscriptionStatus: updates.status ?? tenants[index].subscriptionStatus,
      mercadoPagoPreapprovalId: updates.preapprovalId ?? tenants[index].mercadoPagoPreapprovalId,
      nextBillingDate: (updates.status === SubscriptionStatus.ACTIVE || updates.status === SubscriptionStatus.TRIAL)
        ? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
        : tenants[index].nextBillingDate
    };

    this.setLocalData('tenants', tenants);

    if (newPlan !== oldPlan || updates.status === SubscriptionStatus.ACTIVE) {
      this.reconcileUsers(tenantId, newPlan);
    }
    return tenants[index];
  }

  updateTenantSettings(tenantId: string, settings: TenantSettings): Tenant {
    const tenants = this.getLocalData<Tenant>('tenants');
    const index = tenants.findIndex(t => t.id === tenantId);
    if (index === -1) throw new Error('Tenant not found');

    tenants[index] = {
      ...tenants[index],
      settings: { ...tenants[index].settings, ...settings }
    };

    this.setLocalData('tenants', tenants);
    return tenants[index];
  }

  getActiveOrderForTable(tableId: string, tenantId: string): Order | undefined {
    return this.getLocalData<Order>('orders').find(o => o.tableId === tableId && o.tenantId === tenantId && o.status === 'OPEN');
  }

  createOrder(tableId: string, tenantId: string): Order {
    const order: Order = {
      id: `ord-${Date.now()}`,
      tenantId,
      tableId,
      items: [],
      status: 'OPEN',
      total: 0,
      openedAt: new Date().toISOString()
    };
    return this.insert('orders', order);
  }

  addItemsToOrder(orderId: string, tenantId: string, newItems: Omit<OrderItem, 'status'>[]): Order {
    const order = this.getById<Order>('orders', orderId, tenantId);
    if (!order) throw new Error('Order not found');

    const updatedItems = [...order.items];
    newItems.forEach(newItem => {
      const existing = updatedItems.find(i => i.productId === newItem.productId && i.status === 'PENDING');
      if (existing) {
        existing.quantity += newItem.quantity;
      } else {
        updatedItems.push({ ...newItem, status: 'PENDING' });
      }
      this.adjustStock(newItem.productId, tenantId, 'system', -newItem.quantity, `Venta en mesa ${order.tableId}`);
    });

    const newTotal = updatedItems.reduce((acc, i) => acc + (i.price * i.quantity), 0);
    return this.update<Order>('orders', orderId, tenantId, { items: updatedItems, total: newTotal });
  }

  sendOrderToKitchen(orderId: string, tenantId: string): Order {
    const order = this.getById<Order>('orders', orderId, tenantId);
    if (!order) throw new Error('Order not found');
    const updatedItems = order.items.map(item => {
      if (item.status === 'PENDING') {
        return { ...item, status: 'PREPARING' as OrderItemStatus, sentAt: new Date().toISOString() };
      }
      return item;
    });
    return this.update<Order>('orders', orderId, tenantId, { items: updatedItems });
  }

  updateOrderItemStatus(orderId: string, productId: string, status: OrderItemStatus, tenantId: string): Order {
    const order = this.getById<Order>('orders', orderId, tenantId);
    if (!order) throw new Error('Order not found');
    const updatedItems = order.items.map(item => {
      if (item.productId === productId && item.status !== 'DELIVERED') {
        return { ...item, status };
      }
      return item;
    });
    return this.update<Order>('orders', orderId, tenantId, { items: updatedItems });
  }

  deliverReadyItems(orderId: string, tenantId: string): Order {
    const order = this.getById<Order>('orders', orderId, tenantId);
    if (!order) throw new Error('Order not found');
    const updatedItems = order.items.map(item => {
      if (item.status === 'READY') {
        return { ...item, status: 'DELIVERED' as OrderItemStatus };
      }
      return item;
    });
    return this.update<Order>('orders', orderId, tenantId, { items: updatedItems });
  }

  removeItemFromOrder(orderId: string, tenantId: string, productId: string): Order {
    const order = this.getById<Order>('orders', orderId, tenantId);
    if (!order) throw new Error('Order not found');
    const itemToRemove = order.items.find(i => i.productId === productId);
    if (!itemToRemove) return order;
    this.adjustStock(productId, tenantId, 'system', itemToRemove.quantity, `Cancelación item en mesa ${order.tableId}`);
    const updatedItems = order.items.filter(i => i.productId !== productId);
    const newTotal = updatedItems.reduce((acc, i) => acc + (i.price * i.quantity), 0);
    return this.update<Order>('orders', orderId, tenantId, { items: updatedItems, total: newTotal });
  }

  closeOrder(orderId: string, tenantId: string, userId: string, paymentMethod: any): Order {
    const order = this.getById<Order>('orders', orderId, tenantId);
    if (!order) throw new Error('Order not found');
    const finalizedItems = order.items.map(item => ({ ...item, status: 'DELIVERED' as OrderItemStatus }));
    const updated = this.update<Order>('orders', orderId, tenantId, {
      status: 'PAID', items: finalizedItems, paymentMethod, closedAt: new Date().toISOString(), closedBy: userId
    });
    this.update<Table>('tables', order.tableId, tenantId, { status: 'AVAILABLE' });
    return updated;
  }

  getActiveShift(tenantId: string): Shift | undefined {
    return this.getLocalData<Shift>('shifts').find(s => s.tenantId === tenantId && s.status === 'OPEN');
  }

  openShift(tenantId: string, userId: string, initialCash: number): Shift {
    const shift: Shift = {
      id: `shift-${Date.now()}`, tenantId, openedAt: new Date().toISOString(), openedBy: userId, initialCash,
      totalSales: 0, cashSales: 0, cardSales: 0, ordersCount: 0, status: 'OPEN'
    };
    return this.insert('shifts', shift);
  }

  closeShift(shiftId: string, tenantId: string, userId: string, finalCash: number): Shift {
    const shift = this.getById<Shift>('shifts', shiftId, tenantId);
    if (!shift) throw new Error('Shift not found');
    const orders = this.getLocalData<Order>('orders').filter(o => o.tenantId === tenantId && o.status === 'PAID' && o.closedAt && new Date(o.closedAt) >= new Date(shift.openedAt));
    const totalSales = orders.reduce((acc, o) => acc + o.total, 0);
    const cashSales = orders.filter(o => o.paymentMethod === 'CASH').reduce((acc, o) => acc + o.total, 0);
    const cardSales = orders.filter(o => o.paymentMethod === 'CARD').reduce((acc, o) => acc + o.total, 0);
    return this.update<Shift>('shifts', shiftId, tenantId, {
      status: 'CLOSED', closedAt: new Date().toISOString(), closedBy: userId, finalCash, totalSales, cashSales, cardSales, ordersCount: orders.length
    });
  }

  adjustStock(productId: string, tenantId: string, userId: string, quantity: number, reason: string): Product {
    const product = this.getById<Product>('products', productId, tenantId);
    if (!product) throw new Error('Product not found');
    const before = product.stockQuantity;
    const after = before + quantity;
    const updated = this.update<Product>('products', productId, tenantId, { stockQuantity: after });
    this.logActivity({
      id: `log-${Date.now()}`, tenantId, userId, action: 'STOCK_ADJUST', entityType: 'product', entityId: productId,
      before: { stock: before }, after: { stock: after, reason }, timestamp: new Date().toISOString()
    });
    return updated;
  }

  logActivity(log: AuditLog): void {
    const logs = this.getLocalData<AuditLog>('audit_logs');
    logs.push(log);
    this.setLocalData('audit_logs', logs);
  }

  getUserByEmail(email: string): User | undefined {
    return this.getLocalData<User>('users').find(u => u.email === email && u.isActive);
  }

  getTenant(id: string): Tenant | undefined {
    return this.getLocalData<Tenant>('tenants').find(t => t.id === id);
  }

  initialize() {
    // Si estamos en modo CLOUD, idealmente verificamos conexión
    // Si estamos en modo LOCAL, inicializamos defaults de localStorage
    const tenants = this.getLocalData<Tenant>('tenants');

    if (!localStorage.getItem('gastroflow_tenants')) {
      const generateUuidV4 = () => {
        // Preferir crypto.randomUUID si está disponible
        const cryptoObj: any = (globalThis as any).crypto;
        if (cryptoObj?.randomUUID) return cryptoObj.randomUUID();
        // Fallback UUIDv4 (no criptográficamente perfecto, suficiente para demo local)
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
          const r = Math.random() * 16 | 0;
          const v = c === 'x' ? r : (r & 0x3) | 0x8;
          return v.toString(16);
        });
      };

      const demoTenantId = generateUuidV4();
      const demoTenant: Tenant = {
        id: demoTenantId,
        name: 'Gastro Bar Demo',
        slug: 'gastro-bar',
        plan: PlanTier.PRO,
        subscriptionStatus: SubscriptionStatus.ACTIVE,
        createdAt: new Date().toISOString(),
        settings: { geminiModel: 'gemini-3-flash-preview' }
      };

      const roles: Role[] = DEFAULT_ROLES.map(r => ({ ...r, tenantId: demoTenantId }));
      const demoUser: User = {
        id: 'user-123', tenantId: demoTenantId, email: 'admin@demo.com', name: 'Admin Demo', roleId: roles[0].id, isActive: true
      };
      const mozoUser: User = {
        id: 'user-mozo', tenantId: demoTenantId, email: 'mozo@demo.com', name: 'Mozo Demo', roleId: roles.find(r => r.name === 'Mozo')?.id || 'role-staff', isActive: true
      };

      this.setLocalData('tenants', [demoTenant]);
      this.setLocalData('roles', roles);
      this.setLocalData('users', [demoUser, mozoUser]);

      const category: Category = { id: 'cat-1', tenantId: demoTenantId, name: 'Bebidas', order: 1 };
      this.setLocalData('categories', [category]);

      const products: Product[] = [
        { id: 'p-1', tenantId: demoTenantId, categoryId: 'cat-1', name: 'Cerveza Artesanal IPA', description: '500ml', price: 1200, stockEnabled: true, stockQuantity: 45, stockMin: 10, isActive: true, sku: 'CER-001' },
        { id: 'p-2', tenantId: demoTenantId, categoryId: 'cat-1', name: 'Limonada', description: 'Fresca', price: 800, stockEnabled: true, stockQuantity: 12, stockMin: 15, isActive: true, sku: 'BEB-002' },
      ];
      this.setLocalData('products', products);

      const tables: Table[] = [
        { id: 't-1', tenantId: demoTenantId, number: '1', capacity: 4, zone: 'Interior', status: 'AVAILABLE', isActive: true },
        { id: 't-2', tenantId: demoTenantId, number: '2', capacity: 2, zone: 'Exterior', status: 'OCCUPIED', isActive: true },
      ];
      this.setLocalData('tables', tables);
    }
  }
}

export const db = new DBService();
db.initialize();

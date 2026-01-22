
import React, { useState, useEffect } from 'react';
import { 
  Plus, Users, Search, Edit2, Trash2, X, Check, Loader2, DollarSign, 
  ShoppingCart, Minus, Printer, ChevronRight, ChefHat, Send, Clock, CheckCircle2,
  CheckCircle, Bell, AlertTriangle
} from 'lucide-react';
import { db } from '../services/db';
import { Table, Order, Product, OrderItem, User, OrderItemStatus, Tenant } from '../types';
import { PLANS } from '../constants';

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
}

const Modal: React.FC<ModalProps> = ({ isOpen, onClose, title, children }) => {
  if (!isOpen) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center p-0 sm:p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-slate-900 border-t sm:border border-slate-800 rounded-t-[2.5rem] sm:rounded-3xl w-full max-w-xl overflow-hidden shadow-2xl animate-in slide-in-from-bottom sm:zoom-in-95 duration-300">
        <div className="px-6 py-5 border-b border-slate-800 flex justify-between items-center">
          <h3 className="text-xl font-black text-slate-100 italic tracking-tight">{title}</h3>
          <button onClick={onClose} className="p-2 hover:bg-slate-800 rounded-xl text-slate-400 transition-colors">
            <X size={24} />
          </button>
        </div>
        <div className="p-6 max-h-[85vh] sm:max-h-[80vh] overflow-y-auto custom-scrollbar">
          {children}
        </div>
      </div>
    </div>
  );
};

export const TablesPage: React.FC<{ tenantId: string; user: User; tenant?: Tenant | null; isCloud?: boolean }> = ({ tenantId, user, tenant: tenantProp, isCloud = false }) => {
  const [tables, setTables] = useState<Table[]>([]);
  const [products, setProducts] = useState<Product[]>([]);
  const [orders, setOrders] = useState<Order[]>([]);
  const [filterZone, setFilterZone] = useState('all');
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isOrderModalOpen, setIsOrderModalOpen] = useState(false);
  const [editingTable, setEditingTable] = useState<Table | null>(null);
  const [activeTable, setActiveTable] = useState<Table | null>(null);
  const [activeOrder, setActiveOrder] = useState<Order | null>(null);
  const [loading, setLoading] = useState(false);

  const [orderSearch, setOrderSearch] = useState('');

  // SaaS Context
  const tenant = tenantProp || db.getTenant(tenantId);
  const isMultiUserPlan = tenant ? PLANS[tenant.plan].limits.users > 1 : false;

  useEffect(() => {
    refreshData();
  }, [tenantId, isCloud]);

  const getAuthHeaders = () => {
    const token = localStorage.getItem('gastroflow_token');
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    return headers;
  };

  const refreshData = async () => {
    if (isCloud) {
      try {
        const headers = getAuthHeaders();
        const [tablesRes, productsRes, ordersRes] = await Promise.all([
          fetch('/api/tables', { headers }),
          fetch('/api/products', { headers }),
          fetch('/api/orders', { headers }),
        ]);

        if (tablesRes.ok) {
          const apiTables = await tablesRes.json();
          setTables(
            (apiTables as any[])
              .filter(t => t.is_active !== false)
              .map(t => ({
                id: t.id,
                tenantId: t.tenant_id,
                number: t.number,
                capacity: t.capacity,
                zone: t.zone,
                status: (t.status || 'AVAILABLE').toString().toUpperCase(),
                isActive: t.is_active !== false,
              }))
          );
        }

        if (productsRes.ok) {
          const apiProducts = await productsRes.json();
          setProducts(
            (apiProducts as any[])
              .filter(p => p.is_active !== false)
              .map(p => ({
                id: p.id,
                tenantId: p.tenant_id,
                categoryId: p.category_id,
                name: p.name,
                description: p.description || '',
                price: Number(p.price || 0),
                cost: p.cost ? Number(p.cost) : undefined,
                sku: p.sku || undefined,
                stockEnabled: p.stock_enabled ?? false,
                stockQuantity: p.stock_quantity ?? 0,
                stockMin: p.stock_min ?? 0,
                isActive: p.is_active !== false,
                imageUrl: p.image_url || undefined,
              }))
          );
        }

        if (ordersRes.ok) {
          const apiOrders = await ordersRes.json();
          setOrders((apiOrders as any[]).map(o => ({
            id: o.id,
            tenantId: o.tenant_id,
            tableId: o.table_id,
            items: Array.isArray(o.items) ? o.items : [],
            status: o.status,
            total: Number(o.total || 0),
            paymentMethod: o.payment_method || undefined,
            openedAt: o.opened_at,
            closedAt: o.closed_at || undefined,
            closedBy: o.closed_by || undefined,
          })));
        }
      } catch (err) {
        console.error('Error cargando mesas/productos desde API:', err);
      }
      return;
    }

    // Modo local (demo): usar adaptador in-memory
    setTables(db.query<Table>('tables', tenantId).filter(t => t.isActive));
    setProducts(db.query<Product>('products', tenantId).filter(p => p.isActive));
  };

  const zones = Array.from(new Set(tables.map(t => t.zone)));
  const filteredTables = filterZone === 'all' ? tables : tables.filter(t => t.zone === filterZone);

  // Lógica de auto-enumeración
  const getNextTableNumber = () => {
    if (tables.length === 0) return "1";
    const numbers = tables.map(t => parseInt(t.number)).filter(n => !isNaN(n));
    if (numbers.length === 0) return (tables.length + 1).toString();
    return (Math.max(...numbers) + 1).toString();
  };

  const findActiveOrderForTable = (tableId: string): Order | undefined => {
    if (isCloud) {
      return orders.find(o => o.tableId === tableId && o.status === 'OPEN');
    }
    return db.getActiveOrderForTable(tableId, tenantId);
  };

  const saveOrderToApi = async (order: Order) => {
    const headers = getAuthHeaders();
    const payload: any = {
      table_id: order.tableId,
      status: order.status,
      total: order.total,
      payment_method: order.paymentMethod || null,
      opened_at: order.openedAt,
      closed_at: order.closedAt || null,
      closed_by: order.closedBy || null,
      items: order.items,
    };

    const method = order.id.startsWith('tmp-') ? 'POST' : 'PUT';
    const url = method === 'POST' ? '/api/orders' : `/api/orders/${order.id}`;

    const res = await fetch(url, {
      method,
      headers,
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => null);
      throw new Error(data?.error || 'No se pudo guardar la comanda');
    }
    const saved = await res.json();
    const savedOrder: Order = {
      id: saved.id,
      tenantId: saved.tenant_id,
      tableId: saved.table_id,
      items: Array.isArray(saved.items) ? saved.items : [],
      status: saved.status,
      total: Number(saved.total || 0),
      paymentMethod: saved.payment_method || undefined,
      openedAt: saved.opened_at,
      closedAt: saved.closed_at || undefined,
      closedBy: saved.closed_by || undefined,
    };
    return savedOrder;
  };

  const handleTableClick = (table: Table) => {
    if (table.status === 'AVAILABLE') {
      setActiveTable(table);
      setEditingTable(table);
      setIsModalOpen(true);
    } else {
      setActiveTable(table);

      if (isCloud) {
        const existing = findActiveOrderForTable(table.id);
        if (existing) {
          setActiveOrder(existing);
          setIsOrderModalOpen(true);
        } else {
          // Si no hay comanda abierta, se crea al agregar el primer producto
          setActiveOrder(null);
          setIsOrderModalOpen(true);
        }
      } else {
        const order = findActiveOrderForTable(table.id);
        if (order) {
          setActiveOrder(order);
        } else {
          const newOrder = db.createOrder(table.id, tenantId);
          setActiveOrder(newOrder);
        }
        setIsOrderModalOpen(true);
      }
    }
  };

  const handleDeleteTable = async (e: React.MouseEvent, table: Table) => {
    e.stopPropagation();
    if (!window.confirm(`¿Estás seguro de eliminar la Mesa ${table.number}?`)) return;

    if (isCloud) {
      try {
        const headers = getAuthHeaders();
        const res = await fetch(`/api/tables/${table.id}`, { method: 'DELETE', headers });
        if (!res.ok) {
          const data = await res.json().catch(() => null);
          alert(data?.error || 'No se pudo eliminar la mesa.');
        } else {
          refreshData();
        }
      } catch (error: any) {
        console.error(error);
        alert('Error de red al eliminar la mesa.');
      }
      return;
    }

    try {
      db.removeTable(table.id, tenantId);
      refreshData();
    } catch (error: any) {
      alert(error.message);
    }
  };

  const handleSaveTable = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setLoading(true);
    const formData = new FormData(e.currentTarget);
    
    const tableData: Partial<Table> = {
      number: formData.get('number') as string,
      capacity: Number(formData.get('capacity')),
      zone: formData.get('zone') as string,
      status: (formData.get('status') as any) || 'AVAILABLE',
      isActive: true,
    };

    if (isCloud) {
      try {
        const headers = getAuthHeaders();
        if (editingTable) {
          const res = await fetch(`/api/tables/${editingTable.id}`, {
            method: 'PUT',
            headers,
            body: JSON.stringify({
              number: tableData.number,
              capacity: tableData.capacity,
              zone: tableData.zone,
              status: tableData.status,
              is_active: tableData.isActive,
            }),
          });
          if (!res.ok) {
            const data = await res.json().catch(() => null);
            alert(data?.error || 'No se pudieron guardar los cambios de la mesa.');
            setLoading(false);
            return;
          }
        } else {
          const res = await fetch('/api/tables', {
            method: 'POST',
            headers,
            body: JSON.stringify({
              number: tableData.number,
              capacity: tableData.capacity,
              zone: tableData.zone,
              status: tableData.status,
              is_active: tableData.isActive,
            }),
          });
          if (!res.ok) {
            const data = await res.json().catch(() => null);
            alert(data?.error || 'No se pudo crear la mesa.');
            setLoading(false);
            return;
          }
        }

        await refreshData();
        setIsModalOpen(false);
        setEditingTable(null);
        setLoading(false);
      } catch (error: any) {
        console.error(error);
        alert('Error de red al guardar la mesa.');
        setLoading(false);
      }
      return;
    }

    if (editingTable) {
      db.update<Table>('tables', editingTable.id, tenantId, tableData);
    } else {
      db.insert<Table>('tables', {
        id: `table-${Date.now()}`,
        tenantId,
        ...tableData as Table
      });
    }

    setTimeout(() => {
      refreshData();
      setIsModalOpen(false);
      setEditingTable(null);
      setLoading(false);
    }, 400);
  };

  const handleOpenTableFromModal = async () => {
    if (!editingTable) return;
    setLoading(true);
    try {
      if (isCloud) {
        const headers = getAuthHeaders();
        // Crear comanda vacía
        const payload = {
          table_id: editingTable.id,
          status: 'OPEN',
          items: [],
          total: 0,
          opened_at: new Date().toISOString(),
        };
        const res = await fetch('/api/orders', { method: 'POST', headers, body: JSON.stringify(payload) });
        if (!res.ok) {
          const data = await res.json().catch(() => null);
          throw new Error(data?.error || 'No se pudo crear la comanda');
        }
        const saved = await res.json();
        const savedOrder: Order = {
          id: saved.id,
          tenantId: saved.tenant_id,
          tableId: saved.table_id,
          items: Array.isArray(saved.items) ? saved.items : [],
          status: saved.status,
          total: Number(saved.total || 0),
          paymentMethod: saved.payment_method || undefined,
          openedAt: saved.opened_at,
          closedAt: saved.closed_at || undefined,
          closedBy: saved.closed_by || undefined,
        };

        // Marcar mesa como ocupada
        await fetch(`/api/tables/${editingTable.id}`, { method: 'PUT', headers, body: JSON.stringify({ status: 'OCCUPIED' }) });

        // Actualizar estado local y abrir directamente el modal de consumo
        setOrders(prev => {
          const others = prev.filter(o => o.id !== savedOrder.id);
          return [...others, savedOrder];
        });
        setActiveTable(editingTable);
        setActiveOrder(savedOrder);
        setIsModalOpen(false);
        setIsOrderModalOpen(true);
        setEditingTable(null);
      } else {
        db.update<Table>('tables', editingTable.id, tenantId, { status: 'OCCUPIED' });
        db.createOrder(editingTable.id, tenantId);
        const order = db.getActiveOrderForTable(editingTable.id, tenantId);
        setActiveTable(editingTable);
        setActiveOrder(order || null);
        setIsModalOpen(false);
        setIsOrderModalOpen(true);
      }
    } catch (err: any) {
      console.error(err);
      alert(err.message || 'No se pudo abrir la comanda');
    } finally {
      setLoading(false);
    }
  };

  const addItemToActiveOrder = async (product: Product) => {
    if (!activeTable) return;

    if (isCloud) {
      try {
        let order = activeOrder || findActiveOrderForTable(activeTable.id) || {
          id: `tmp-${Date.now()}`,
          tenantId,
          tableId: activeTable.id,
          items: [],
          status: 'OPEN',
          total: 0,
          openedAt: new Date().toISOString(),
        } as Order;

        const items = [...order.items];
        const existing = items.find(i => i.productId === product.id && i.status === 'PENDING');
        if (existing) {
          existing.quantity += 1;
        } else {
          items.push({
            productId: product.id,
            name: product.name,
            quantity: 1,
            price: product.price,
            status: 'PENDING',
          });
        }
        const total = items.reduce((acc, i) => acc + i.price * i.quantity, 0);
        order = { ...order, items, total };

        const saved = await saveOrderToApi(order);
        setActiveOrder(saved);
        setOrders(prev => {
          const others = prev.filter(o => o.id !== saved.id);
          return [...others, saved];
        });
      } catch (err: any) {
        console.error(err);
        alert(err.message || 'No se pudo agregar el producto a la comanda.');
      }
      return;
    }

    if (!activeOrder) return;
    db.addItemsToOrder(activeOrder.id, tenantId, [{
      productId: product.id,
      name: product.name,
      quantity: 1,
      price: product.price
    }]);
    setActiveOrder(db.getActiveOrderForTable(activeTable!.id, tenantId) || null);
  };

  const removeItemFromActiveOrder = async (productId: string) => {
    if (!activeOrder || !activeTable) return;
    const item = activeOrder.items.find(i => i.productId === productId);
    if (!item) return;

    if (item.status !== 'PENDING' && !window.confirm('Este producto ya fue enviado a cocina. ¿Realmente deseas eliminarlo?')) {
        return;
    }
    if (!window.confirm('¿Deseas eliminar este producto de la comanda? Se devolverá al stock.')) {
        return;
    }

    if (isCloud) {
      try {
        const remaining = activeOrder.items.filter(i => i.productId !== productId);
        const total = remaining.reduce((acc, i) => acc + i.price * i.quantity, 0);
        const updated: Order = { ...activeOrder, items: remaining, total };
        const saved = await saveOrderToApi(updated);
        setActiveOrder(saved);
        setOrders(prev => {
          const others = prev.filter(o => o.id !== saved.id);
          return [...others, saved];
        });
      } catch (err: any) {
        console.error(err);
        alert(err.message || 'No se pudo actualizar la comanda.');
      }
      return;
    }

    const updated = db.removeItemFromOrder(activeOrder.id, tenantId, productId);
    setActiveOrder(updated);
  };

  const handleSendToKitchen = async () => {
    if (!activeOrder || !activeTable) return;

    if (isCloud) {
      try {
        const items = activeOrder.items.map(item =>
          item.status === 'PENDING'
            ? { ...item, status: 'PREPARING' as OrderItemStatus, sentAt: new Date().toISOString() }
            : item
        );
        const updated: Order = { ...activeOrder, items };
        const saved = await saveOrderToApi(updated);
        setActiveOrder(saved);
        setOrders(prev => {
          const others = prev.filter(o => o.id !== saved.id);
          return [...others, saved];
        });
        alert('Pedido enviado a cocina correctamente.');
      } catch (err: any) {
        console.error(err);
        alert(err.message || 'No se pudo enviar el pedido a cocina.');
      }
      return;
    }

    db.sendOrderToKitchen(activeOrder.id, tenantId);
    setActiveOrder(db.getActiveOrderForTable(activeTable!.id, tenantId) || null);
    alert('Pedido enviado a cocina correctamente.');
  };

  const handleServeReadyItems = async () => {
    if (!activeOrder || !activeTable) return;

    if (isCloud) {
      try {
        const items = activeOrder.items.map(item =>
          item.status === 'READY' ? { ...item, status: 'DELIVERED' as OrderItemStatus } : item
        );
        const updated: Order = { ...activeOrder, items };
        const saved = await saveOrderToApi(updated);
        setActiveOrder(saved);
        setOrders(prev => {
          const others = prev.filter(o => o.id !== saved.id);
          return [...others, saved];
        });
        refreshData();
      } catch (err: any) {
        console.error(err);
        alert(err.message || 'No se pudo actualizar la comanda.');
      }
      return;
    }

    db.deliverReadyItems(activeOrder.id, tenantId);
    setActiveOrder(db.getActiveOrderForTable(activeTable!.id, tenantId) || null);
    refreshData();
  };

  const handleCloseOrder = async (paymentMethod: any) => {
    if (!activeOrder || !activeTable) return;
    
    if (activeOrder.items.length === 0) {
      alert('No se puede cobrar una mesa sin productos.');
      return;
    }

    if (isCloud) {
      try {
        const finalizedItems = activeOrder.items.map(item => ({ ...item, status: 'DELIVERED' as OrderItemStatus }));
        const updated: Order = {
          ...activeOrder,
          items: finalizedItems,
          status: 'PAID',
          paymentMethod,
          closedAt: new Date().toISOString(),
          closedBy: user.id,
        };
        const saved = await saveOrderToApi(updated);

        // Liberar mesa en backend
        const headers = getAuthHeaders();
        await fetch(`/api/tables/${activeTable.id}`, {
          method: 'PUT',
          headers,
          body: JSON.stringify({ status: 'AVAILABLE' }),
        });

        setOrders(prev => prev.filter(o => o.id !== saved.id));
        setIsOrderModalOpen(false);
        setActiveOrder(null);
        setActiveTable(null);
        await refreshData();
      } catch (err: any) {
        console.error(err);
        alert(err.message || 'No se pudo cerrar la comanda.');
      }
      return;
    }

    db.closeOrder(activeOrder.id, tenantId, user.id, paymentMethod);
    setIsOrderModalOpen(false);
    setActiveOrder(null);
    setActiveTable(null);
    refreshData();
  };

  const hasPendingToKitchen = (activeOrder?.items || []).some(i => i.status === 'PENDING');
  const hasReadyToServe = (activeOrder?.items || []).some(i => i.status === 'READY');

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      <div className="flex flex-col sm:flex-row justify-between gap-4 items-center">
        <div className="flex items-center gap-2 bg-slate-900 p-1.5 rounded-2xl border border-slate-800 overflow-x-auto w-full sm:w-auto scrollbar-hide">
          <button 
            onClick={() => setFilterZone('all')}
            className={`px-5 py-2.5 rounded-xl text-xs font-black uppercase tracking-widest transition-all whitespace-nowrap ${filterZone === 'all' ? 'bg-blue-600 text-white shadow-lg' : 'text-slate-500 hover:text-slate-300'}`}
          >
            Todas
          </button>
          {zones.map(zone => (
            <button 
              key={zone}
              onClick={() => setFilterZone(zone)}
              className={`px-5 py-2.5 rounded-xl text-xs font-black uppercase tracking-widest transition-all whitespace-nowrap ${filterZone === zone ? 'bg-blue-600 text-white shadow-lg' : 'text-slate-500 hover:text-slate-300'}`}
            >
              {zone}
            </button>
          ))}
        </div>
        <button 
          onClick={() => { setEditingTable(null); setIsModalOpen(true); }}
          className="w-full sm:w-auto flex items-center justify-center gap-3 px-8 py-4 bg-blue-600 hover:bg-blue-500 text-white rounded-2xl font-black transition-all shadow-xl shadow-blue-600/20 active:scale-95"
        >
          <Plus size={20} />
          Añadir Mesa
        </button>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-4 sm:gap-6">
        {filteredTables.map(table => {
          const tableOrder = isCloud
            ? orders.find(o => o.tableId === table.id && o.status === 'OPEN')
            : db.getActiveOrderForTable(table.id, tenantId);
          const hasReady = tableOrder && Array.isArray(tableOrder.items)
            ? tableOrder.items.some(i => i.status === 'READY')
            : false;
          
          return (
            <div 
              key={table.id}
              onClick={() => handleTableClick(table)}
              className={`relative group p-6 sm:p-8 rounded-[2.5rem] border-2 cursor-pointer transition-all duration-500 flex flex-col items-center justify-center gap-4 ${
                table.status === 'AVAILABLE' 
                  ? 'bg-slate-900/40 border-slate-800 hover:border-emerald-500/50' 
                  : table.status === 'OCCUPIED'
                    ? hasReady ? 'bg-emerald-500/10 border-emerald-500/40 animate-pulse shadow-emerald-500/10' : 'bg-blue-500/10 border-blue-500/40 hover:border-blue-500/70 shadow-lg shadow-blue-500/5'
                    : 'bg-amber-500/5 border-amber-500/20 hover:border-amber-500/50'
              }`}
            >
              {/* Delete Button (Solo visible en hover para mesas libres) */}
              {table.status === 'AVAILABLE' && (
                <button 
                  onClick={(e) => handleDeleteTable(e, table)}
                  className="absolute top-4 right-4 p-2.5 bg-red-600/10 text-red-500 hover:bg-red-600 hover:text-white rounded-xl opacity-0 group-hover:opacity-100 transition-all border border-red-500/20 shadow-lg z-10"
                >
                  <Trash2 size={14} />
                </button>
              )}

              <div className={`w-16 h-16 sm:w-20 sm:h-20 rounded-3xl flex items-center justify-center mb-1 transition-all duration-500 group-hover:scale-110 shadow-2xl ${
                table.status === 'AVAILABLE' ? 'bg-slate-800 text-slate-400' : 
                table.status === 'OCCUPIED' ? (hasReady ? 'bg-emerald-600 text-white' : 'bg-blue-600 text-white shadow-blue-500/30') :
                'bg-amber-500/20 text-amber-400'
              }`}>
                <span className="text-2xl sm:text-3xl font-black italic">{table.number}</span>
              </div>
              
              <div className="text-center">
                <p className="text-[9px] sm:text-[10px] font-black uppercase tracking-widest text-slate-500 mb-1">{table.zone}</p>
                <div className="flex items-center justify-center gap-2 text-slate-300">
                  <Users size={12} className="opacity-50" />
                  <span className="text-xs sm:text-sm font-bold">{table.capacity}</span>
                </div>
              </div>

              {table.status === 'OCCUPIED' && (
                <div className={`px-3 py-1 rounded-full flex items-center gap-1.5 ${hasReady ? 'bg-emerald-500/20' : 'bg-blue-500/20'}`}>
                  {hasReady ? <Bell size={10} className="text-emerald-400 animate-bounce" /> : <ShoppingCart size={10} className="text-blue-400" />}
                  <span className={`text-[9px] font-black uppercase tracking-tight ${hasReady ? 'text-emerald-400' : 'text-blue-400'}`}>
                    {hasReady ? 'Listo' : 'Ocupada'}
                  </span>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Order & Billing Modal */}
      <Modal 
        isOpen={isOrderModalOpen} 
        onClose={() => setIsOrderModalOpen(false)} 
        title={`Mesa ${activeTable?.number} - Comanda`}
      >
        <div className="space-y-6">
          <div className="flex flex-col gap-6">
             <div className="bg-slate-800/40 rounded-[2rem] p-6 border border-slate-700/50 shadow-inner">
                <div className="flex items-center justify-between mb-4">
                  <h4 className="text-[10px] font-black uppercase tracking-widest text-slate-500">Artículos en la mesa</h4>
                  <span className="text-[10px] font-bold text-slate-600">{activeOrder?.items.length || 0} ítems</span>
                </div>
                <div className="space-y-4 max-h-[220px] overflow-y-auto pr-2 custom-scrollbar">
                  {activeOrder?.items.map((item, idx) => (
                    <div key={idx} className="flex justify-between items-center text-sm animate-in fade-in slide-in-from-right-2 duration-300 group/item" style={{ animationDelay: `${idx * 50}ms` }}>
                      <div className="flex items-center gap-3">
                        <span className={`w-7 h-7 flex items-center justify-center rounded-lg font-black text-xs ${
                          item.status === 'PENDING' ? 'bg-blue-600/20 text-blue-400' : 
                          item.status === 'PREPARING' ? 'bg-amber-600/20 text-amber-400 animate-pulse' :
                          item.status === 'READY' ? 'bg-emerald-600/20 text-emerald-400 shadow-lg shadow-emerald-500/20' :
                          'bg-slate-800 text-slate-500'
                        }`}>
                          {item.quantity}
                        </span>
                        <div className="flex flex-col">
                           <span className={`font-bold tracking-tight ${item.status === 'DELIVERED' ? 'text-slate-500 line-through opacity-50' : 'text-slate-200'}`}>{item.name}</span>
                           <span className={`text-[9px] font-black uppercase tracking-widest ${item.status === 'READY' ? 'text-emerald-400 animate-pulse' : 'text-slate-500'}`}>
                             {item.status === 'PENDING' ? 'Pendiente Envío' : 
                              item.status === 'PREPARING' ? 'En Cocina' : 
                              item.status === 'READY' ? '¡LISTO PARA RETIRAR!' : 'Servido'}
                           </span>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className="text-slate-400 font-black">${(item.price * item.quantity).toLocaleString()}</span>
                        {item.status === 'PENDING' && (
                          <button onClick={() => removeItemFromActiveOrder(item.productId)} className="p-2 text-slate-400 hover:text-red-400 hover:bg-red-400/10 rounded-xl transition-all"><Trash2 size={16} /></button>
                        )}
                      </div>
                    </div>
                  ))}
                  {(!activeOrder?.items || activeOrder.items.length === 0) && (
                    <div className="py-8 text-center text-slate-500 italic text-xs">Mesa vacía.</div>
                  )}
                </div>
                <div className="mt-6 pt-5 border-t border-slate-700/50 flex justify-between items-center">
                  <span className="text-base font-black text-slate-400 italic uppercase">Subtotal</span>
                  <span className="text-3xl font-black text-emerald-400 tracking-tighter">${(activeOrder ? activeOrder.total : 0).toLocaleString()}</span>
                </div>
             </div>

             <div className="flex gap-4">
                {isMultiUserPlan && hasPendingToKitchen && (
                  <button onClick={handleSendToKitchen} className="flex-1 py-4 bg-amber-600 hover:bg-amber-500 text-white rounded-2xl font-black transition-all flex items-center justify-center gap-3 active:scale-95 animate-pulse"><Send size={18} /> Enviar a Cocina</button>
                )}
                {isMultiUserPlan && hasReadyToServe && (
                  <button onClick={handleServeReadyItems} className="flex-1 py-4 bg-emerald-600 hover:bg-emerald-500 text-white rounded-2xl font-black transition-all flex items-center justify-center gap-3 active:scale-95 animate-bounce"><CheckCircle size={20} /> Entregar Todo</button>
                )}
             </div>

             <div className="space-y-4">
                <div className="relative group">
                  <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
                  <input type="text" placeholder="Buscar plato..." className="w-full bg-slate-800/50 border border-slate-700 rounded-2xl py-4 pl-12 pr-4 text-sm text-slate-100 outline-none" value={orderSearch} onChange={(e) => setOrderSearch(e.target.value)} />
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 max-h-[180px] overflow-y-auto pr-2 custom-scrollbar">
                  {products.filter(p => p.name.toLowerCase().includes(orderSearch.toLowerCase())).map(product => (
                    <button key={product.id} onClick={() => addItemToActiveOrder(product)} className="text-left p-4 bg-slate-800/60 hover:bg-blue-600/10 rounded-2xl border border-slate-700/50 flex items-center justify-between group">
                      <div className="flex flex-col min-w-0"><span className="text-xs font-black text-slate-200 truncate">{product.name}</span><span className="text-[10px] font-black text-emerald-400 uppercase tracking-wider">${product.price}</span></div>
                      <Plus size={16} className="text-slate-600 group-hover:text-blue-400 transition-colors" />
                    </button>
                  ))}
                </div>
             </div>
          </div>

          <div className="pt-6 border-t border-slate-800 flex flex-col sm:flex-row gap-3">
            <button onClick={() => setIsOrderModalOpen(false)} className="order-2 sm:order-1 px-6 py-4 text-slate-500 hover:text-slate-100 font-black text-xs uppercase tracking-widest transition-colors text-center">Cerrar</button>
            <div className="order-1 sm:order-2 flex-1 flex flex-col sm:flex-row gap-3">
               <button onClick={() => handleCloseOrder('CASH')} className="flex-1 py-4 bg-emerald-600 hover:bg-emerald-500 text-white rounded-2xl font-black transition-all shadow-xl flex items-center justify-center gap-3 active:scale-[0.98]"><DollarSign size={20} /> Cobrar Efectivo</button>
               <button onClick={() => handleCloseOrder('CARD')} className="flex-1 py-4 bg-blue-600 hover:bg-blue-500 text-white rounded-2xl font-black transition-all shadow-xl flex items-center justify-center gap-3 active:scale-[0.98]">Tarjeta</button>
            </div>
          </div>
        </div>
      </Modal>

      {/* Edit/Create Table Modal */}
      <Modal 
        isOpen={isModalOpen} 
        onClose={() => setIsModalOpen(false)} 
        title={editingTable ? `Configurar Mesa ${editingTable.number}` : 'Añadir Nueva Mesa'}
      >
        <form onSubmit={handleSaveTable} className="space-y-6">
          <div className="grid grid-cols-2 gap-4 sm:gap-6">
            <div className="space-y-2">
              <label className="text-xs font-black text-slate-500 uppercase tracking-widest ml-1">Nro. Mesa</label>
              <input 
                name="number" 
                required 
                defaultValue={editingTable ? editingTable.number : getNextTableNumber()} 
                readOnly={!editingTable} // Solo se puede elegir número si se está editando
                className={`w-full border border-slate-700 rounded-2xl py-3.5 px-5 text-slate-100 outline-none focus:ring-2 focus:ring-blue-500/50 ${!editingTable ? 'bg-slate-800/50 text-slate-500 cursor-not-allowed italic' : 'bg-slate-800'}`} 
              />
              {!editingTable && <p className="text-[9px] text-blue-400 font-bold uppercase ml-1">Auto-generado</p>}
            </div>
            <div className="space-y-2">
              <label className="text-xs font-black text-slate-500 uppercase tracking-widest ml-1">Comensales</label>
              <input name="capacity" type="number" required defaultValue={editingTable?.capacity || 4} className="w-full bg-slate-800 border border-slate-700 rounded-2xl py-3.5 px-5 text-slate-100 outline-none focus:ring-2 focus:ring-blue-500/50" />
            </div>
            <div className="space-y-2">
              <label className="text-xs font-black text-slate-500 uppercase tracking-widest ml-1">Zona / Sector</label>
              <input name="zone" required defaultValue={editingTable?.zone || (filterZone !== 'all' ? filterZone : 'Interior')} className="w-full bg-slate-800 border border-slate-700 rounded-2xl py-3.5 px-5 text-slate-100 outline-none focus:ring-2 focus:ring-blue-500/50" placeholder="Ej: Interior" />
            </div>
            <div className="space-y-2">
              <label className="text-xs font-black text-slate-500 uppercase tracking-widest ml-1">Estado</label>
              <select name="status" defaultValue={editingTable?.status || 'AVAILABLE'} className="w-full bg-slate-800 border border-slate-700 rounded-2xl py-3.5 px-5 text-slate-100 outline-none appearance-none cursor-pointer">
                <option value="AVAILABLE">Libre</option>
                <option value="OCCUPIED">Ocupada</option>
                <option value="RESERVED">Reservada</option>
              </select>
            </div>
          </div>

          <div className="pt-6 border-t border-slate-800 flex flex-col sm:flex-row justify-end gap-3">
             {editingTable && (
               <button 
                type="button"
                onClick={handleOpenTableFromModal}
                className="w-full sm:mr-auto sm:w-auto px-8 py-4 bg-blue-600/10 text-blue-400 hover:bg-blue-600/20 border border-blue-500/20 rounded-2xl font-black uppercase text-xs tracking-widest transition-all"
              >
                Abrir Comanda
              </button>
             )}
            <button type="submit" className="w-full sm:w-auto px-10 py-4 bg-blue-600 hover:bg-blue-500 text-white rounded-2xl font-black transition-all shadow-xl active:scale-95">
              {editingTable ? 'Guardar Cambios' : 'Confirmar Mesa'}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
};

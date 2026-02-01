
import React, { useState, useEffect } from 'react';
import { db } from '../services/db';
import { Shift, Order, User } from '../types';
import { 
  Wallet, Clock, ArrowRight, CheckCircle2, DollarSign, ListChecks, 
  Loader2, LogIn, LogOut, TrendingUp, AlertTriangle, CreditCard, 
  Receipt, UserCheck, Scale, AlertCircle
} from 'lucide-react';

export const CashierPage: React.FC<{ tenantId: string, user: User; isCloud?: boolean }> = ({ tenantId, user, isCloud = false }) => {
  const [activeShift, setActiveShift] = useState<Shift | undefined>(undefined);
  const [closedShifts, setClosedShifts] = useState<Shift[]>([]);
  const [loading, setLoading] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [initialCash, setInitialCash] = useState<number>(0);
  const [finalCash, setFinalCash] = useState<number>(0);
  
  const [currentShiftSales, setCurrentShiftSales] = useState({
    total: 0,
    cash: 0,
    card: 0,
    count: 0
  });

  useEffect(() => {
    refreshData();
  }, [tenantId, isCloud]);

  const refreshData = async () => {
    try {
      if (isCloud) {
        const token = localStorage.getItem('restoflux_token');
        const headers: Record<string, string> = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = `Bearer ${token}`;

        const [shiftsRes, ordersRes] = await Promise.all([
          fetch('/api/shifts', { headers }),
          fetch('/api/orders', { headers }),
        ]);

        let fetchedShifts: any[] = [];
        if (shiftsRes.ok) fetchedShifts = await shiftsRes.json();
        let fetchedOrders: any[] = [];
        if (ordersRes.ok) fetchedOrders = await ordersRes.json();

        const openShift = fetchedShifts.find(s => s.status === 'OPEN');

        if (openShift) {
          const ordersInShift = fetchedOrders.filter(o => o.status === 'PAID' && o.closed_at && new Date(o.closed_at) >= new Date(openShift.opened_at));
          const stats = {
            total: ordersInShift.reduce((acc: number, o: any) => acc + Number(o.total || 0), 0),
            cash: ordersInShift.filter(o => o.payment_method === 'CASH').reduce((acc: number, o: any) => acc + Number(o.total || 0), 0),
            card: ordersInShift.filter(o => o.payment_method === 'CARD').reduce((acc: number, o: any) => acc + Number(o.total || 0), 0),
            count: ordersInShift.length
          };

          setActiveShift({
            id: openShift.id,
            tenantId: openShift.tenant_id,
            openedAt: openShift.opened_at,
            openedBy: openShift.opened_by,
            initialCash: Number(openShift.initial_cash || 0),
            totalSales: Number(openShift.total_sales || 0),
            cashSales: Number(openShift.cash_sales || stats.cash || 0),
            cardSales: Number(openShift.card_sales || stats.card || 0),
            ordersCount: Number(openShift.orders_count || stats.count || 0),
            status: openShift.status,
          } as Shift);

          setCurrentShiftSales(stats);
          setFinalCash(prev => prev === 0 ? (Number(openShift.initial_cash || 0) + stats.cash) : prev);
        } else {
          setActiveShift(undefined);
          setFinalCash(0);
          setCurrentShiftSales({ total: 0, cash: 0, card: 0, count: 0 });
        }

        const closed = fetchedShifts.filter((s: any) => s.status === 'CLOSED').map((s: any) => ({
          id: s.id,
          tenantId: s.tenant_id,
          openedAt: s.opened_at,
          closedAt: s.closed_at,
          openedBy: s.opened_by,
          closedBy: s.closed_by,
          initialCash: Number(s.initial_cash || 0),
          finalCash: Number(s.final_cash || 0),
          totalSales: Number(s.total_sales || 0),
          cashSales: Number(s.cash_sales || 0),
          cardSales: Number(s.card_sales || 0),
          ordersCount: Number(s.orders_count || 0),
          status: s.status,
        } as Shift));

        setClosedShifts(closed.sort((a: Shift, b: Shift) => new Date(b.closedAt!).getTime() - new Date(a.closedAt!).getTime()));
        return;
      }

      const shift = db.getActiveShift(tenantId);
      setActiveShift(shift);

      if (shift) {
        const allOrders = db.query<Order>('orders', tenantId);
        const ordersInShift = allOrders.filter(o => 
          o.status === 'PAID' && 
          o.closedAt && 
          new Date(o.closedAt) >= new Date(shift.openedAt)
        );

        const stats = {
          total: ordersInShift.reduce((acc, o) => acc + o.total, 0),
          cash: ordersInShift.filter(o => o.paymentMethod === 'CASH').reduce((acc, o) => acc + o.total, 0),
          card: ordersInShift.filter(o => o.paymentMethod === 'CARD').reduce((acc, o) => acc + o.total, 0),
          count: ordersInShift.length
        };
        
        setCurrentShiftSales(stats);
        setFinalCash(prev => prev === 0 ? (shift.initialCash + stats.cash) : prev);
      } else {
        setFinalCash(0);
        setCurrentShiftSales({ total: 0, cash: 0, card: 0, count: 0 });
      }

      const closed = db.query<Shift>('shifts', tenantId)
        .filter(s => s.status === 'CLOSED')
        .sort((a, b) => new Date(b.closedAt!).getTime() - new Date(a.closedAt!).getTime());
      
      setClosedShifts(closed);
    } catch (error) {
      console.error("Error al refrescar datos de caja:", error);
    }
  };

  const handleOpenShift = async () => {
    if (initialCash < 0) return alert("El monto inicial no puede ser negativo");
    setLoading(true);
    try {
      if (isCloud) {
        const token = localStorage.getItem('restoflux_token');
        const headers: Record<string, string> = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = `Bearer ${token}`;
        const res = await fetch('/api/shifts', { method: 'POST', headers, body: JSON.stringify({ initial_cash: initialCash }) });
        if (!res.ok) {
          const data = await res.json().catch(() => null);
          const msg = data?.error || 'No se pudo abrir el turno de caja.';
          alert(msg);
          return;
        }
        await refreshData();
        setInitialCash(0);
      } else {
        db.openShift(tenantId, user.id, initialCash);
        refreshData();
        setInitialCash(0);
      }
    } catch (error) {
      alert("Error al abrir turno");
    } finally {
      setLoading(false);
    }
  };

  const handleCloseShift = async () => {
    if (!activeShift) return;
    
    // Si no se ha mostrado la confirmación, la mostramos
    if (!showConfirm) {
      setShowConfirm(true);
      return;
    }

    setLoading(true);
    try {
      if (isCloud) {
        const token = localStorage.getItem('restoflux_token');
        const headers: Record<string, string> = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = `Bearer ${token}`;
        await fetch(`/api/shifts/${activeShift.id}`, { method: 'PUT', headers, body: JSON.stringify({ final_cash: finalCash, status: 'CLOSED' }) });
        setShowConfirm(false);
        setActiveShift(undefined);
        await refreshData();
      } else {
        db.closeShift(activeShift.id, tenantId, user.id, finalCash);
        setShowConfirm(false);
        setActiveShift(undefined);
        refreshData();
      }
    } catch (error) {
      console.error("Error al cerrar turno:", error);
      alert("Ocurrió un error al intentar cerrar el turno. Por favor, intenta de nuevo.");
    } finally {
      setLoading(false);
    }
  };

  const theoreticalCashBalance = activeShift ? activeShift.initialCash + currentShiftSales.cash : 0;
  const difference = finalCash - theoreticalCashBalance;

  return (
    <div className="max-w-5xl mx-auto space-y-10 animate-in fade-in duration-500">
      {/* Current Shift Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-[2.5rem] p-10 shadow-2xl overflow-hidden relative">
        <div className="absolute top-0 right-0 w-96 h-96 bg-blue-600/5 rounded-full blur-[100px] -mr-40 -mt-40"></div>
        
        {!activeShift ? (
          <div className="flex flex-col items-center text-center space-y-8 py-4">
            <div className="w-24 h-24 bg-blue-600/10 text-blue-400 rounded-full flex items-center justify-center shadow-lg shadow-blue-500/10 border border-blue-500/20">
              <Wallet size={48} strokeWidth={1.5} />
            </div>
            <div>
              <h2 className="text-4xl font-black text-slate-100 italic">Caja Cerrada</h2>
              <p className="text-slate-400 mt-2 max-w-xs mx-auto">Configura el fondo de caja para iniciar las operaciones del día.</p>
            </div>
            
            <div className="w-full max-w-sm space-y-4">
              <div className="space-y-2 text-left">
                <label className="text-xs font-black text-slate-500 uppercase tracking-widest ml-1">Efectivo Inicial (Fondo)</label>
                <div className="relative group">
                   <DollarSign className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500 group-focus-within:text-blue-400 transition-colors" size={18} />
                   <input 
                    type="number" 
                    className="w-full bg-slate-800/50 border border-slate-700 rounded-2xl py-5 pl-12 pr-4 text-white text-2xl font-black outline-none focus:ring-4 focus:ring-blue-500/10 focus:border-blue-500/50 transition-all"
                    placeholder="0"
                    value={initialCash}
                    onChange={(e) => setInitialCash(Number(e.target.value))}
                   />
                </div>
              </div>
              <button 
                onClick={handleOpenShift}
                disabled={loading}
                className="w-full py-5 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 text-white rounded-3xl font-black text-lg transition-all shadow-xl shadow-blue-600/20 flex items-center justify-center gap-3 active:scale-95"
              >
                {loading ? <Loader2 size={24} className="animate-spin" /> : <LogIn size={24} />}
                Iniciar Turno de Trabajo
              </button>
            </div>
          </div>
        ) : (
          <div className="space-y-10">
            <div className="flex justify-between items-start">
              <div className="flex items-center gap-5">
                <div className="w-16 h-16 bg-emerald-500/10 text-emerald-400 rounded-2xl flex items-center justify-center border border-emerald-500/20 shadow-lg shadow-emerald-500/5">
                  <Clock size={32} />
                </div>
                <div>
                  <h2 className="text-3xl font-black text-slate-100 italic">Turno en Curso</h2>
                  <div className="flex items-center gap-3 mt-1 text-slate-400 text-sm font-medium">
                     <span className="flex items-center gap-1.5"><UserCheck size={14} className="text-blue-400" /> {user.name}</span>
                     <span className="w-1 h-1 bg-slate-700 rounded-full"></span>
                     <span>Iniciado {new Date(activeShift.openedAt).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'})}</span>
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button 
                  onClick={() => { setFinalCash(0); refreshData(); }}
                  className="p-3 bg-slate-800 text-slate-400 hover:text-slate-100 rounded-2xl border border-slate-700 transition-all hover:scale-110 active:scale-90"
                  title="Actualizar balance"
                >
                  <TrendingUp size={20} />
                </button>
                <span className="px-5 py-2 bg-emerald-500/10 text-emerald-400 text-[10px] font-black uppercase tracking-[0.2em] rounded-full border border-emerald-500/20 animate-pulse">
                  Live Control
                </span>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
              <div className="bg-slate-800/40 p-6 rounded-3xl border border-slate-700/50 backdrop-blur-sm">
                <p className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-3 flex items-center gap-2">
                   <Wallet size={12} /> Fondo Inicial
                </p>
                <p className="text-3xl font-black text-slate-100">${activeShift.initialCash.toLocaleString()}</p>
              </div>
              <div className="bg-slate-800/40 p-6 rounded-3xl border border-slate-700/50 backdrop-blur-sm">
                <p className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-3 flex items-center gap-2">
                   <Receipt size={12} /> Ventas (CASH)
                </p>
                <p className="text-3xl font-black text-emerald-400">${currentShiftSales.cash.toLocaleString()}</p>
              </div>
              <div className="bg-slate-800/40 p-6 rounded-3xl border border-slate-700/50 backdrop-blur-sm">
                <p className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-3 flex items-center gap-2">
                   <CreditCard size={12} /> Ventas (CARD)
                </p>
                <p className="text-3xl font-black text-blue-400">${currentShiftSales.card.toLocaleString()}</p>
              </div>
              <div className="bg-blue-600/10 p-6 rounded-3xl border border-blue-500/30 backdrop-blur-sm">
                <p className="text-[10px] font-black text-blue-400 uppercase tracking-widest mb-3 flex items-center gap-2">
                   <Scale size={12} /> Total Ventas
                </p>
                <p className="text-3xl font-black text-white">${currentShiftSales.total.toLocaleString()}</p>
              </div>
            </div>

            <div className="pt-10 border-t border-slate-800 grid grid-cols-1 lg:grid-cols-2 gap-10 items-end">
              <div className="space-y-4">
                <div className="flex justify-between items-end ml-1">
                   <label className="text-xs font-black text-slate-500 uppercase tracking-widest">Contabilizar Efectivo en Caja</label>
                   <span className="text-[10px] font-bold text-slate-600 uppercase">Teórico Cash: ${theoreticalCashBalance.toLocaleString()}</span>
                </div>
                <div className="relative">
                   <DollarSign className="absolute left-5 top-1/2 -translate-y-1/2 text-slate-500" size={22} />
                   <input 
                    type="number" 
                    className={`w-full bg-slate-800/80 border-2 rounded-[1.5rem] py-5 pl-14 pr-6 text-white text-3xl font-black outline-none transition-all ${difference !== 0 ? 'border-amber-500/30 focus:border-amber-500 shadow-lg shadow-amber-500/5' : 'border-slate-700 focus:border-blue-500'}`}
                    placeholder="Monto físico..."
                    value={finalCash}
                    onChange={(e) => setFinalCash(Number(e.target.value))}
                   />
                </div>
                {difference !== 0 && (
                  <div className={`flex items-center gap-3 px-5 py-3 rounded-2xl border ${difference > 0 ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' : 'bg-red-500/10 border-red-500/20 text-red-400'}`}>
                    <AlertTriangle size={18} />
                    <span className="text-sm font-black uppercase tracking-tight">
                       Diferencia: {difference > 0 ? 'Sobrante' : 'Faltante'} de ${Math.abs(difference).toLocaleString()}
                    </span>
                  </div>
                )}
              </div>
              <div className="space-y-5">
                <div className="flex flex-col gap-3">
                  {showConfirm ? (
                    <div className="flex gap-2 animate-in zoom-in-95 duration-200">
                      <button 
                        onClick={() => setShowConfirm(false)}
                        className="flex-1 py-6 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-[1.5rem] font-black text-xl transition-all"
                      >
                        Cancelar
                      </button>
                      <button 
                        onClick={handleCloseShift}
                        disabled={loading}
                        className="flex-[2] py-6 bg-red-600 hover:bg-red-500 text-white rounded-[1.5rem] font-black text-xl transition-all shadow-2xl shadow-red-600/20 flex items-center justify-center gap-4"
                      >
                        {loading ? <Loader2 size={28} className="animate-spin" /> : <AlertCircle size={28} />}
                        Sí, Cerrar Caja
                      </button>
                    </div>
                  ) : (
                    <button 
                      onClick={handleCloseShift}
                      disabled={loading}
                      className="w-full py-6 bg-slate-100 hover:bg-white text-slate-950 rounded-[1.5rem] font-black text-xl transition-all shadow-2xl flex items-center justify-center gap-4 active:scale-[0.98]"
                    >
                      <LogOut size={28} />
                      Realizar Cierre de Turno
                    </button>
                  )}
                </div>
                <div className="bg-slate-800/30 px-6 py-4 rounded-2xl border border-slate-700/30 flex justify-between items-center">
                   <span className="text-xs font-bold text-slate-500 uppercase">Comandas Procesadas</span>
                   <span className="text-lg font-black text-slate-300">{currentShiftSales.count}</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* History Section */}
      {closedShifts.length > 0 && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="p-3 bg-slate-900 rounded-2xl border border-slate-800 text-slate-400">
                <ListChecks size={24} />
              </div>
              <h3 className="text-2xl font-black text-slate-100 italic tracking-tight">Historial de Operaciones</h3>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-5">
            {closedShifts.map(shift => {
            const shiftTheoreticalCash = shift.initialCash + shift.cashSales;
            const shiftDiff = (shift.finalCash || 0) - shiftTheoreticalCash;

            return (
              <div key={shift.id} className="bg-slate-900/40 border border-slate-800 rounded-[2rem] p-8 flex flex-col md:flex-row justify-between items-center gap-10 group hover:border-slate-600 transition-all duration-300">
                <div className="flex items-center gap-6 min-w-[200px]">
                  <div className="w-14 h-14 bg-slate-800 rounded-2xl flex items-center justify-center text-slate-500 group-hover:bg-emerald-500/10 group-hover:text-emerald-400 transition-all border border-slate-700/50">
                    <CheckCircle2 size={28} />
                  </div>
                  <div>
                    <p className="text-lg font-black text-slate-100 italic">{new Date(shift.openedAt).toLocaleDateString('es-AR', { weekday: 'long', day: 'numeric', month: 'short' })}</p>
                    <p className="text-[10px] font-black text-slate-500 uppercase tracking-widest mt-1">
                      {new Date(shift.openedAt).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})} ➔ {shift.closedAt ? new Date(shift.closedAt).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}) : '--'}
                    </p>
                  </div>
                </div>

                <div className="grid grid-cols-2 lg:grid-cols-4 gap-x-12 gap-y-6 text-center flex-1">
                   <div>
                      <p className="text-[10px] font-black text-slate-600 uppercase tracking-widest mb-1.5 flex items-center justify-center gap-1.5">
                         <Receipt size={10} /> Ventas
                      </p>
                      <p className="text-lg font-black text-slate-100">${shift.totalSales.toLocaleString()}</p>
                   </div>
                   <div>
                      <p className="text-[10px] font-black text-slate-600 uppercase tracking-widest mb-1.5 flex items-center justify-center gap-1.5">
                         <DollarSign size={10} /> Cash
                      </p>
                      <p className="text-lg font-black text-emerald-500">${shift.cashSales.toLocaleString()}</p>
                   </div>
                   <div>
                      <p className="text-[10px] font-black text-slate-600 uppercase tracking-widest mb-1.5 flex items-center justify-center gap-1.5">
                         <CreditCard size={10} /> Card
                      </p>
                      <p className="text-lg font-black text-blue-400">${shift.cardSales.toLocaleString()}</p>
                   </div>
                   <div>
                      <p className="text-[10px] font-black text-slate-600 uppercase tracking-widest mb-1.5 flex items-center justify-center gap-1.5">
                         <Receipt size={10} /> Tickets
                      </p>
                      <p className="text-lg font-black text-slate-300">{shift.ordersCount}</p>
                   </div>
                </div>

                <div className="flex flex-col items-end min-w-[140px] pl-6 border-l border-slate-800">
                  <p className="text-[10px] font-black text-slate-600 uppercase tracking-widest mb-1">Balance Caja</p>
                  <p className={`text-xl font-black ${shiftDiff < 0 ? 'text-red-400' : shiftDiff > 0 ? 'text-emerald-400' : 'text-slate-400'}`}>
                    {shiftDiff > 0 ? '+' : ''}{shiftDiff.toLocaleString()}
                  </p>
                  <p className="text-[10px] font-bold text-slate-500 italic mt-1 uppercase">Final: ${shift.finalCash?.toLocaleString()}</p>
                </div>
              </div>
            );
          })}
          </div>
        </div>
      )}
    </div>
  );
};

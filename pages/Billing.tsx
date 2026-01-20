
import React, { useState } from 'react';
import {
  Check, Zap, Shield, Crown, CreditCard, History,
  ExternalLink, Loader2, AlertCircle, CheckCircle2,
  ArrowRight, Sparkles, Building2, X, Users
} from 'lucide-react';
import { PLANS } from '../constants';
import { PlanTier, Tenant, SubscriptionStatus, User } from '../types';
import { db } from '../services/db';

export const BillingPage: React.FC<{ tenant: Tenant, onUpdate: (t: Tenant) => void }> = ({ tenant, onUpdate }) => {
  const [loadingPlan, setLoadingPlan] = useState<PlanTier | null>(null);
  const [showCheckout, setShowCheckout] = useState<{ planId: PlanTier, name: string, price: number } | null>(null);
  const [checkoutStatus, setCheckoutStatus] = useState<'idle' | 'processing' | 'success'>('idle');
  const [reconciliationNotice, setReconciliationNotice] = useState(false);

  const handleSubscribeClick = (plan: any) => {
    setShowCheckout({ planId: plan.id, name: plan.name, price: plan.price });
  };

  const handleConfirmPayment = async () => {
    if (!showCheckout) return;
    setCheckoutStatus('processing');

    console.log('[DEBUG] Payment attempt:', {
      hostname: window.location.hostname,
      env: (import.meta as any).env.VITE_APP_MODE
    });

    const isCloud = (import.meta as any).env.VITE_APP_MODE === 'CLOUD' ||
      (!window.location.hostname.includes('localhost') && !window.location.hostname.includes('127.0.0.1'));

    console.log('[DEBUG] isCloud result:', isCloud);

    if (isCloud) {
      try {
        const res = await fetch('/api/subscriptions', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            tenantId: tenant.id,
            planId: showCheckout.planId,
            price: showCheckout.price,
            backUrl: window.location.href // Return to this page
          })
        });
        const data = await res.json();
        if (data.init_point) {
          window.location.href = data.init_point;
          return;
        } else {
          console.error('No init_point returned', data);
          alert('Error al iniciar pago con Mercado Pago. Verifica la configuración.');
          setCheckoutStatus('idle');
          return;
        }
      } catch (err) {
        console.error('Payment initialization failed', err);
        alert('Error de conexión con el servidor de pagos.');
        setCheckoutStatus('idle');
        return;
      }
    }

    // Fallback Simulation (Local Mode)
    // Check current users before update to show notice if needed
    const currentActiveUsers = db.query<User>('users', tenant.id).filter(u => u.isActive).length;
    const newLimit = PLANS[showCheckout.planId].limits.users;

    // Simular latencia de Mercado Pago
    setTimeout(() => {
      const updatedTenant = db.updateTenantSubscription(tenant.id, {
        plan: showCheckout.planId,
        status: SubscriptionStatus.ACTIVE,
        preapprovalId: `mp-sub-${Date.now()}`
      });

      if (currentActiveUsers > newLimit) {
        setReconciliationNotice(true);
      }

      setCheckoutStatus('success');

      setTimeout(() => {
        onUpdate(updatedTenant);
        setShowCheckout(null);
        setCheckoutStatus('idle');
        setReconciliationNotice(false);
      }, 4000);
    }, 2500);
  };

  return (
    <div className="max-w-6xl mx-auto space-y-12 animate-in fade-in duration-700">
      {/* Header Stat Card */}
      <section className="bg-slate-900/60 border border-slate-800/80 rounded-[2.5rem] p-10 shadow-2xl relative overflow-hidden backdrop-blur-xl">
        <div className="absolute top-0 right-0 w-80 h-80 bg-blue-600/5 rounded-full blur-[100px] -mr-40 -mt-40"></div>
        <div className="absolute bottom-0 left-0 w-60 h-60 bg-purple-600/5 rounded-full blur-[80px] -ml-30 -mb-30"></div>

        <div className="flex flex-col md:flex-row justify-between items-center gap-10 relative z-10">
          <div className="flex items-center gap-8 text-center md:text-left">
            <div className="w-20 h-20 bg-gradient-to-tr from-blue-600 to-purple-600 rounded-[2rem] flex items-center justify-center shadow-2xl shadow-blue-500/20">
              <Building2 size={36} className="text-white" />
            </div>
            <div>
              <h2 className="text-3xl font-black text-slate-100 italic tracking-tight mb-2">Estado de Suscripción</h2>
              <div className="flex flex-wrap items-center gap-3 justify-center md:justify-start">
                <span className="px-5 py-1.5 bg-blue-600/20 text-blue-400 border border-blue-500/30 font-black rounded-full text-xs uppercase tracking-[0.1em]">
                  {PLANS[tenant.plan].name}
                </span>
                <span className={`px-5 py-1.5 rounded-full text-xs font-black uppercase tracking-[0.1em] flex items-center gap-2 border ${tenant.subscriptionStatus === SubscriptionStatus.ACTIVE
                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                  : 'bg-red-500/10 text-red-400 border-red-500/20 animate-pulse'
                  }`}>
                  <div className={`w-2 h-2 rounded-full ${tenant.subscriptionStatus === SubscriptionStatus.ACTIVE ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]' : 'bg-red-500'}`}></div>
                  {tenant.subscriptionStatus === SubscriptionStatus.ACTIVE ? 'Servicio Activo' : 'Acceso Restringido'}
                </span>
              </div>
            </div>
          </div>

          <div className="bg-slate-800/40 p-6 rounded-3xl border border-slate-700/50 text-center min-w-[240px]">
            <p className="text-[10px] text-slate-500 uppercase font-black tracking-[0.2em] mb-2">Próximo Vencimiento</p>
            <p className="text-2xl font-black text-slate-100 italic">
              {tenant.nextBillingDate
                ? new Date(tenant.nextBillingDate).toLocaleDateString('es-AR', { day: 'numeric', month: 'long', year: 'numeric' })
                : 'Pendiente de Pago'}
            </p>
          </div>
        </div>
      </section>

      {/* Pricing Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
        {(Object.values(PLANS) as any).map((plan: any) => (
          <div
            key={plan.id}
            className={`group relative flex flex-col p-10 rounded-[3rem] border-2 transition-all duration-500 ${tenant.plan === plan.id
              ? 'bg-blue-600/10 border-blue-500/50 shadow-2xl shadow-blue-500/10'
              : 'bg-slate-900/40 border-slate-800/80 hover:border-blue-500/30 hover:bg-slate-900/60 shadow-xl hover:shadow-blue-500/5'
              }`}
          >
            {tenant.plan === plan.id && (
              <div className="absolute -top-4 left-1/2 -translate-x-1/2 bg-gradient-to-r from-blue-600 to-blue-400 text-white text-[10px] font-black px-6 py-2 rounded-full uppercase tracking-widest shadow-xl">
                Tu Plan Actual
              </div>
            )}

            <div className="mb-10 text-center">
              <div className={`w-14 h-14 rounded-2xl flex items-center justify-center mx-auto mb-6 transition-transform group-hover:scale-110 ${plan.id === PlanTier.BASIC ? 'bg-slate-800 text-slate-400' :
                plan.id === PlanTier.PRO ? 'bg-blue-600/20 text-blue-400' :
                  'bg-purple-600/20 text-purple-400'
                }`}>
                {plan.id === PlanTier.BASIC ? <Shield size={28} /> :
                  plan.id === PlanTier.PRO ? <Zap size={28} /> : <Crown size={28} />}
              </div>
              <h3 className="text-2xl font-black text-slate-100 italic mb-2 tracking-tight">{plan.name}</h3>
              <div className="flex items-baseline justify-center gap-1.5">
                <span className="text-5xl font-black text-white italic">${plan.price.toLocaleString()}</span>
                <span className="text-slate-500 font-bold uppercase text-[10px] tracking-widest">/mes</span>
              </div>
            </div>

            <ul className="flex-1 space-y-5 mb-10">
              {plan.features.map((feature: string, idx: number) => (
                <li key={idx} className="flex items-center gap-4 text-slate-300">
                  <div className="flex-shrink-0 w-6 h-6 rounded-full bg-blue-500/10 flex items-center justify-center border border-blue-500/20">
                    <Check size={14} className="text-blue-400" />
                  </div>
                  <span className="text-sm font-medium leading-relaxed">{feature}</span>
                </li>
              ))}
            </ul>

            <button
              disabled={tenant.plan === plan.id && tenant.subscriptionStatus === SubscriptionStatus.ACTIVE}
              onClick={() => handleSubscribeClick(plan)}
              className={`w-full py-5 rounded-[1.5rem] font-black text-lg transition-all flex items-center justify-center gap-3 ${tenant.plan === plan.id && tenant.subscriptionStatus === SubscriptionStatus.ACTIVE
                ? 'bg-slate-800/50 text-slate-600 cursor-default border border-slate-700/50'
                : 'bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 text-white shadow-xl active:scale-95 shadow-blue-600/20'
                }`}
            >
              {tenant.plan === plan.id && tenant.subscriptionStatus === SubscriptionStatus.ACTIVE ? (
                <>Plan Activo</>
              ) : (
                <>{tenant.plan === plan.id ? 'Renovar Suscripción' : `Elegir ${plan.name}`} <Sparkles size={18} /></>
              )}
            </button>
          </div>
        ))}
      </div>

      {/* History */}
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="p-3 bg-slate-900 rounded-2xl border border-slate-800 text-slate-400 shadow-xl">
              <History size={24} />
            </div>
            <h3 className="text-2xl font-black text-slate-100 italic tracking-tight">Historial de Facturación</h3>
          </div>
        </div>

        <div className="bg-slate-900/40 border border-slate-800/80 rounded-[2rem] overflow-hidden backdrop-blur-md">
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-slate-800 text-slate-500 text-[10px] font-black uppercase tracking-[0.2em] bg-slate-800/20">
                <th className="px-8 py-6">Fecha</th>
                <th className="px-8 py-6">Concepto</th>
                <th className="px-8 py-6 text-center">Importe</th>
                <th className="px-8 py-6 text-center">Estado</th>
                <th className="px-8 py-6 text-right">Comprobante</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50 text-slate-300">
              <tr className="hover:bg-slate-800/30 transition-colors">
                <td className="px-8 py-6 font-bold text-slate-400">Hoy</td>
                <td className="px-8 py-6">
                  <div className="flex flex-col">
                    <span className="font-black italic text-slate-100 uppercase tracking-tighter">Suscripción GastroFlow {PLANS[tenant.plan].name}</span>
                    <span className="text-[10px] text-slate-500 font-bold">Pago mensual vía Mercado Pago</span>
                  </div>
                </td>
                <td className="px-8 py-6 text-center">
                  <span className="text-xl font-black text-slate-200">${PLANS[tenant.plan].price.toLocaleString()}</span>
                </td>
                <td className="px-8 py-6 text-center">
                  <span className={`px-4 py-1 rounded-lg text-[10px] font-black uppercase tracking-widest border ${tenant.subscriptionStatus === SubscriptionStatus.ACTIVE
                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                    : 'bg-red-500/10 text-red-400 border-red-500/20'
                    }`}>
                    {tenant.subscriptionStatus === SubscriptionStatus.ACTIVE ? 'Aprobado' : 'Pendiente'}
                  </span>
                </td>
                <td className="px-8 py-6 text-right">
                  <button className="flex items-center gap-2 ml-auto text-blue-400 hover:text-blue-300 font-black text-[10px] uppercase tracking-widest group transition-all">
                    Factura PDF <ExternalLink size={12} className="group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Mercado Pago Checkout Modal */}
      {showCheckout && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-6 bg-slate-950/90 backdrop-blur-md animate-in fade-in duration-300">
          <div className="bg-slate-900 border border-slate-800 w-full max-w-lg rounded-[2.5rem] overflow-hidden shadow-[0_0_100px_rgba(0,0,0,0.5)] animate-in zoom-in-95 duration-300">
            <div className="bg-[#009EE3] p-8 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="bg-white p-2 rounded-lg">
                  <CreditCard size={20} className="text-[#009EE3]" />
                </div>
                <span className="text-white font-black text-xl italic">Mercado Pago Checkout</span>
              </div>
              <button onClick={() => setShowCheckout(null)} className="text-white/60 hover:text-white"><X size={24} /></button>
            </div>

            <div className="p-10 space-y-8">
              {checkoutStatus === 'idle' && (
                <>
                  <div className="space-y-4 text-center">
                    <h4 className="text-2xl font-black text-slate-100 tracking-tight">Confirmar Suscripción</h4>
                    <p className="text-slate-400">Estás por contratar el plan <b>{showCheckout.name}</b> por <b>${showCheckout.price.toLocaleString()}/mes</b>.</p>
                  </div>

                  <div className="bg-slate-800/40 p-6 rounded-3xl border border-slate-700/50 space-y-4">
                    <div className="flex justify-between text-sm">
                      <span className="text-slate-500 font-bold uppercase tracking-widest text-[10px]">Producto</span>
                      <span className="text-slate-200 font-black italic">GastroFlow {showCheckout.name}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-slate-500 font-bold uppercase tracking-widest text-[10px]">Recurrencia</span>
                      <span className="text-slate-200 font-bold">Mensual</span>
                    </div>
                    <div className="pt-4 border-t border-slate-700 flex justify-between items-center">
                      <span className="text-slate-100 font-black italic">Total a pagar hoy</span>
                      <span className="text-3xl font-black text-emerald-400">${showCheckout.price.toLocaleString()}</span>
                    </div>
                  </div>

                  <button
                    onClick={handleConfirmPayment}
                    className="w-full py-5 bg-[#009EE3] hover:bg-[#0089C7] text-white rounded-2xl font-black text-xl shadow-xl transition-all active:scale-95 flex items-center justify-center gap-3"
                  >
                    Suscribirme ahora <Sparkles size={20} />
                  </button>
                </>
              )}

              {checkoutStatus === 'processing' && (
                <div className="py-12 flex flex-col items-center text-center space-y-6">
                  <div className="w-20 h-20 bg-blue-500/10 rounded-full flex items-center justify-center">
                    <Loader2 size={40} className="animate-spin text-[#009EE3]" />
                  </div>
                  <div>
                    <h4 className="text-2xl font-black text-slate-100">Procesando Pago</h4>
                    <p className="text-slate-400 mt-2">Estamos conectando con Mercado Pago para confirmar tu transacción...</p>
                  </div>
                </div>
              )}

              {checkoutStatus === 'success' && (
                <div className="py-12 flex flex-col items-center text-center space-y-6 animate-in zoom-in-95 duration-500">
                  <div className="w-24 h-24 bg-emerald-500/20 text-emerald-400 rounded-full flex items-center justify-center shadow-lg shadow-emerald-500/20">
                    <CheckCircle2 size={50} />
                  </div>
                  <div>
                    <h4 className="text-3xl font-black text-emerald-400 italic">¡Pago Exitoso!</h4>
                    <p className="text-slate-300 mt-2">Tu plan se ha actualizado correctamente. Bienvenido a <b>GastroFlow {showCheckout.name}</b>.</p>
                  </div>

                  {reconciliationNotice && (
                    <div className="bg-amber-500/10 border border-amber-500/20 p-5 rounded-2xl flex items-start gap-3 text-left animate-in slide-in-from-bottom-2 duration-700 delay-300">
                      <Users className="text-amber-500 flex-shrink-0 mt-1" size={20} />
                      <div>
                        <p className="text-xs font-black text-amber-500 uppercase tracking-widest mb-1">Ajuste de Equipo</p>
                        <p className="text-xs text-slate-400 font-medium">Debido al límite de usuarios del Plan {showCheckout.name}, se ha mantenido activo solo al <b>Administrador</b>. Los demás usuarios han sido suspendidos temporalmente.</p>
                      </div>
                    </div>
                  )}

                  <div className="w-full pt-4">
                    <div className="h-1 w-full bg-slate-800 rounded-full overflow-hidden">
                      <div className="h-full bg-emerald-500 animate-progress"></div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

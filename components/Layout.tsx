
import React, { useState } from 'react';
import { 
  LayoutDashboard, 
  Package, 
  Users, 
  Table as TableIcon, 
  CreditCard, 
  Settings, 
  LogOut,
  ChevronLeft,
  ChevronRight,
  Menu as MenuIcon,
  Wallet,
  ShieldAlert,
  ChefHat,
  Layers,
  Crown,
  Zap,
  Shield,
  BarChart3
} from 'lucide-react';
import { db } from '../services/db';
import { PlanTier, SubscriptionStatus } from '../types';
import { PLANS } from '../constants';

interface LayoutProps {
  children: React.ReactNode;
  user: any;
  tenant: any;
  onLogout: () => void;
  activePage: string;
  setActivePage: (page: string) => void;
}

const NavItem = ({ icon: Icon, label, active, onClick, collapsed, alert }: any) => (
  <button
    onClick={onClick}
    className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-200 group ${
      active 
        ? 'bg-blue-600/20 text-blue-400 border border-blue-600/30 shadow-lg shadow-blue-500/5' 
        : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'
    } ${collapsed ? 'justify-center' : ''}`}
  >
    <div className="relative">
      <Icon size={20} className={active ? 'text-blue-400' : 'text-slate-400 group-hover:text-slate-200'} />
      {alert && <div className="absolute -top-1 -right-1 w-2 h-2 bg-red-500 rounded-full border-2 border-slate-900"></div>}
    </div>
    {!collapsed && <span className="font-bold text-sm whitespace-nowrap">{label}</span>}
  </button>
);

export const Layout: React.FC<LayoutProps> = ({ children, user, tenant, onLogout, activePage, setActivePage }) => {
  const [collapsed, setCollapsed] = useState(true);
  
  // En cloud, los permisos vienen del user (desde API); en local, del rol
  const userRole = db.query<any>('roles', user.tenantId).find(r => r.id === user.roleId);
  const permissions = user.permissions?.length ? user.permissions : (userRole?.permissions || []);

  // Determinar si está en TRIAL activo (no expirado)
  const now = Date.now();
  const trialEndsAt = tenant?.trialEndsAt ? new Date(tenant.trialEndsAt) : null;
  const isTrialActive = tenant?.subscriptionStatus === SubscriptionStatus.TRIAL && 
                        trialEndsAt && trialEndsAt.getTime() > now;

  const menuItems = [
    { id: 'tables', label: 'Salón', icon: TableIcon, permission: 'tables.view' },
    { id: 'kitchen', label: 'Cocina', icon: ChefHat, permission: 'kitchen.view' },
    { id: 'catalog', label: 'Catálogo', icon: Layers, permission: 'menu.view' },
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard, permission: 'dashboard.view' },
    { id: 'reports', label: 'Reportes BI', icon: BarChart3, permission: 'reports.view' },
    { id: 'cash', label: 'Caja/Turnos', icon: Wallet, permission: 'cash.manage' },
    { id: 'users', label: 'Usuarios y Roles', icon: Users, permission: 'users.view' },
    { id: 'billing', label: 'Suscripción', icon: CreditCard, permission: 'billing.manage' },
  ];

  // Durante TRIAL activo: mostrar TODAS las funciones
  // Después del trial o con suscripción normal: filtrar por permisos del rol
  const allowedMenuItems = menuItems.filter(item => {
    // Durante trial activo, dar acceso a todo excepto restricciones de plan
    const hasPerm = isTrialActive ? true : permissions.includes(item.permission);
    
    // El módulo de cocina solo existe para planes multi-usuario (excepto en trial que se muestra todo)
    if (item.id === 'kitchen' && tenant && !isTrialActive) {
      const isMultiUserPlan = PLANS[tenant.plan].limits.users > 1;
      return hasPerm && isMultiUserPlan;
    }
    
    return hasPerm;
  });

  const getPlanBadge = () => {
    if (!tenant) return null;
    const isBasic = tenant.plan === PlanTier.BASIC;
    const isPro = tenant.plan === PlanTier.PRO;
    
    const colors = {
      glow: isBasic ? 'shadow-slate-500/10 border-slate-700/50' : isPro ? 'shadow-blue-500/20 border-blue-500/40' : 'shadow-purple-500/20 border-purple-500/40',
      bg: isBasic ? 'bg-slate-800/30' : isPro ? 'bg-blue-600/10' : 'bg-purple-600/10',
      iconBg: isBasic ? 'bg-slate-700 text-slate-400' : isPro ? 'bg-blue-600 text-white' : 'bg-purple-600 text-white'
    };

    if (collapsed) {
      return (
        <button 
          onClick={() => setActivePage('billing')}
          className={`mx-auto w-12 h-12 rounded-2xl border flex items-center justify-center transition-all hover:scale-110 active:scale-90 shadow-xl ${colors.bg} ${colors.glow}`}
          title={`Plan ${tenant.plan}`}
        >
          <div className="relative">
            {isBasic ? <Shield size={20} className="text-slate-400" /> : isPro ? <Zap size={20} className="text-blue-400" /> : <Crown size={20} className="text-purple-400" />}
            {/* Pequeño punto de estatus activo */}
            <div className={`absolute -bottom-1 -right-1 w-2.5 h-2.5 rounded-full border-2 border-slate-900 ${isBasic ? 'bg-slate-500' : isPro ? 'bg-blue-400' : 'bg-purple-400'}`}></div>
          </div>
        </button>
      );
    }

    return (
      <button 
        onClick={() => setActivePage('billing')}
        className={`w-full p-4 rounded-2xl border flex items-center gap-3 transition-all hover:scale-[1.02] active:scale-95 group/plan shadow-xl ${colors.bg} ${colors.glow}`}
      >
        <div className={`w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 ${colors.iconBg}`}>
          {isBasic ? <Shield size={18} /> : isPro ? <Zap size={18} /> : <Crown size={18} />}
        </div>
        <div className="text-left flex-1 min-w-0">
          <p className="text-[9px] font-black text-slate-500 uppercase tracking-widest truncate">Plan Actual</p>
          <p className={`text-sm font-black italic tracking-tight truncate ${
            isBasic ? 'text-slate-300' : isPro ? 'text-blue-400' : 'text-purple-400'
          }`}>
            {tenant.plan}
          </p>
        </div>
        {permissions.includes('billing.manage') && (
          <div className="opacity-0 group-hover/plan:opacity-100 transition-opacity">
            <ChevronRight size={14} className="text-slate-500" />
          </div>
        )}
      </button>
    );
  };

  return (
    <div className="flex h-screen overflow-hidden bg-slate-950">
      <aside 
        className={`${collapsed ? 'w-24' : 'w-72'} flex flex-col border-r border-slate-800 transition-all duration-300 ease-in-out bg-slate-900/40 backdrop-blur-3xl`}
      >
        <div className="p-8 flex items-center justify-between">
          {!collapsed && (
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-600 rounded-2xl flex items-center justify-center font-black text-white italic shadow-lg shadow-blue-500/20">G</div>
              <span className="text-xl font-black bg-clip-text text-transparent bg-gradient-to-r from-blue-100 to-blue-400 italic">GastroFlow</span>
            </div>
          )}
          <button 
            onClick={() => setCollapsed(!collapsed)}
            className={`p-2 rounded-xl hover:bg-slate-800 text-slate-400 transition-all active:scale-90 ${collapsed ? 'mx-auto' : ''}`}
          >
            {collapsed ? <ChevronRight size={20} /> : <ChevronLeft size={20} />}
          </button>
        </div>

        <nav className="flex-1 px-4 space-y-1.5 scrollbar-hide overflow-y-auto">
          {allowedMenuItems.map((item) => (
            <NavItem 
              key={item.id}
              icon={item.icon}
              label={item.label}
              active={activePage === item.id}
              onClick={() => setActivePage(item.id)}
              collapsed={collapsed}
            />
          ))}
        </nav>

        <div className="p-6 border-t border-slate-800 space-y-6">
          <div className="flex justify-center">
            {getPlanBadge()}
          </div>
          
          <div className="space-y-3">
            {!collapsed && (
              <div className={`px-4 py-3 rounded-2xl border ${
                userRole?.name === 'Administrador' ? 'bg-blue-600/10 border-blue-500/20' : 'bg-slate-800/30 border-slate-700/50'
              }`}>
                <p className="text-[10px] text-slate-500 uppercase font-black tracking-widest mb-1">
                  {userRole?.name || 'Invitado'}
                </p>
                <p className="text-sm font-bold text-slate-200 truncate">{user.name}</p>
              </div>
            )}
            <button
              onClick={onLogout}
              className={`w-full flex items-center gap-3 px-4 py-3 text-red-400 hover:bg-red-400/10 rounded-xl transition-all active:scale-[0.98] ${collapsed ? 'justify-center' : ''}`}
            >
              <LogOut size={20} />
              {!collapsed && <span className="font-bold text-sm">Cerrar Sesión</span>}
            </button>
          </div>
        </div>
      </aside>

      <main className="flex-1 flex flex-col overflow-hidden">
        <header className="h-20 border-b border-slate-800 flex items-center justify-between px-10 bg-slate-950/40 backdrop-blur-md">
          <h1 className="text-2xl font-black text-slate-100 tracking-tight italic">
            {menuItems.find(i => i.id === activePage)?.label || 'Panel'}
          </h1>
          <div className="flex items-center gap-4">
             <div className="flex flex-col items-end mr-2">
                <span className={`text-[10px] font-black uppercase tracking-widest ${
                  userRole?.name === 'Administrador' ? 'text-blue-400' : 'text-slate-500'
                }`}>
                  {userRole?.name}
                </span>
                <span className="text-sm font-bold text-slate-200">{user.name}</span>
             </div>
             <div className={`h-12 w-12 rounded-2xl flex items-center justify-center text-lg font-black italic shadow-xl border border-white/10 ${
                userRole?.name === 'Administrador' 
                ? 'bg-gradient-to-tr from-blue-600 to-purple-600 shadow-blue-500/10' 
                : 'bg-slate-800 shadow-black'
             }`}>
              {user.name.charAt(0)}
            </div>
          </div>
        </header>
        
        <div className="flex-1 overflow-y-auto p-10 custom-scrollbar">
          {children}
        </div>
      </main>
    </div>
  );
};

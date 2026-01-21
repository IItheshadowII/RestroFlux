
import React, { useState, useEffect } from 'react';
import { Layout } from './components/Layout';
import { Dashboard } from './pages/Dashboard';
import { CatalogPage } from './pages/Catalog';
import { TablesPage } from './pages/Tables';
import { UsersRolesPage } from './pages/UsersRoles';
import { BillingPage } from './pages/Billing';
import { CashierPage } from './pages/Cashier';
import { KitchenPage } from './pages/Kitchen';
import { ReportsPage } from './pages/Reports';
import { db } from './services/db';
import { User, Tenant, SubscriptionStatus, PlanTier } from './types';
import { LogIn, Key, Mail, Store, AlertTriangle, ShieldX } from 'lucide-react';

const LoginPage = ({ onLogin }: { onLogin: (u: User) => void }) => {
  const [email, setEmail] = useState('admin@demo.com');
  const [password, setPassword] = useState('password123');
  const [loading, setLoading] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setTimeout(() => {
      const user = db.getUserByEmail(email);
      if (user) {
        onLogin(user);
      } else {
        alert('Credenciales inválidas');
      }
      setLoading(false);
    }, 1000);
  };

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-6 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-blue-900/20 via-slate-950 to-slate-950">
      <div className="w-full max-w-md">
        <div className="text-center mb-10 space-y-4">
          <div className="mx-auto w-16 h-16 bg-gradient-to-br from-blue-500 to-purple-600 rounded-2xl flex items-center justify-center text-3xl font-bold italic shadow-2xl shadow-blue-500/20">G</div>
          <h1 className="text-4xl font-black tracking-tight text-white italic">GastroFlow</h1>
          <p className="text-slate-400">Panel de control multi-tenant</p>
        </div>

        <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-800 p-8 rounded-3xl shadow-2xl">
          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="space-y-2">
              <label className="text-sm font-bold text-slate-400 uppercase tracking-widest ml-1">Email</label>
              <div className="relative">
                <Mail className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full bg-slate-800/50 border border-slate-700 text-white rounded-2xl py-3 pl-12 pr-4 focus:ring-2 focus:ring-blue-500/50 outline-none transition-all"
                  placeholder="admin@demo.com"
                />
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-bold text-slate-400 uppercase tracking-widest ml-1">Contraseña</label>
              <div className="relative">
                <Key className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full bg-slate-800/50 border border-slate-700 text-white rounded-2xl py-3 pl-12 pr-4 focus:ring-2 focus:ring-blue-500/50 outline-none transition-all"
                  placeholder="••••••••"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 text-white font-bold py-4 rounded-2xl transition-all shadow-xl shadow-blue-900/20 flex items-center justify-center gap-2 group"
            >
              {loading ? 'Validando...' : (
                <>
                  Entrar al Sistema
                  <LogIn size={20} className="group-hover:translate-x-1 transition-transform" />
                </>
              )}
            </button>
          </form>

          <div className="mt-8 pt-8 border-t border-slate-800 text-center">
            <button className="text-slate-500 hover:text-blue-400 text-sm font-medium transition-colors">
              ¿Olvidaste tu contraseña?
            </button>
          </div>
        </div>

        <p className="text-center mt-8 text-slate-500 text-xs">
          © 2024 GastroFlow SaaS. Versión 2.1.0-beta
        </p>
      </div>
    </div>
  );
};

const AccessDenied = () => (
  <div className="flex flex-col items-center justify-center min-h-[60vh] text-center space-y-6 animate-in fade-in duration-500">
    <div className="w-24 h-24 bg-red-500/10 text-red-500 rounded-full flex items-center justify-center shadow-2xl border border-red-500/20">
      <ShieldX size={48} />
    </div>
    <div className="space-y-2">
      <h2 className="text-4xl font-black italic text-slate-100 tracking-tight">Acceso Restringido</h2>
      <p className="text-slate-500 max-w-sm mx-auto font-medium">No tienes los permisos necesarios para visualizar este módulo. Por favor, contacta a un administrador.</p>
    </div>
  </div>
);

const App: React.FC = () => {
  const [user, setUser] = useState<User | null>(null);
  const [tenant, setTenant] = useState<Tenant | null>(null);
  const [activePage, setActivePage] = useState('tables');

  const isCloud = (import.meta as any).env.VITE_APP_MODE === 'CLOUD' ||
    (!window.location.hostname.includes('localhost') && !window.location.hostname.includes('127.0.0.1'));

  const fetchTenantFromApi = async (tenantId: string): Promise<Tenant | null> => {
    try {
      const res = await fetch(`/api/tenants/${tenantId}`);
      if (!res.ok) return null;
      return await res.json();
    } catch (err) {
      console.error('Error fetching tenant from API:', err);
      return null;
    }
  };

  useEffect(() => {
    const stored = localStorage.getItem('gastroflow_current_user');
    if (stored) {
      const u = JSON.parse(stored);
      setUser(u);
      // Intentar cargar desde backend en CLOUD, fallback a local
      if (isCloud) {
        fetchTenantFromApi(u.tenantId).then((t) => setTenant(t || db.getTenant(u.tenantId) || null));
      } else {
        setTenant(db.getTenant(u.tenantId) || null);
      }
    }

    // Global event listener for tab switching
    const handleSwitchTab = (e: any) => {
      setActivePage(e.detail);
    };
    window.addEventListener('switchTab', handleSwitchTab);
    return () => window.removeEventListener('switchTab', handleSwitchTab);
  }, []);

  const handleLogin = (u: User) => {
    setUser(u);
    localStorage.setItem('gastroflow_current_user', JSON.stringify(u));
    if (isCloud) {
      fetchTenantFromApi(u.tenantId).then((t) => setTenant(t || db.getTenant(u.tenantId) || null));
    } else {
      setTenant(db.getTenant(u.tenantId) || null);
    }
  };

  const handleLogout = () => {
    setUser(null);
    setTenant(null);
    localStorage.removeItem('gastroflow_current_user');
  };

  const refreshTenantData = () => {
    if (!user) return;
    if (isCloud) {
      fetchTenantFromApi(user.tenantId).then((t) => {
        if (t) setTenant(t);
        else setTenant(db.getTenant(user.tenantId) || null);
      });
      return;
    }
    setTenant(db.getTenant(user.tenantId) || null);
  };

  if (!user || !tenant) {
    return <LoginPage onLogin={handleLogin} />;
  }

  // Multi-tenant Billing Lock
  const isLocked = tenant.subscriptionStatus !== SubscriptionStatus.ACTIVE;
  const currentActivePage = isLocked ? 'billing' : activePage;

  // Lógica de permisos por rol
  const userRole = db.query<any>('roles', user.tenantId).find(r => r.id === user.roleId);
  const permissions = userRole?.permissions || [];

  const pagePermissionMap: Record<string, string> = {
    'dashboard': 'dashboard.view',
    'reports': 'reports.view',
    'tables': 'tables.view',
    'kitchen': 'kitchen.view',
    'catalog': 'menu.view',
    'users': 'users.view',
    'billing': 'billing.manage',
    'cash': 'cash.manage'
  };

  const hasAccess = !pagePermissionMap[currentActivePage] || permissions.includes(pagePermissionMap[currentActivePage]);

  return (
    <Layout
      user={user}
      onLogout={handleLogout}
      activePage={currentActivePage}
      setActivePage={setActivePage}
    >
      {isLocked && (
        <div className="mb-10 p-8 bg-red-500/10 border-2 border-red-500/20 rounded-[2rem] flex flex-col md:flex-row items-center gap-8 text-red-400 shadow-2xl animate-in slide-in-from-top-4 duration-500">
          <div className="w-16 h-16 bg-red-500/20 rounded-2xl flex items-center justify-center flex-shrink-0">
            <Store size={32} />
          </div>
          <div className="flex-1 text-center md:text-left">
            <h4 className="text-xl font-black italic tracking-tight uppercase">Suscripción Suspendida / Bloqueada</h4>
            <p className="text-sm opacity-90 mt-1 font-bold">Tu cuenta ha sido limitada debido a un problema con el pago de Mercado Pago o el fin del periodo de gracia.</p>
          </div>
          <button
            onClick={() => setActivePage('billing')}
            className="px-10 py-4 bg-red-600 hover:bg-red-500 text-white rounded-2xl font-black transition-all shadow-xl shadow-red-600/30 active:scale-95 flex items-center gap-2"
          >
            Regularizar Cuenta <AlertTriangle size={18} />
          </button>
        </div>
      )}

      {!hasAccess ? <AccessDenied /> : (
        <>
          {currentActivePage === 'dashboard' && <Dashboard tenantId={tenant.id} />}
          {currentActivePage === 'reports' && <ReportsPage tenantId={tenant.id} />}
          {currentActivePage === 'catalog' && <CatalogPage tenantId={tenant.id} user={user} />}
          {currentActivePage === 'kitchen' && <KitchenPage tenantId={tenant.id} />}
          {currentActivePage === 'tables' && <TablesPage tenantId={tenant.id} user={user} />}
          {currentActivePage === 'users' && <UsersRolesPage tenantId={tenant.id} />}
          {currentActivePage === 'billing' && <BillingPage tenant={tenant} user={user} onUpdate={refreshTenantData} />}
          {currentActivePage === 'cash' && <CashierPage tenantId={tenant.id} user={user} />}
        </>
      )}
    </Layout>
  );
};

export default App;

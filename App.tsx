
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
import { LogIn, Key, Mail, Store, AlertTriangle, ShieldX, Building2, Users, CreditCard, Clock, ChevronDown, ChevronUp, Loader2, RefreshCw, X } from 'lucide-react';

type TenantOption = { id: string; name: string; slug?: string };

const getQueryParams = () => {
  try {
    return new URLSearchParams(window.location.search || '');
  } catch {
    return new URLSearchParams();
  }
};

const getPathArea = (): 'admin' | 'app' => {
  const p = window.location.pathname || '/';
  if (p.startsWith('/admin')) return 'admin';
  return 'app';
};

const TenantLoginPage = ({ onLogin, isCloud }: { onLogin: (u: User) => void; isCloud: boolean }) => {
  const [email, setEmail] = useState('admin@demo.com');
  const [password, setPassword] = useState('password123');
  const [tenantOptions, setTenantOptions] = useState<TenantOption[] | null>(null);
  const [selectedTenantId, setSelectedTenantId] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const tryAdminLoginAndRedirect = async (): Promise<boolean> => {
    try {
      const adminRes = await fetch('/api/admin/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      const adminData = await adminRes.json().catch(() => ({}));
      if (adminRes.ok && adminData?.ok && adminData?.token && adminData?.user) {
        localStorage.setItem('gastroflow_admin_token', adminData.token);
        localStorage.setItem('gastroflow_admin_user', JSON.stringify(adminData.user));
        window.location.href = '/admin';
        return true;
      }
    } catch (e) {
      console.error('Fallback admin login error:', e);
    }
    return false;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      if (isCloud) {
        const res = await fetch('/api/app/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email,
            password,
            ...(selectedTenantId ? { tenantId: selectedTenantId } : {})
          })
        });

        const data = await res.json().catch(() => ({}));

        if (res.status === 409 && Array.isArray(data?.tenants)) {
          setTenantOptions(data.tenants);
          setSelectedTenantId(data.tenants[0]?.id || '');
          setError(null);
          return;
        }

        if (!res.ok || !data?.ok || !data?.token || !data?.user) {
          // If the app-login failed because the account is global/admin, try admin login automatically
          const errMsg = data?.error || 'Credenciales inválidas';
          // Common case: email belongs to a global admin (there will be no tenant candidates)
          // We try admin-login once; if it fails, we fall back to showing the original error.
          const redirected = await tryAdminLoginAndRedirect();
          if (redirected) return;
          setError(errMsg);
          return;
        }

        if (data.scope !== 'tenant') {
          // In case backend returned a non-tenant scope here (or misrouted auth), try admin-login
          const redirected = await tryAdminLoginAndRedirect();
          if (!redirected) {
            setError('Este frontend actualmente requiere login de tenant (no global).');
          }
          return;
        }

        localStorage.setItem('gastroflow_token', data.token);
        localStorage.setItem('gastroflow_last_tenant_id', data.user.tenantId);

        const u: User = {
          id: data.user.id,
          tenantId: data.user.tenantId,
          email: data.user.email,
          name: data.user.name,
          roleId: data.user.roleId,
          isActive: true,
          permissions: Array.isArray(data.user.permissions) ? data.user.permissions : []
        };

        onLogin(u);
        return;
      }

      // LOCAL mode
      const user = db.getUserByEmail(email);
      if (user) {
        onLogin(user);
      } else {
        setError('Credenciales inválidas');
      }
    } catch (err: any) {
      console.error('Login error:', err);
      setError(err?.message || 'Error de conexión');
    } finally {
      setLoading(false);
    }
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
            {isCloud && tenantOptions && tenantOptions.length > 0 && (
              <div className="space-y-2">
                <label className="text-sm font-bold text-slate-400 uppercase tracking-widest ml-1">Empresa</label>
                <div className="relative">
                  <Store className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
                  <select
                    value={selectedTenantId}
                    onChange={(e) => setSelectedTenantId(e.target.value)}
                    className="w-full bg-slate-800/50 border border-slate-700 text-white rounded-2xl py-3 pl-12 pr-4 focus:ring-2 focus:ring-blue-500/50 outline-none transition-all"
                  >
                    {tenantOptions.map((t) => (
                      <option key={t.id} value={t.id}>
                        {t.name}{t.slug ? ` (${t.slug})` : ''}
                      </option>
                    ))}
                  </select>
                </div>
                <p className="text-xs text-slate-500 font-medium">Este email está asociado a más de una empresa.</p>
              </div>
            )}

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

            {error && (
              <div className="bg-red-500/10 border border-red-500/20 text-red-300 rounded-2xl p-4 text-sm font-bold">
                {error}
              </div>
            )}

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
              <div className="space-y-3">
                <button
                  type="button"
                  onClick={() => { window.location.href = '/app/forgot-password'; }}
                  className="text-slate-500 hover:text-blue-400 text-sm font-medium transition-colors"
                >
                  ¿Olvidaste tu contraseña?
                </button>
                <div className="text-sm text-slate-600">
                  ¿No tenés cuenta?{' '}
                  <button
                    type="button"
                    onClick={() => { window.location.href = '/app/register'; }}
                    className="text-blue-400 hover:text-blue-300 font-bold transition-colors"
                  >
                    Registrate
                  </button>
                </div>
              </div>
          </div>
        </div>

        <p className="text-center mt-8 text-slate-500 text-xs">
          © 2024 GastroFlow SaaS. Versión 2.1.0-beta
        </p>
      </div>
    </div>
  );
};

const AdminLoginPage = ({ onLogin }: { onLogin: (u: { id: string; email: string; name: string }) => void }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await fetch('/api/admin/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data?.ok || !data?.token || !data?.user) {
        setError(data?.error || 'Credenciales inválidas');
        return;
      }
      localStorage.setItem('gastroflow_admin_token', data.token);
      localStorage.setItem('gastroflow_admin_user', JSON.stringify(data.user));
      onLogin(data.user);
    } catch (err: any) {
      console.error('Admin login error:', err);
      setError(err?.message || 'Error de conexión');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-6 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-purple-900/20 via-slate-950 to-slate-950">
      <div className="w-full max-w-md">
        <div className="text-center mb-10 space-y-4">
          <div className="mx-auto w-16 h-16 bg-gradient-to-br from-purple-500 to-blue-600 rounded-2xl flex items-center justify-center text-3xl font-bold italic shadow-2xl shadow-purple-500/20">G</div>
          <h1 className="text-4xl font-black tracking-tight text-white italic">GastroFlow</h1>
          <p className="text-slate-400">Admin de Plataforma (owner)</p>
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
                  className="w-full bg-slate-800/50 border border-slate-700 text-white rounded-2xl py-3 pl-12 pr-4 focus:ring-2 focus:ring-purple-500/50 outline-none transition-all"
                  placeholder="owner@tuempresa.com"
                />
              </div>
            </div>

            {error && (
              <div className="bg-red-500/10 border border-red-500/20 text-red-300 rounded-2xl p-4 text-sm font-bold">
                {error}
              </div>
            )}

            <div className="space-y-2">
              <label className="text-sm font-bold text-slate-400 uppercase tracking-widest ml-1">Contraseña</label>
              <div className="relative">
                <Key className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full bg-slate-800/50 border border-slate-700 text-white rounded-2xl py-3 pl-12 pr-4 focus:ring-2 focus:ring-purple-500/50 outline-none transition-all"
                  placeholder="••••••••"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-500 hover:to-blue-500 text-white font-bold py-4 rounded-2xl transition-all shadow-xl shadow-purple-900/20 flex items-center justify-center gap-2 group"
            >
              {loading ? 'Validando...' : (
                <>
                  Entrar al Admin
                  <LogIn size={20} className="group-hover:translate-x-1 transition-transform" />
                </>
              )}
            </button>
          </form>

          <div className="mt-8 pt-8 border-t border-slate-800 text-center">
            <button
              type="button"
              onClick={() => { window.location.href = '/admin/forgot-password'; }}
              className="text-slate-500 hover:text-purple-400 text-sm font-medium transition-colors"
            >
              ¿Olvidaste tu contraseña?
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

const AppForgotPasswordPage = ({ isCloud }: { isCloud: boolean }) => {
  const [email, setEmail] = useState('');
  const [tenantOptions, setTenantOptions] = useState<TenantOption[] | null>(null);
  const [selectedTenantId, setSelectedTenantId] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      if (!isCloud) {
        setSent(true);
        return;
      }
      const res = await fetch('/api/app/auth/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email,
          ...(selectedTenantId ? { tenantId: selectedTenantId } : {})
        })
      });
      const data = await res.json().catch(() => ({}));
      if (res.status === 409 && Array.isArray(data?.tenants)) {
        setTenantOptions(data.tenants);
        setSelectedTenantId(data.tenants[0]?.id || '');
        setError(null);
        return;
      }
      if (!res.ok || !data?.ok) {
        setError(data?.error || 'No se pudo enviar el email');
        return;
      }
      setSent(true);
    } catch (err: any) {
      setError(err?.message || 'Error de conexión');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-6 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-blue-900/20 via-slate-950 to-slate-950">
      <div className="w-full max-w-md">
        <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-800 p-8 rounded-3xl shadow-2xl">
          <h1 className="text-2xl font-black text-white italic mb-2">Recuperar contraseña</h1>
          <p className="text-slate-400 text-sm mb-6">Te enviaremos un link si el email existe.</p>

          {sent ? (
            <div className="space-y-6">
              <div className="bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 rounded-2xl p-4 text-sm font-bold">
                Listo. Si el email existe, vas a recibir un link de recuperación.
              </div>
              <button
                type="button"
                onClick={() => { window.location.href = '/app'; }}
                className="w-full bg-slate-800 hover:bg-slate-700 text-white font-bold py-3 rounded-2xl transition-all"
              >
                Volver al login
              </button>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-5">
              {isCloud && tenantOptions && tenantOptions.length > 0 && (
                <div className="space-y-2">
                  <label className="text-sm font-bold text-slate-400 uppercase tracking-widest ml-1">Empresa</label>
                  <div className="relative">
                    <Store className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
                    <select
                      value={selectedTenantId}
                      onChange={(e) => setSelectedTenantId(e.target.value)}
                      className="w-full bg-slate-800/50 border border-slate-700 text-white rounded-2xl py-3 pl-12 pr-4 focus:ring-2 focus:ring-blue-500/50 outline-none transition-all"
                    >
                      {tenantOptions.map((t) => (
                        <option key={t.id} value={t.id}>
                          {t.name}{t.slug ? ` (${t.slug})` : ''}
                        </option>
                      ))}
                    </select>
                  </div>
                  <p className="text-xs text-slate-500 font-medium">Este email está asociado a más de una empresa.</p>
                </div>
              )}
              <div className="space-y-2">
                <label className="text-sm font-bold text-slate-400 uppercase tracking-widest ml-1">Email</label>
                <div className="relative">
                  <Mail className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full bg-slate-800/50 border border-slate-700 text-white rounded-2xl py-3 pl-12 pr-4 focus:ring-2 focus:ring-blue-500/50 outline-none transition-all"
                    placeholder="tu@email.com"
                    required
                  />
                </div>
              </div>

              {error && (
                <div className="bg-red-500/10 border border-red-500/20 text-red-300 rounded-2xl p-4 text-sm font-bold">
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={loading}
                className="w-full bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 text-white font-bold py-4 rounded-2xl transition-all"
              >
                {loading ? 'Enviando...' : 'Enviar link'}
              </button>

              <button
                type="button"
                onClick={() => { window.location.href = '/app'; }}
                className="w-full text-slate-500 hover:text-slate-200 text-sm font-medium transition-colors"
              >
                Volver
              </button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};

const AppResetPasswordPage = ({ isCloud }: { isCloud: boolean }) => {
  const q = getQueryParams();
  const initialEmail = q.get('email') || '';
  const token = q.get('token') || '';
  const [email, setEmail] = useState(initialEmail);
  const [newPassword, setNewPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!token) {
      setError('Token faltante');
      return;
    }
    if (newPassword.length < 8) {
      setError('La contraseña debe tener al menos 8 caracteres');
      return;
    }
    if (newPassword !== confirm) {
      setError('Las contraseñas no coinciden');
      return;
    }
    setLoading(true);
    try {
      if (!isCloud) {
        setOk(true);
        return;
      }
      const res = await fetch('/api/app/auth/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, token, newPassword })
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data?.ok) {
        setError(data?.error || 'No se pudo resetear');
        return;
      }
      setOk(true);
    } catch (err: any) {
      setError(err?.message || 'Error de conexión');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-6 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-blue-900/20 via-slate-950 to-slate-950">
      <div className="w-full max-w-md">
        <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-800 p-8 rounded-3xl shadow-2xl">
          <h1 className="text-2xl font-black text-white italic mb-2">Nueva contraseña</h1>
          <p className="text-slate-400 text-sm mb-6">Definí una nueva contraseña para tu cuenta.</p>

          {ok ? (
            <div className="space-y-6">
              <div className="bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 rounded-2xl p-4 text-sm font-bold">
                Contraseña actualizada. Ya podés iniciar sesión.
              </div>
              <button
                type="button"
                onClick={() => { window.location.href = '/app'; }}
                className="w-full bg-slate-800 hover:bg-slate-700 text-white font-bold py-3 rounded-2xl transition-all"
              >
                Ir al login
              </button>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-5">
              <div className="space-y-2">
                <label className="text-sm font-bold text-slate-400 uppercase tracking-widest ml-1">Email</label>
                <div className="relative">
                  <Mail className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full bg-slate-800/50 border border-slate-700 text-white rounded-2xl py-3 pl-12 pr-4 focus:ring-2 focus:ring-blue-500/50 outline-none transition-all"
                    required
                  />
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-sm font-bold text-slate-400 uppercase tracking-widest ml-1">Contraseña nueva</label>
                <div className="relative">
                  <Key className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
                  <input
                    type="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="w-full bg-slate-800/50 border border-slate-700 text-white rounded-2xl py-3 pl-12 pr-4 focus:ring-2 focus:ring-blue-500/50 outline-none transition-all"
                    placeholder="mínimo 8 caracteres"
                    required
                  />
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-sm font-bold text-slate-400 uppercase tracking-widest ml-1">Confirmar contraseña</label>
                <div className="relative">
                  <Key className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
                  <input
                    type="password"
                    value={confirm}
                    onChange={(e) => setConfirm(e.target.value)}
                    className="w-full bg-slate-800/50 border border-slate-700 text-white rounded-2xl py-3 pl-12 pr-4 focus:ring-2 focus:ring-blue-500/50 outline-none transition-all"
                    required
                  />
                </div>
              </div>

              {error && (
                <div className="bg-red-500/10 border border-red-500/20 text-red-300 rounded-2xl p-4 text-sm font-bold">
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={loading}
                className="w-full bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 text-white font-bold py-4 rounded-2xl transition-all"
              >
                {loading ? 'Actualizando...' : 'Cambiar contraseña'}
              </button>

              <button
                type="button"
                onClick={() => { window.location.href = '/app'; }}
                className="w-full text-slate-500 hover:text-slate-200 text-sm font-medium transition-colors"
              >
                Volver
              </button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};

const AppRegisterPage = ({ isCloud, onLogin }: { isCloud: boolean; onLogin: (u: User) => void }) => {
  const [tenantName, setTenantName] = useState('');
  const [tenantSlug, setTenantSlug] = useState('');
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      if (!isCloud) {
        setError('El registro automático está disponible solo en modo CLOUD.');
        return;
      }
      const res = await fetch('/api/app/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tenantName, tenantSlug: tenantSlug || undefined, name, email, password })
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data?.ok || !data?.token || !data?.user) {
        setError(data?.error || 'No se pudo registrar');
        return;
      }
      localStorage.setItem('gastroflow_token', data.token);
      localStorage.setItem('gastroflow_last_tenant_id', data.user.tenantId);

      const u: User = {
        id: data.user.id,
        tenantId: data.user.tenantId,
        email: data.user.email,
        name: data.user.name,
        roleId: data.user.roleId,
        isActive: true,
        permissions: Array.isArray(data.user.permissions) ? data.user.permissions : []
      };
      localStorage.setItem('gastroflow_current_user', JSON.stringify(u));

      window.history.replaceState({}, document.title, '/app');
      onLogin(u);
    } catch (err: any) {
      setError(err?.message || 'Error de conexión');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-6 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-blue-900/20 via-slate-950 to-slate-950">
      <div className="w-full max-w-md">
        <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-800 p-8 rounded-3xl shadow-2xl">
          <h1 className="text-2xl font-black text-white italic mb-2">Crear cuenta</h1>
          <p className="text-slate-400 text-sm mb-6">Creá tu empresa y el usuario administrador.</p>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="space-y-2">
              <label className="text-sm font-bold text-slate-400 uppercase tracking-widest ml-1">Empresa</label>
              <div className="relative">
                <Store className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
                <input
                  value={tenantName}
                  onChange={(e) => setTenantName(e.target.value)}
                  className="w-full bg-slate-800/50 border border-slate-700 text-white rounded-2xl py-3 pl-12 pr-4 focus:ring-2 focus:ring-blue-500/50 outline-none transition-all"
                  placeholder="Mi Restaurant"
                  required
                />
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-bold text-slate-400 uppercase tracking-widest ml-1">Slug (opcional)</label>
              <input
                value={tenantSlug}
                onChange={(e) => setTenantSlug(e.target.value)}
                className="w-full bg-slate-800/50 border border-slate-700 text-white rounded-2xl py-3 px-4 focus:ring-2 focus:ring-blue-500/50 outline-none transition-all"
                placeholder="mi-restaurant"
              />
              <p className="text-xs text-slate-500 font-medium">Se usa para identificar tu empresa (si está libre).</p>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-bold text-slate-400 uppercase tracking-widest ml-1">Tu nombre</label>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full bg-slate-800/50 border border-slate-700 text-white rounded-2xl py-3 px-4 focus:ring-2 focus:ring-blue-500/50 outline-none transition-all"
                placeholder="Juan Pérez"
                required
              />
            </div>

            <div className="space-y-2">
              <label className="text-sm font-bold text-slate-400 uppercase tracking-widest ml-1">Email</label>
              <div className="relative">
                <Mail className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full bg-slate-800/50 border border-slate-700 text-white rounded-2xl py-3 pl-12 pr-4 focus:ring-2 focus:ring-blue-500/50 outline-none transition-all"
                  placeholder="tu@email.com"
                  required
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
                  placeholder="mínimo 8 caracteres"
                  required
                />
              </div>
            </div>

            {error && (
              <div className="bg-red-500/10 border border-red-500/20 text-red-300 rounded-2xl p-4 text-sm font-bold">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 text-white font-bold py-4 rounded-2xl transition-all"
            >
              {loading ? 'Creando...' : 'Crear cuenta'}
            </button>

            <button
              type="button"
              onClick={() => { window.location.href = '/app'; }}
              className="w-full text-slate-500 hover:text-slate-200 text-sm font-medium transition-colors"
            >
              Ya tengo cuenta
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};

const AdminForgotPasswordPage = () => {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await fetch('/api/admin/auth/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data?.ok) {
        setError(data?.error || 'No se pudo enviar el email');
        return;
      }
      setSent(true);
    } catch (err: any) {
      setError(err?.message || 'Error de conexión');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-6 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-purple-900/20 via-slate-950 to-slate-950">
      <div className="w-full max-w-md">
        <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-800 p-8 rounded-3xl shadow-2xl">
          <h1 className="text-2xl font-black text-white italic mb-2">Recuperar contraseña (Admin)</h1>
          <p className="text-slate-400 text-sm mb-6">Te enviaremos un link si el email existe.</p>

          {sent ? (
            <div className="space-y-6">
              <div className="bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 rounded-2xl p-4 text-sm font-bold">
                Listo. Si el email existe, vas a recibir un link de recuperación.
              </div>
              <button
                type="button"
                onClick={() => { window.location.href = '/admin'; }}
                className="w-full bg-slate-800 hover:bg-slate-700 text-white font-bold py-3 rounded-2xl transition-all"
              >
                Volver
              </button>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-5">
              <div className="space-y-2">
                <label className="text-sm font-bold text-slate-400 uppercase tracking-widest ml-1">Email</label>
                <div className="relative">
                  <Mail className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full bg-slate-800/50 border border-slate-700 text-white rounded-2xl py-3 pl-12 pr-4 focus:ring-2 focus:ring-purple-500/50 outline-none transition-all"
                    placeholder="owner@tuempresa.com"
                    required
                  />
                </div>
              </div>

              {error && (
                <div className="bg-red-500/10 border border-red-500/20 text-red-300 rounded-2xl p-4 text-sm font-bold">
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={loading}
                className="w-full bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-500 hover:to-blue-500 text-white font-bold py-4 rounded-2xl transition-all"
              >
                {loading ? 'Enviando...' : 'Enviar link'}
              </button>

              <button
                type="button"
                onClick={() => { window.location.href = '/admin'; }}
                className="w-full text-slate-500 hover:text-slate-200 text-sm font-medium transition-colors"
              >
                Volver
              </button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};

const AdminResetPasswordPage = () => {
  const q = getQueryParams();
  const initialEmail = q.get('email') || '';
  const token = q.get('token') || '';
  const [email, setEmail] = useState(initialEmail);
  const [newPassword, setNewPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!token) {
      setError('Token faltante');
      return;
    }
    if (newPassword.length < 8) {
      setError('La contraseña debe tener al menos 8 caracteres');
      return;
    }
    if (newPassword !== confirm) {
      setError('Las contraseñas no coinciden');
      return;
    }
    setLoading(true);
    try {
      const res = await fetch('/api/admin/auth/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, token, newPassword })
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data?.ok) {
        setError(data?.error || 'No se pudo resetear');
        return;
      }
      setOk(true);
    } catch (err: any) {
      setError(err?.message || 'Error de conexión');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-6 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-purple-900/20 via-slate-950 to-slate-950">
      <div className="w-full max-w-md">
        <div className="bg-slate-900/50 backdrop-blur-xl border border-slate-800 p-8 rounded-3xl shadow-2xl">
          <h1 className="text-2xl font-black text-white italic mb-2">Nueva contraseña (Admin)</h1>
          <p className="text-slate-400 text-sm mb-6">Definí una nueva contraseña para tu cuenta.</p>

          {ok ? (
            <div className="space-y-6">
              <div className="bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 rounded-2xl p-4 text-sm font-bold">
                Contraseña actualizada. Ya podés iniciar sesión.
              </div>
              <button
                type="button"
                onClick={() => { window.location.href = '/admin'; }}
                className="w-full bg-slate-800 hover:bg-slate-700 text-white font-bold py-3 rounded-2xl transition-all"
              >
                Ir al login
              </button>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-5">
              <div className="space-y-2">
                <label className="text-sm font-bold text-slate-400 uppercase tracking-widest ml-1">Email</label>
                <div className="relative">
                  <Mail className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full bg-slate-800/50 border border-slate-700 text-white rounded-2xl py-3 pl-12 pr-4 focus:ring-2 focus:ring-purple-500/50 outline-none transition-all"
                    required
                  />
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-sm font-bold text-slate-400 uppercase tracking-widest ml-1">Contraseña nueva</label>
                <div className="relative">
                  <Key className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
                  <input
                    type="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="w-full bg-slate-800/50 border border-slate-700 text-white rounded-2xl py-3 pl-12 pr-4 focus:ring-2 focus:ring-purple-500/50 outline-none transition-all"
                    placeholder="mínimo 8 caracteres"
                    required
                  />
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-sm font-bold text-slate-400 uppercase tracking-widest ml-1">Confirmar contraseña</label>
                <div className="relative">
                  <Key className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
                  <input
                    type="password"
                    value={confirm}
                    onChange={(e) => setConfirm(e.target.value)}
                    className="w-full bg-slate-800/50 border border-slate-700 text-white rounded-2xl py-3 pl-12 pr-4 focus:ring-2 focus:ring-purple-500/50 outline-none transition-all"
                    required
                  />
                </div>
              </div>

              {error && (
                <div className="bg-red-500/10 border border-red-500/20 text-red-300 rounded-2xl p-4 text-sm font-bold">
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={loading}
                className="w-full bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-500 hover:to-blue-500 text-white font-bold py-4 rounded-2xl transition-all"
              >
                {loading ? 'Actualizando...' : 'Cambiar contraseña'}
              </button>

              <button
                type="button"
                onClick={() => { window.location.href = '/admin'; }}
                className="w-full text-slate-500 hover:text-slate-200 text-sm font-medium transition-colors"
              >
                Volver
              </button>
            </form>
          )}
        </div>
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

// ==========================================
// ADMIN DASHBOARD (Panel Global Owner)
// ==========================================
const AdminDashboardPage: React.FC<{ onLogout: () => void }> = ({ onLogout }) => {
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<any>(null);
  const [expandedTenant, setExpandedTenant] = useState<string | null>(null);
  const [tenantDetail, setTenantDetail] = useState<any>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [trialModal, setTrialModal] = useState<{ tenantId: string; tenantName: string } | null>(null);
  const [trialDays, setTrialDays] = useState('15');
  const [trialAction, setTrialAction] = useState<'extend' | 'end' | 'set'>('extend');
  const [trialDate, setTrialDate] = useState('');
  const [actionLoading, setActionLoading] = useState(false);

  const fetchDashboard = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('gastroflow_admin_token');
      const res = await fetch('/api/admin/dashboard', {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) setData(await res.json());
    } catch (err) {
      console.error('Error fetching admin dashboard:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchTenantDetail = async (tenantId: string) => {
    if (expandedTenant === tenantId) {
      setExpandedTenant(null);
      setTenantDetail(null);
      return;
    }
    setExpandedTenant(tenantId);
    setLoadingDetail(true);
    try {
      const token = localStorage.getItem('gastroflow_admin_token');
      const res = await fetch(`/api/admin/tenants/${tenantId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) setTenantDetail(await res.json());
    } catch (err) {
      console.error('Error fetching tenant detail:', err);
    } finally {
      setLoadingDetail(false);
    }
  };

  const handleTrialAction = async () => {
    if (!trialModal) return;
    setActionLoading(true);
    try {
      const token = localStorage.getItem('gastroflow_admin_token');
      const body = trialAction === 'set' 
        ? { action: 'set', days: trialDate }
        : { action: trialAction, days: parseInt(trialDays, 10) };
      
      const res = await fetch(`/api/admin/tenants/${trialModal.tenantId}/trial`, {
        method: 'PATCH',
        headers: { 
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(body),
      });
      
      const result = await res.json();
      if (res.ok) {
        alert(result.message || 'Acción completada');
        setTrialModal(null);
        fetchDashboard();
      } else {
        alert(result.error || 'Error');
      }
    } catch (err) {
      console.error('Error modifying trial:', err);
      alert('Error de conexión');
    } finally {
      setActionLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboard();
  }, []);

  const formatDate = (d: string | null) =>
    d ? new Date(d).toLocaleDateString('es-AR', { day: 'numeric', month: 'short', year: 'numeric' }) : '-';

  const getStatusBadge = (status: string, trialEndsAt: string | null) => {
    const now = Date.now();
    const isTrialActive = status === 'TRIAL' && (!trialEndsAt || new Date(trialEndsAt).getTime() > now);
    const trialExpired = status === 'TRIAL' && trialEndsAt && new Date(trialEndsAt).getTime() <= now;

    if (status === 'ACTIVE') return <span className="px-2 py-1 bg-emerald-500/20 text-emerald-400 text-xs font-bold rounded-full">Activo</span>;
    if (isTrialActive) {
      const days = trialEndsAt ? Math.ceil((new Date(trialEndsAt).getTime() - now) / (1000 * 60 * 60 * 24)) : '?';
      return <span className="px-2 py-1 bg-blue-500/20 text-blue-400 text-xs font-bold rounded-full">Trial ({days}d)</span>;
    }
    if (trialExpired) return <span className="px-2 py-1 bg-orange-500/20 text-orange-400 text-xs font-bold rounded-full">Trial Vencido</span>;
    if (status === 'PAST_DUE') return <span className="px-2 py-1 bg-yellow-500/20 text-yellow-400 text-xs font-bold rounded-full">Pago Pendiente</span>;
    if (status === 'CANCELED') return <span className="px-2 py-1 bg-red-500/20 text-red-400 text-xs font-bold rounded-full">Cancelado</span>;
    return <span className="px-2 py-1 bg-slate-500/20 text-slate-400 text-xs font-bold rounded-full">{status}</span>;
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-8">
      <div className="max-w-6xl mx-auto space-y-8">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-black italic">Panel Admin Global</h1>
            <p className="text-slate-400 text-sm">Gestión de tenants, suscripciones y usuarios</p>
          </div>
          <div className="flex gap-3">
            <button onClick={fetchDashboard} className="p-3 bg-slate-800 hover:bg-slate-700 rounded-xl transition-colors">
              <RefreshCw size={18} />
            </button>
            <button onClick={onLogout} className="px-5 py-3 bg-slate-800 hover:bg-slate-700 rounded-xl font-bold transition-colors">
              Salir
            </button>
          </div>
        </div>

        {loading ? (
          <div className="flex justify-center py-20"><Loader2 className="animate-spin" size={32} /></div>
        ) : data ? (
          <>
            {/* Stats Cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-5">
                <div className="flex items-center gap-3 mb-2">
                  <Building2 size={20} className="text-blue-400" />
                  <span className="text-slate-400 text-sm font-bold">Total Tenants</span>
                </div>
                <p className="text-3xl font-black">{data.totals.total_tenants}</p>
              </div>
              <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-5">
                <div className="flex items-center gap-3 mb-2">
                  <Clock size={20} className="text-blue-400" />
                  <span className="text-slate-400 text-sm font-bold">En Trial</span>
                </div>
                <p className="text-3xl font-black text-blue-400">{data.totals.trial_tenants}</p>
              </div>
              <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-5">
                <div className="flex items-center gap-3 mb-2">
                  <CreditCard size={20} className="text-emerald-400" />
                  <span className="text-slate-400 text-sm font-bold">Activos (Pago)</span>
                </div>
                <p className="text-3xl font-black text-emerald-400">{data.totals.active_tenants}</p>
              </div>
              <div className="bg-slate-900/50 border border-slate-800 rounded-2xl p-5">
                <div className="flex items-center gap-3 mb-2">
                  <Users size={20} className="text-purple-400" />
                  <span className="text-slate-400 text-sm font-bold">Usuarios Totales</span>
                </div>
                <p className="text-3xl font-black text-purple-400">{data.totals.total_users}</p>
              </div>
            </div>

            {/* Tenants Table */}
            <div className="bg-slate-900/50 border border-slate-800 rounded-2xl overflow-hidden">
              <div className="px-6 py-4 border-b border-slate-800">
                <h2 className="text-lg font-black">Todos los Tenants</h2>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="bg-slate-800/50 text-slate-400 text-xs uppercase tracking-wider">
                    <tr>
                      <th className="px-6 py-4 text-left">Empresa</th>
                      <th className="px-6 py-4 text-left">Plan</th>
                      <th className="px-6 py-4 text-left">Estado</th>
                      <th className="px-6 py-4 text-center">Usuarios</th>
                      <th className="px-6 py-4 text-left">Vencimiento</th>
                      <th className="px-6 py-4 text-left">Acciones</th>
                      <th className="px-6 py-4"></th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/50">
                    {data.tenants.map((t: any) => (
                      <React.Fragment key={t.id}>
                        <tr className="hover:bg-slate-800/30 transition-colors">
                          <td className="px-6 py-4">
                            <div>
                              <p className="font-bold text-white">{t.name}</p>
                              <p className="text-slate-500 text-xs">{t.slug || t.id.slice(0, 8)}</p>
                            </div>
                          </td>
                          <td className="px-6 py-4">
                            <span className="px-2 py-1 bg-slate-700 text-slate-300 text-xs font-bold rounded">{t.plan}</span>
                          </td>
                          <td className="px-6 py-4">{getStatusBadge(t.subscriptionStatus || t.subscription_status, t.trialEndsAt || t.trial_ends_at)}</td>
                          <td className="px-6 py-4 text-center font-bold">{t.userCount ?? t.user_count ?? 0}</td>
                          <td className="px-6 py-4 text-slate-400">
                            {(t.subscriptionStatus === 'TRIAL' || t.subscription_status === 'TRIAL')
                              ? formatDate(t.trialEndsAt || t.trial_ends_at)
                              : formatDate(t.nextBillingDate || t.next_billing_date)}
                          </td>
                          <td className="px-6 py-4">
                            <button
                              onClick={() => setTrialModal({ tenantId: t.id, tenantName: t.name })}
                              className="px-3 py-1.5 bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 text-xs font-bold rounded-lg transition-colors"
                            >
                              Gestionar Trial
                            </button>
                          </td>
                          <td className="px-6 py-4">
                            <button
                              onClick={() => fetchTenantDetail(t.id)}
                              className="p-2 hover:bg-slate-700 rounded-lg transition-colors"
                            >
                              {expandedTenant === t.id ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                            </button>
                          </td>
                        </tr>
                        {expandedTenant === t.id && (
                          <tr>
                            <td colSpan={7} className="px-6 py-4 bg-slate-800/20">
                              {loadingDetail ? (
                                <div className="flex justify-center py-4"><Loader2 className="animate-spin" size={20} /></div>
                              ) : tenantDetail ? (
                                <div className="space-y-3">
                                  <p className="text-sm font-bold text-slate-300">Usuarios de {tenantDetail.name}:</p>
                                  {tenantDetail.users && tenantDetail.users.length > 0 ? (
                                    <div className="grid gap-2">
                                      {tenantDetail.users.map((u: any) => (
                                        <div key={u.id} className="flex items-center justify-between bg-slate-900/50 p-3 rounded-xl">
                                          <div>
                                            <p className="font-bold text-white">{u.name}</p>
                                            <p className="text-slate-500 text-xs">{u.email} • {u.role_name || 'Sin rol'}</p>
                                          </div>
                                          <div className="text-right text-xs text-slate-500">
                                            <p>{u.is_active ? '✅ Activo' : '❌ Inactivo'}</p>
                                            <p>Último login: {u.last_login ? formatDate(u.last_login) : 'Nunca'}</p>
                                          </div>
                                        </div>
                                      ))}
                                    </div>
                                  ) : (
                                    <p className="text-slate-500 text-sm">Sin usuarios registrados</p>
                                  )}
                                </div>
                              ) : (
                                <p className="text-slate-500">Error cargando detalle</p>
                              )}
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        ) : (
          <p className="text-slate-500">No se pudo cargar el dashboard</p>
        )}

        {/* Trial Management Modal */}
        {trialModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/90 backdrop-blur-md">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-md overflow-hidden shadow-2xl">
              <div className="px-6 py-4 border-b border-slate-800 flex justify-between items-center">
                <h3 className="text-lg font-black">Gestionar Trial</h3>
                <button onClick={() => setTrialModal(null)} className="p-2 hover:bg-slate-800 rounded-xl">
                  <X size={18} />
                </button>
              </div>
              <div className="p-6 space-y-5">
                <p className="text-slate-400 text-sm">
                  Tenant: <span className="font-bold text-white">{trialModal.tenantName}</span>
                </p>

                <div className="space-y-3">
                  <label className="text-sm text-slate-400 font-bold">Acción</label>
                  <div className="grid grid-cols-3 gap-2">
                    <button
                      onClick={() => setTrialAction('extend')}
                      className={`px-4 py-2 rounded-xl text-sm font-bold transition-colors ${
                        trialAction === 'extend' ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                      }`}
                    >
                      Extender
                    </button>
                    <button
                      onClick={() => setTrialAction('set')}
                      className={`px-4 py-2 rounded-xl text-sm font-bold transition-colors ${
                        trialAction === 'set' ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                      }`}
                    >
                      Establecer
                    </button>
                    <button
                      onClick={() => setTrialAction('end')}
                      className={`px-4 py-2 rounded-xl text-sm font-bold transition-colors ${
                        trialAction === 'end' ? 'bg-red-600 text-white' : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                      }`}
                    >
                      Terminar
                    </button>
                  </div>
                </div>

                {trialAction === 'extend' && (
                  <div className="space-y-2">
                    <label className="text-sm text-slate-400 font-bold">Días a agregar</label>
                    <input
                      type="number"
                      value={trialDays}
                      onChange={(e) => setTrialDays(e.target.value)}
                      min="1"
                      max="365"
                      className="w-full px-4 py-3 bg-slate-800 border border-slate-700 rounded-xl text-white"
                      placeholder="15"
                    />
                    <p className="text-xs text-slate-500">Se agregarán estos días a partir de la fecha actual o del vencimiento existente (lo que sea mayor).</p>
                  </div>
                )}

                {trialAction === 'set' && (
                  <div className="space-y-2">
                    <label className="text-sm text-slate-400 font-bold">Fecha de vencimiento</label>
                    <input
                      type="date"
                      value={trialDate}
                      onChange={(e) => setTrialDate(e.target.value)}
                      className="w-full px-4 py-3 bg-slate-800 border border-slate-700 rounded-xl text-white"
                    />
                    <p className="text-xs text-slate-500">El trial finalizará en esta fecha exacta.</p>
                  </div>
                )}

                {trialAction === 'end' && (
                  <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-xl">
                    <p className="text-red-400 text-sm font-bold">⚠️ Esto terminará el trial inmediatamente.</p>
                    <p className="text-slate-500 text-xs mt-1">El tenant pasará a estado INACTIVE y no podrá usar la app hasta que active una suscripción.</p>
                  </div>
                )}

                <div className="flex gap-3 pt-3">
                  <button
                    onClick={() => setTrialModal(null)}
                    className="flex-1 px-4 py-3 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl font-bold transition-colors"
                  >
                    Cancelar
                  </button>
                  <button
                    onClick={handleTrialAction}
                    disabled={actionLoading || (trialAction === 'set' && !trialDate)}
                    className={`flex-1 px-4 py-3 rounded-xl font-bold transition-colors disabled:opacity-50 ${
                      trialAction === 'end' 
                        ? 'bg-red-600 hover:bg-red-500 text-white' 
                        : 'bg-blue-600 hover:bg-blue-500 text-white'
                    }`}
                  >
                    {actionLoading ? <Loader2 className="animate-spin mx-auto" size={18} /> : 'Confirmar'}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

const App: React.FC = () => {
  const [user, setUser] = useState<User | null>(null);
  const [tenant, setTenant] = useState<Tenant | null>(null);
  const [activePage, setActivePage] = useState('tables');
  const [adminUser, setAdminUser] = useState<{ id: string; email: string; name: string } | null>(null);
  const area = getPathArea();

  const isCloud = (import.meta as any).env.VITE_APP_MODE === 'CLOUD' ||
    (!window.location.hostname.includes('localhost') && !window.location.hostname.includes('127.0.0.1'));

  const pathname = window.location.pathname || '/';
  const isAppRegister = pathname.startsWith('/app/register');
  const isAppForgot = pathname.startsWith('/app/forgot-password');
  const isAppReset = pathname.startsWith('/app/reset-password');
  const isAdminForgot = pathname.startsWith('/admin/forgot-password');
  const isAdminReset = pathname.startsWith('/admin/reset-password');

  const fetchTenantFromApi = async (tenantId: string): Promise<Tenant | null> => {
    try {
      const token = localStorage.getItem('gastroflow_token');
      const res = await fetch(`/api/app/tenants/${tenantId}`, {
        headers: {
          ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
        }
      });
      if (!res.ok) return null;
      return await res.json();
    } catch (err) {
      console.error('Error fetching tenant from API:', err);
      return null;
    }
  };

  const fetchMeFromApi = async (): Promise<User | null> => {
    try {
      const token = localStorage.getItem('gastroflow_token');
      if (!token) return null;
      const res = await fetch('/api/app/me', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!res.ok) return null;
      const data = await res.json();
      if (!data || data.scope !== 'tenant' || !data.user) return null;

      const u: User = {
        id: data.user.id,
        tenantId: data.user.tenantId,
        email: data.user.email,
        name: data.user.name,
        roleId: data.user.roleId,
        isActive: true,
        permissions: Array.isArray(data.user.permissions) ? data.user.permissions : []
      };
      return u;
    } catch (err) {
      console.error('Error fetching /api/me:', err);
      return null;
    }
  };

  useEffect(() => {
    // Redirigir root a /app para separar UI
    if (window.location.pathname === '/' || window.location.pathname === '') {
      window.history.replaceState({}, document.title, '/app');
    }

    if (area === 'admin') {
      const storedAdmin = localStorage.getItem('gastroflow_admin_user');
      if (storedAdmin) {
        try {
          setAdminUser(JSON.parse(storedAdmin));
        } catch {
          localStorage.removeItem('gastroflow_admin_user');
        }
      }
      return;
    }

    const stored = localStorage.getItem('gastroflow_current_user');

    if (isCloud) {
      // En cloud, la fuente de verdad es el token. Si existe, refrescamos /me.
      fetchMeFromApi().then((me) => {
        if (me) {
          setUser(me);
          localStorage.setItem('gastroflow_current_user', JSON.stringify(me));
          fetchTenantFromApi(me.tenantId).then((t) => setTenant(t || null));
        } else if (stored) {
          // Fallback (por compat): si hay user pero token inválido/ausente, forzar re-login
          setUser(null);
          setTenant(null);
          localStorage.removeItem('gastroflow_current_user');
        }
      });
    } else if (stored) {
      const u = JSON.parse(stored);
      setUser(u);
      setTenant(db.getTenant(u.tenantId) || null);
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
    localStorage.removeItem('gastroflow_token');
  };

  const handleAdminLogout = () => {
    setAdminUser(null);
    localStorage.removeItem('gastroflow_admin_user');
    localStorage.removeItem('gastroflow_admin_token');
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

  if (area === 'admin') {
    if (isAdminForgot) return <AdminForgotPasswordPage />;
    if (isAdminReset) return <AdminResetPasswordPage />;
    if (!adminUser) {
      return <AdminLoginPage onLogin={(u) => setAdminUser(u)} />;
    }
    return <AdminDashboardPage onLogout={handleAdminLogout} />;
  }

  if (isAppRegister) {
    return <AppRegisterPage isCloud={isCloud} onLogin={handleLogin} />;
  }
  if (isAppForgot) {
    return <AppForgotPasswordPage isCloud={isCloud} />;
  }
  if (isAppReset) {
    return <AppResetPasswordPage isCloud={isCloud} />;
  }

  if (!user || !tenant) {
    return <TenantLoginPage onLogin={handleLogin} isCloud={isCloud} />;
  }

  // Multi-tenant Billing Lock
  const now = Date.now();
  const trialEndsAt = tenant.trialEndsAt ? new Date(tenant.trialEndsAt) : null;
  const isTrial = tenant.subscriptionStatus === SubscriptionStatus.TRIAL;
  const isTrialExpired = isTrial && trialEndsAt && trialEndsAt.getTime() <= now;
  const isLocked =
    tenant.subscriptionStatus === SubscriptionStatus.PAST_DUE ||
    tenant.subscriptionStatus === SubscriptionStatus.CANCELED ||
    tenant.subscriptionStatus === SubscriptionStatus.INACTIVE ||
    isTrialExpired;

  const trialDaysLeft = isTrial && trialEndsAt
    ? Math.max(0, Math.ceil((trialEndsAt.getTime() - now) / (1000 * 60 * 60 * 24)))
    : null;
  const currentActivePage = isLocked ? 'billing' : activePage;

  // Lógica de permisos por rol
  const userRole = db.query<any>('roles', user.tenantId).find(r => r.id === user.roleId);
  const permissions = user.permissions || userRole?.permissions || [];

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
      tenant={tenant}
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

      {!isLocked && isTrial && (
        <div className="mb-10 p-8 bg-blue-600/10 border-2 border-blue-500/20 rounded-[2rem] flex flex-col md:flex-row items-center gap-8 text-blue-200 shadow-2xl animate-in slide-in-from-top-4 duration-500">
          <div className="w-16 h-16 bg-blue-500/20 rounded-2xl flex items-center justify-center flex-shrink-0">
            <Store size={32} />
          </div>
          <div className="flex-1 text-center md:text-left">
            <h4 className="text-xl font-black italic tracking-tight uppercase">Trial activo</h4>
            <p className="text-sm opacity-90 mt-1 font-bold">
              {trialDaysLeft === null
                ? 'Tu periodo de prueba está activo. Podés elegir un plan cuando quieras.'
                : `Te quedan ${trialDaysLeft} día(s) de prueba. Podés elegir un plan cuando quieras.`}
            </p>
          </div>
          <button
            onClick={() => setActivePage('billing')}
            className="px-10 py-4 bg-blue-600 hover:bg-blue-500 text-white rounded-2xl font-black transition-all shadow-xl shadow-blue-600/30 active:scale-95 flex items-center gap-2"
          >
            Ver planes <LogIn size={18} />
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
          {currentActivePage === 'users' && <UsersRolesPage tenantId={tenant.id} tenant={tenant} isCloud={isCloud} />}
          {currentActivePage === 'billing' && <BillingPage tenant={tenant} user={user} onUpdate={refreshTenantData} />}
          {currentActivePage === 'cash' && <CashierPage tenantId={tenant.id} user={user} />}
        </>
      )}
    </Layout>
  );
};

export default App;

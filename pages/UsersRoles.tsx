
import React, { useState, useEffect } from 'react';
import { PlanTier } from '../types';
import { 
  UserPlus, Shield, MoreHorizontal, UserCheck, UserX, 
  X, Check, Loader2, Trash2, ShieldPlus, Lock, 
  Mail, User as UserIcon, Settings2, AlertTriangle,
  ChevronRight, Circle, Sparkles, Key, Cpu,
  Eye, Layout, Wallet, Package, Settings, Info,
  TrendingUp, CreditCard
} from 'lucide-react';
import { db } from '../services/db';
import { User, Role, Tenant } from '../types';
import { PERMISSION_GROUPS, PERMISSIONS, PLANS } from '../constants';
import { getEffectivePlan, isTrialActive } from '../utils/subscription';

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
  maxWidth?: string;
}

const Modal: React.FC<ModalProps> = ({ isOpen, onClose, title, children, maxWidth = "max-w-xl" }) => {
  if (!isOpen) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/90 backdrop-blur-md animate-in fade-in duration-300">
      <div className={`bg-slate-900 border border-slate-800 rounded-[2.5rem] w-full ${maxWidth} overflow-hidden shadow-2xl animate-in zoom-in-95 duration-300`}>
        <div className="px-8 py-6 border-b border-slate-800 flex justify-between items-center bg-slate-900/50">
          <h3 className="text-2xl font-black text-slate-100 italic tracking-tight">{title}</h3>
          <button onClick={onClose} className="p-3 hover:bg-slate-800 rounded-2xl text-slate-400 transition-colors">
            <X size={24} />
          </button>
        </div>
        <div className="p-8 max-h-[85vh] overflow-y-auto custom-scrollbar">
          {children}
        </div>
      </div>
    </div>
  );
};

export const UsersRolesPage: React.FC<{ tenantId: string; tenant?: Tenant | null; isCloud?: boolean }> = ({ tenantId, tenant: tenantProp, isCloud = false }) => {
  const [users, setUsers] = useState<User[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [tenant, setTenant] = useState<Tenant | undefined>(tenantProp || undefined);
  const [activeTab, setActiveTab] = useState<'users' | 'roles' | 'ai'>('users');
  const [loading, setLoading] = useState(false);
  
  // Modals
  const [isUserModalOpen, setIsUserModalOpen] = useState(false);
  const [isRoleModalOpen, setIsRoleModalOpen] = useState(false);
  const [isUpgradeModalOpen, setIsUpgradeModalOpen] = useState(false);
  const [editingItem, setEditingItem] = useState<any>(null);

  // Form State for Permissions
  const [selectedRolePerms, setSelectedRolePerms] = useState<string[]>([]);

  useEffect(() => {
    // En cloud, el tenant viene de props (API); en local, del DB adapter
    if (isCloud) {
      setTenant(tenantProp || undefined);
    } else {
      setTenant(db.getTenant(tenantId));
    }
    refreshData();
  }, [tenantId, isCloud, tenantProp?.id]);

  const refreshData = async () => {
    if (isCloud) {
      try {
        const token = localStorage.getItem('gastroflow_token');
        const headers: Record<string, string> = {};
        if (token) headers['Authorization'] = `Bearer ${token}`;

        const [usersRes, rolesRes] = await Promise.all([
          fetch(`/api/tenants/${tenantId}/users`, { headers }),
          fetch(`/api/tenants/${tenantId}/roles`, { headers }),
        ]);

        if (usersRes.ok) {
          const apiUsers = await usersRes.json();
          // Solo mostramos usuarios activos
          setUsers(apiUsers.filter((u: any) => u.isActive !== false));
        }
        if (rolesRes.ok) {
          const apiRoles = await rolesRes.json();
          setRoles(apiRoles);
        }
      } catch (err) {
        console.error('Error fetching users/roles for tenant:', err);
      }
      return;
    }

    // Modo local (MVP): seguir usando el adaptador in-memory
    setUsers([...db.query<User>('users', tenantId).filter(u => u.isActive)]);
    setRoles([...db.query<Role>('roles', tenantId)]);
    setTenant(db.getTenant(tenantId));
  };

  const activeUsersCount = users.filter(u => u.isActive).length;
  const effectiveTenant = tenant || tenantProp || undefined;

  let userLimit = 0;
  if (effectiveTenant) {
    const effectivePlan = getEffectivePlan(effectiveTenant as any);
    userLimit = PLANS[effectivePlan].limits.users;
  }

  const canAddMoreUsers = userLimit > 0 ? activeUsersCount < userLimit : false;

  const handleOpenUserModal = () => {
    if (!canAddMoreUsers) {
      setIsUpgradeModalOpen(true);
      return;
    }
    setEditingItem(null);
    setIsUserModalOpen(true);
  };

  const handleToggleUserStatus = async (user: User) => {
    // En cloud usamos la API (soft delete). En local, el adaptador DB.
    if (!user.isActive) return; // De momento solo soportamos desactivar desde la UI

    if (!window.confirm("¿Desactivar usuario? Desaparecerá de la lista activa.")) {
      return;
    }

    if (isCloud) {
      try {
        const token = localStorage.getItem('gastroflow_token');
        const headers: Record<string, string> = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = `Bearer ${token}`;

        const res = await fetch(`/api/tenants/${tenantId}/users/${user.id}`, {
          method: 'DELETE',
          headers,
        });
        if (!res.ok) {
          const data = await res.json().catch(() => null);
          alert(data?.error || 'No se pudo desactivar el usuario.');
        } else {
          refreshData();
        }
      } catch (e: any) {
        console.error(e);
        alert('Error de red al desactivar el usuario.');
      }
      return;
    }

    try {
      db.removeUser(user.id, tenantId);
      refreshData();
    } catch (e: any) {
      alert(e.message);
    }
  };

  const handleDeleteUser = async (e: React.MouseEvent, targetUser: User) => {
    e.stopPropagation();
    
    const currentUserStr = localStorage.getItem('gastroflow_current_user');
    const currentUser = currentUserStr ? JSON.parse(currentUserStr) : null;

    if (currentUser && currentUser.id === targetUser.id) {
      alert('No puedes eliminar tu propia cuenta de usuario mientras estás en sesión.');
      return;
    }

    if (!window.confirm(`¿Estás seguro de que deseas dar de baja a "${targetUser.name}"?`)) {
      return;
    }

    if (isCloud) {
      try {
        const token = localStorage.getItem('gastroflow_token');
        const headers: Record<string, string> = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = `Bearer ${token}`;

        const res = await fetch(`/api/tenants/${tenantId}/users/${targetUser.id}`, {
          method: 'DELETE',
          headers,
        });
        if (!res.ok) {
          const data = await res.json().catch(() => null);
          alert(data?.error || 'No se pudo dar de baja al usuario.');
        } else {
          refreshData();
        }
      } catch (error: any) {
        console.error(error);
        alert('Error de red al dar de baja al usuario.');
      }
      return;
    }

    try {
      db.removeUser(targetUser.id, tenantId);
      refreshData();
    } catch (error: any) {
      alert(error.message);
    }
  };

  const handleDeleteRole = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    if (!window.confirm('¿Estás seguro de que deseas eliminar este rol?')) {
      return;
    }

    if (isCloud) {
      try {
        const token = localStorage.getItem('gastroflow_token');
        const headers: Record<string, string> = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = `Bearer ${token}`;

        const res = await fetch(`/api/tenants/${tenantId}/roles/${id}`, {
          method: 'DELETE',
          headers,
        });
        if (!res.ok) {
          const data = await res.json().catch(() => null);
          alert(data?.error || 'No se pudo eliminar el rol.');
        } else {
          refreshData();
        }
      } catch (error: any) {
        console.error(error);
        alert('Error de red al eliminar el rol.');
      }
      return;
    }

    try {
      db.removeRole(id, tenantId);
      refreshData();
    } catch (error: any) {
      alert(error.message);
    }
  };

  const handleOpenRoleModal = (role?: Role) => {
    setEditingItem(role || null);
    setSelectedRolePerms(role ? [...role.permissions] : []);
    setIsRoleModalOpen(true);
  };

  const togglePermission = (permId: string) => {
    setSelectedRolePerms(prev => 
      prev.includes(permId) ? prev.filter(p => p !== permId) : [...prev, permId]
    );
  };

  const handleSaveUser = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setLoading(true);
    const form = e.currentTarget;
    const formData = new FormData(form);
    
    const name = formData.get('name') as string;
    const email = formData.get('email') as string;
    const roleId = formData.get('roleId') as string;
    const password = formData.get('password') as string | null;

    if (!name || !email || !roleId) {
      alert('Completa nombre, email y rol.');
      setLoading(false);
      return;
    }

    if (isCloud) {
      try {
        const token = localStorage.getItem('gastroflow_token');
        const headers: Record<string, string> = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = `Bearer ${token}`;

        if (editingItem) {
          // Edición: solo actualizamos nombre/rol desde la UI
          const res = await fetch(`/api/tenants/${tenantId}/users/${editingItem.id}`, {
            method: 'PUT',
            headers,
            body: JSON.stringify({ name, roleId }),
          });
          if (!res.ok) {
            const data = await res.json().catch(() => null);
            alert(data?.error || 'No se pudieron guardar los cambios del integrante.');
            setLoading(false);
            return;
          }
        } else {
          if (!canAddMoreUsers) {
            alert('Has alcanzado el límite de usuarios de tu plan.');
            setLoading(false);
            return;
          }
          if (!password || password.length < 6) {
            alert('Define una contraseña inicial de al menos 6 caracteres para el nuevo integrante.');
            setLoading(false);
            return;
          }

          const res = await fetch(`/api/tenants/${tenantId}/users`, {
            method: 'POST',
            headers,
            body: JSON.stringify({ name, email, roleId, password }),
          });
          if (!res.ok) {
            const data = await res.json().catch(() => null);
            alert(data?.error || 'No se pudo registrar el nuevo integrante.');
            setLoading(false);
            return;
          }
        }

        await refreshData();
        setIsUserModalOpen(false);
        setEditingItem(null);
        setLoading(false);
        form.reset();
      } catch (error: any) {
        console.error(error);
        alert('Error de red al guardar el integrante.');
        setLoading(false);
      }
      return;
    }

    // Modo local (demo)
    const userData = {
      name,
      email,
      roleId,
      isActive: true,
    };

    if (editingItem) {
      db.update<User>('users', editingItem.id, tenantId, userData);
    } else {
      if (!canAddMoreUsers) {
        alert('Has alcanzado el límite de usuarios de tu plan.');
        setLoading(false);
        return;
      }
      db.insert<User>('users', {
        id: `user-${Date.now()}`,
        tenantId,
        ...userData,
      });
    }

    setTimeout(() => {
      refreshData();
      setIsUserModalOpen(false);
      setEditingItem(null);
      setLoading(false);
    }, 400);
  };

  const handleSaveRole = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setLoading(true);
    const formData = new FormData(e.currentTarget);
    const name = formData.get('name') as string;

    if (!name) {
      alert("Debes asignar un nombre al rol.");
      setLoading(false);
      return;
    }

    const roleData = {
      name: name,
      permissions: selectedRolePerms,
    };

    if (isCloud) {
      try {
        const token = localStorage.getItem('gastroflow_token');
        const headers: Record<string, string> = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = `Bearer ${token}`;

        if (editingItem) {
          const res = await fetch(`/api/tenants/${tenantId}/roles/${editingItem.id}`, {
            method: 'PUT',
            headers,
            body: JSON.stringify(roleData),
          });
          if (!res.ok) {
            const data = await res.json().catch(() => null);
            alert(data?.error || 'No se pudieron guardar los cambios del rol.');
            setLoading(false);
            return;
          }
        } else {
          const res = await fetch(`/api/tenants/${tenantId}/roles`, {
            method: 'POST',
            headers,
            body: JSON.stringify(roleData),
          });
          if (!res.ok) {
            const data = await res.json().catch(() => null);
            alert(data?.error || 'No se pudo crear el rol.');
            setLoading(false);
            return;
          }
        }

        await refreshData();
        setIsRoleModalOpen(false);
        setEditingItem(null);
        setLoading(false);
      } catch (error: any) {
        console.error(error);
        alert('Error de red al guardar el rol.');
        setLoading(false);
      }
      return;
    }

    if (editingItem) {
      db.update<Role>('roles', editingItem.id, tenantId, roleData);
    } else {
      db.insert<Role>('roles', {
        id: `role-${Date.now()}`,
        tenantId,
        ...roleData
      });
    }

    setTimeout(() => {
      refreshData();
      setIsRoleModalOpen(false);
      setEditingItem(null);
      setLoading(false);
    }, 400);
  };

  const handleSaveAiSettings = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setLoading(true);
    const formData = new FormData(e.currentTarget);
    
    const settings = {
      geminiApiKey: formData.get('apiKey') as string,
      geminiModel: formData.get('model') as string,
    };

    db.updateTenantSettings(tenantId, settings);

    setTimeout(() => {
      refreshData();
      setLoading(false);
      alert("Configuración de IA guardada exitosamente.");
    }, 500);
  };

  const getRoleIcon = (roleName: string) => {
    if (roleName === 'Administrador') return <Shield size={24} />;
    if (roleName === 'Encargado') return <UserCheck size={24} />;
    if (roleName === 'Mozo') return <Info size={24} />;
    return <Circle size={24} />;
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      <div className="flex border-b border-slate-800">
        <button 
          onClick={() => setActiveTab('users')}
          className={`px-8 py-5 font-black text-xs uppercase tracking-widest transition-all border-b-4 ${activeTab === 'users' ? 'border-blue-600 text-blue-400' : 'border-transparent text-slate-500 hover:text-slate-300'}`}
        >
          Gestión de Equipo
        </button>
        <button 
          onClick={() => setActiveTab('roles')}
          className={`px-8 py-5 font-black text-xs uppercase tracking-widest transition-all border-b-4 ${activeTab === 'roles' ? 'border-purple-600 text-purple-400' : 'border-transparent text-slate-500 hover:text-slate-300'}`}
        >
          Roles & Permisos
        </button>
        <button 
          onClick={() => setActiveTab('ai')}
          className={`px-8 py-5 font-black text-xs uppercase tracking-widest transition-all border-b-4 ${activeTab === 'ai' ? 'border-emerald-600 text-emerald-400' : 'border-transparent text-slate-500 hover:text-slate-300'}`}
        >
          IA & API Config
        </button>
      </div>

      {activeTab === 'users' && (
        <div className="space-y-6">
          <div className="flex justify-between items-center">
             <div className="bg-slate-800/30 px-6 py-4 rounded-3xl border border-slate-700/50 flex items-center gap-4">
                <div className="flex flex-col">
                   <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Capacidad del Plan</span>
                   <div className="flex items-center gap-2">
                      <span className="text-lg font-black text-slate-100">{users.length} / {userLimit}</span>
                      <span className="text-xs text-slate-500 font-bold uppercase tracking-tighter">Usuarios activos</span>
                   </div>
                </div>
                {!canAddMoreUsers && (
                   <div className="px-4 py-2 bg-amber-500/10 border border-amber-500/20 rounded-xl flex items-center gap-2 animate-pulse">
                      <AlertTriangle size={14} className="text-amber-500" />
                      <span className="text-[10px] font-black text-amber-500 uppercase">Límite alcanzado</span>
                   </div>
                )}
             </div>
             
             <button 
                onClick={handleOpenUserModal}
                className={`flex items-center gap-3 px-8 py-4 rounded-2xl font-black shadow-xl transition-all active:scale-95 ${
                   canAddMoreUsers 
                   ? 'bg-blue-600 hover:bg-blue-500 text-white shadow-blue-900/20' 
                   : 'bg-slate-800 text-slate-500 border border-slate-700'
                }`}
              >
                <UserPlus size={20} />
                Añadir Integrante
              </button>
          </div>
          
          <div className="bg-slate-900/50 border border-slate-800 rounded-[2.5rem] overflow-hidden shadow-2xl backdrop-blur-sm">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-slate-800 text-slate-500 text-[10px] font-black uppercase tracking-[0.2em] bg-slate-800/20">
                  <th className="px-8 py-6">Usuario / Info</th>
                  <th className="px-8 py-6">Email Contacto</th>
                  <th className="px-8 py-6">Nivel de Acceso</th>
                  <th className="px-8 py-6 text-center">Estatus</th>
                  <th className="px-8 py-6 text-right">Control</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50 text-slate-300">
                {users.map(user => {
                  const uRole = roles.find(r => r.id === user.roleId);
                  return (
                    <tr key={user.id} className="hover:bg-slate-800/30 transition-colors group">
                      <td className="px-8 py-6">
                        <div className="flex items-center gap-4">
                          <div className={`w-12 h-12 rounded-2xl flex items-center justify-center font-black text-lg border-2 shadow-inner italic ${
                            uRole?.name === 'Administrador' ? 'bg-blue-600/20 text-blue-400 border-blue-500/20' : 'bg-slate-800 text-slate-500 border-slate-700'
                          }`}>
                            {user.name.charAt(0)}
                          </div>
                          <span className="font-bold text-slate-100 text-lg tracking-tight">{user.name}</span>
                        </div>
                      </td>
                      <td className="px-8 py-6 text-slate-400 font-mono text-sm">{user.email}</td>
                      <td className="px-8 py-6">
                        <span className={`px-4 py-1.5 text-[10px] font-black rounded-xl border-2 uppercase tracking-widest ${
                          uRole?.name === 'Administrador' ? 'bg-blue-600/10 text-blue-400 border-blue-500/30' : 'bg-slate-800 text-slate-500 border-slate-700'
                        }`}>
                          {uRole?.name || 'Invitado'}
                        </span>
                      </td>
                      <td className="px-8 py-6 text-center">
                        <button 
                          onClick={(e) => { e.stopPropagation(); handleToggleUserStatus(user); }}
                          className={`inline-flex items-center gap-2 text-[10px] font-black uppercase tracking-widest px-4 py-1.5 rounded-full border-2 transition-all ${
                            user.isActive 
                            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' 
                            : 'bg-red-500/10 text-red-400 border-red-500/30 opacity-50'
                          }`}
                        >
                          <div className={`w-2 h-2 rounded-full ${user.isActive ? 'bg-emerald-400 shadow-[0_0_8px_rgba(16,185,129,0.5)]' : 'bg-red-400'}`}></div>
                          {user.isActive ? 'Activo' : 'Suspendido'}
                        </button>
                      </td>
                      <td className="px-8 py-6 text-right">
                        <div className="flex items-center justify-end gap-3 opacity-0 group-hover:opacity-100 transition-opacity">
                           <button onClick={(e) => { e.stopPropagation(); setEditingItem(user); setIsUserModalOpen(true); }} className="p-3 bg-slate-800 hover:bg-blue-600 text-slate-400 hover:text-white rounded-2xl transition-all shadow-lg"><Settings2 size={18} /></button>
                           <button onClick={(e) => handleDeleteUser(e, user)} className="p-3 bg-slate-800 hover:bg-red-600 text-slate-400 hover:text-white rounded-2xl transition-all shadow-lg"><Trash2 size={18} /></button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Roles & AI Tabs Content (kept same for brevity but included in full file output if needed) */}
      {activeTab === 'roles' && (
        <div className="space-y-12 animate-in slide-in-from-bottom-4 duration-500">
          <div className="flex justify-between items-center">
             <div className="bg-slate-800/30 p-4 rounded-3xl border border-slate-700/50 flex items-center gap-3">
                <Shield className="text-purple-400" size={20} />
                <p className="text-xs font-bold text-slate-400 italic">Cada rol define las capacidades de tus empleados dentro de GastroFlow.</p>
             </div>
             <button 
                onClick={() => handleOpenRoleModal()}
                className="flex items-center gap-3 px-8 py-4 bg-purple-600 hover:bg-purple-500 text-white rounded-2xl font-black shadow-xl shadow-purple-900/20 transition-all active:scale-95"
              >
                <ShieldPlus size={20} />
                Nuevo Perfil de Acceso
              </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {roles.map(role => (
              <div key={role.id} className={`group relative flex flex-col p-10 rounded-[3rem] border-2 transition-all duration-300 ${
                role.name === 'Administrador' 
                ? 'bg-blue-600/10 border-blue-500/30 shadow-blue-500/5' 
                : 'bg-slate-900/50 border-slate-800 hover:border-slate-600'
              }`}>
                <div className="flex items-center justify-between mb-8">
                  <div className={`w-16 h-16 rounded-[1.5rem] flex items-center justify-center border-2 transition-all ${
                    role.name === 'Administrador' ? 'bg-blue-600 text-white border-blue-400/50 shadow-xl shadow-blue-500/20' : 'bg-slate-800 text-slate-400 border-slate-700'
                  }`}>
                    {getRoleIcon(role.name)}
                  </div>
                  <div className="flex gap-2">
                    <button onClick={() => handleOpenRoleModal(role)} className="p-3 bg-slate-800/80 text-slate-400 hover:text-white rounded-2xl transition-all border border-transparent hover:border-slate-600"><Settings2 size={20} /></button>
                    {role.name !== 'Administrador' && (
                      <button onClick={(e) => handleDeleteRole(e, role.id)} className="p-3 bg-slate-800/80 text-slate-400 hover:text-red-400 rounded-2xl transition-all border border-transparent hover:border-red-400/20"><Trash2 size={20} /></button>
                    )}
                  </div>
                </div>
                
                <h4 className="text-2xl font-black text-slate-100 italic tracking-tight mb-4">{role.name}</h4>
                
                <div className="space-y-3 mt-auto">
                   <p className="text-[10px] font-black text-slate-500 uppercase tracking-widest flex items-center gap-2">
                     <Check size={12} className="text-emerald-500" /> {role.permissions.length} Permisos habilitados
                   </p>
                   <div className="flex flex-wrap gap-1.5">
                      {PERMISSION_GROUPS.map(group => {
                         const hasPermsInGroup = group.permissions.some(p => role.permissions.includes(p.id));
                         if (!hasPermsInGroup) return null;
                         return (
                           <div key={group.name} className="px-2 py-1 bg-slate-800/50 rounded-lg text-[8px] font-black text-slate-400 uppercase border border-slate-700/50">
                              {group.name}
                           </div>
                         );
                      })}
                   </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* AI & Config Tab */}
      {activeTab === 'ai' && (
        <div className="max-w-3xl space-y-8 animate-in slide-in-from-bottom-4 duration-500">
           <div className="bg-gradient-to-br from-purple-900/40 to-blue-900/20 border border-purple-500/30 p-10 rounded-[2.5rem] shadow-2xl relative overflow-hidden">
              <div className="relative z-10">
                 <div className="flex items-center gap-4 mb-8">
                    <div className="w-20 h-20 bg-emerald-600/20 text-emerald-400 rounded-3xl flex items-center justify-center border border-emerald-500/30 shadow-xl shadow-emerald-500/10">
                       <Sparkles size={36} />
                    </div>
                    <div>
                       <h3 className="text-3xl font-black text-slate-100 italic tracking-tight">Google Gemini Engine</h3>
                       <p className="text-slate-400 text-sm">Configuración avanzada de inteligencia artificial para tu local.</p>
                    </div>
                 </div>

                 <form onSubmit={handleSaveAiSettings} className="space-y-8">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                       <div className="space-y-3">
                          <label className="text-xs font-black text-slate-500 uppercase tracking-widest ml-1 flex items-center gap-2">
                             <Key size={14} /> Gemini API Key
                          </label>
                          <input 
                            name="apiKey" 
                            type="password"
                            defaultValue={tenant?.settings?.geminiApiKey}
                            className="w-full bg-slate-800/50 border border-slate-700 text-white rounded-2xl py-4 px-6 outline-none focus:ring-4 focus:ring-emerald-500/10 focus:border-emerald-500/50 transition-all font-mono"
                            placeholder="sk-..."
                          />
                       </div>
                       <div className="space-y-3">
                          <label className="text-xs font-black text-slate-500 uppercase tracking-widest ml-1 flex items-center gap-2">
                             <Cpu size={14} /> Engine Model
                          </label>
                          <select 
                            name="model"
                            defaultValue={tenant?.settings?.geminiModel || 'gemini-3-flash-preview'}
                            className="w-full bg-slate-800/50 border border-slate-700 text-white rounded-2xl py-4 px-6 outline-none focus:ring-4 focus:ring-emerald-500/10 focus:border-emerald-500/50 transition-all appearance-none cursor-pointer"
                          >
                             <option value="gemini-3-flash-preview">Gemini 3 Flash (Fast)</option>
                             <option value="gemini-3-pro-preview">Gemini 3 Pro (High Precision)</option>
                             <option value="gemini-flash-latest">Gemini Flash (Stable)</option>
                          </select>
                       </div>
                    </div>

                    <button type="submit" className="w-full py-5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-2xl font-black text-lg shadow-xl shadow-emerald-900/40 transition-all active:scale-95 flex items-center justify-center gap-3">
                      {loading ? <Loader2 size={24} className="animate-spin" /> : <Settings2 size={24} />}
                      Guardar Parametrización IA
                    </button>
                 </form>
              </div>
           </div>
        </div>
      )}

      {/* Upgrade Modal */}
      <Modal 
        isOpen={isUpgradeModalOpen} 
        onClose={() => setIsUpgradeModalOpen(false)} 
        title="Mejora tu Plan"
      >
        <div className="text-center space-y-8">
           <div className="w-20 h-20 bg-amber-500/10 text-amber-500 rounded-full flex items-center justify-center mx-auto shadow-xl border border-amber-500/20">
              <TrendingUp size={40} />
           </div>
           <div className="space-y-2">
              <h4 className="text-2xl font-black text-white italic tracking-tight">¡Has alcanzado tu límite!</h4>
              {(() => {
                const trialActive = isTrialActive(tenant);
                const effectivePlan = getEffectivePlan(tenant as any);
                return (<p className="text-slate-400 font-medium">Tu plan actual <b>{PLANS[effectivePlan].name}{trialActive ? ' (TRIAL)' : ''}</b> solo permite un máximo de <b>{userLimit}</b> usuarios.</p>);
              })()}
           </div>
           
           <div className="bg-slate-800/40 p-6 rounded-3xl border border-slate-700/50 text-left space-y-4">
              <p className="text-xs font-black text-slate-500 uppercase tracking-widest">Beneficios del Plan Pro:</p>
              <ul className="space-y-3">
                 <li className="flex items-center gap-3 text-sm text-slate-300 font-bold">
                    <Check size={16} className="text-emerald-500" /> Hasta 3 Usuarios simultáneos
                 </li>
                 <li className="flex items-center gap-3 text-sm text-slate-300 font-bold">
                    <Check size={16} className="text-emerald-500" /> Gestión de hasta 50 mesas
                 </li>
                 <li className="flex items-center gap-3 text-sm text-slate-300 font-bold">
                    <Check size={16} className="text-emerald-500" /> Dashboard avanzado de ventas
                 </li>
              </ul>
           </div>

           <div className="flex flex-col gap-3">
              <button 
                 onClick={() => {
                    setIsUpgradeModalOpen(false);
                    // Emitir un evento o disparar el cambio de pestaña a billing
                    window.dispatchEvent(new CustomEvent('switchTab', { detail: 'billing' }));
                 }}
                 className="w-full py-5 bg-blue-600 hover:bg-blue-500 text-white rounded-2xl font-black text-lg shadow-xl shadow-blue-900/20 transition-all active:scale-95 flex items-center justify-center gap-3"
              >
                 Ver Planes de Suscripción <CreditCard size={20} />
              </button>
              <button 
                 onClick={() => setIsUpgradeModalOpen(false)}
                 className="text-slate-500 hover:text-slate-300 font-black text-xs uppercase tracking-widest py-2"
              >
                 Quizás más tarde
              </button>
           </div>
        </div>
      </Modal>

      {/* Role & Permissions Modal */}
      <Modal 
        isOpen={isRoleModalOpen} 
        onClose={() => setIsRoleModalOpen(false)} 
        title={editingItem ? `Rol: ${editingItem.name}` : 'Crear Perfil de Acceso'}
        maxWidth="max-w-4xl"
      >
        <form onSubmit={handleSaveRole} className="space-y-10">
          <div className="space-y-3">
            <label className="text-xs font-black text-slate-500 uppercase tracking-widest ml-1">Nombre del Perfil</label>
            <input 
              name="name" 
              required 
              defaultValue={editingItem?.name} 
              disabled={editingItem?.name === 'Administrador'}
              className="w-full bg-slate-800 border-2 border-slate-700 rounded-2xl py-5 px-6 text-slate-100 font-black text-xl italic outline-none focus:border-purple-500/50 transition-all disabled:opacity-50" 
              placeholder="Ej: Supervisor de Turno" 
            />
          </div>

          <div className="space-y-8">
             <h4 className="text-sm font-black text-slate-100 uppercase tracking-[0.2em] border-l-4 border-purple-600 pl-4">Matriz de Permisos por Módulo</h4>
             
             <div className="grid grid-cols-1 md:grid-cols-2 gap-10">
                {PERMISSION_GROUPS.map(group => (
                  <div key={group.name} className="space-y-6">
                     <div className="flex items-center gap-3 text-slate-100 pb-2 border-b border-slate-800">
                        <div className="p-2 bg-slate-800 rounded-lg text-purple-400">
                           {group.icon === 'layout' && <Layout size={18} />}
                           {group.icon === 'wallet' && <Wallet size={18} />}
                           {group.icon === 'package' && <Package size={18} />}
                           {group.icon === 'settings' && <Settings size={18} />}
                        </div>
                        <h5 className="font-black italic text-sm">{group.name}</h5>
                     </div>
                     
                     <div className="space-y-4">
                        {group.permissions.map(perm => (
                          <label key={perm.id} className={`flex items-start gap-4 p-4 rounded-2xl border-2 transition-all cursor-pointer group/label ${
                            selectedRolePerms.includes(perm.id) 
                              ? 'bg-purple-600/10 border-purple-500/40' 
                              : 'bg-slate-800/30 border-slate-800 hover:border-slate-700'
                          }`}>
                             <div className="pt-0.5">
                                <input 
                                  type="checkbox"
                                  checked={selectedRolePerms.includes(perm.id)}
                                  onChange={() => togglePermission(perm.id)}
                                  disabled={editingItem?.name === 'Administrador'}
                                  className="w-5 h-5 rounded-lg bg-slate-700 border-slate-600 text-purple-600 focus:ring-purple-500/50 cursor-pointer"
                                />
                             </div>
                             <div className="flex flex-col gap-1">
                                <span className={`text-sm font-black transition-colors ${selectedRolePerms.includes(perm.id) ? 'text-white' : 'text-slate-400 group-hover/label:text-slate-300'}`}>
                                   {perm.label}
                                </span>
                                <span className="text-[10px] font-medium text-slate-500 leading-relaxed">
                                   {perm.description}
                                </span>
                             </div>
                          </label>
                        ))}
                     </div>
                  </div>
                ))}
             </div>
          </div>

          <div className="pt-10 border-t border-slate-800 flex justify-end gap-4">
            <button type="button" onClick={() => setIsRoleModalOpen(false)} className="px-8 py-4 text-slate-500 hover:text-slate-100 font-black text-xs uppercase tracking-widest transition-colors">Cancelar</button>
            <button 
              type="submit" 
              className="px-12 py-4 bg-purple-600 hover:bg-purple-500 text-white rounded-2xl font-black shadow-xl shadow-purple-900/20 active:scale-95 transition-all"
            >
              Confirmar Cambios de Perfil
            </button>
          </div>
        </form>
      </Modal>

      {/* User Modal */}
      <Modal isOpen={isUserModalOpen} onClose={() => setIsUserModalOpen(false)} title={editingItem ? 'Configurar Integrante' : 'Nuevo Integrante'}>
         <form onSubmit={handleSaveUser} className="space-y-8">
            <div className="space-y-6">
              <div className="space-y-2">
                <label className="text-xs font-black text-slate-500 uppercase tracking-widest ml-1">Nombre Completo</label>
                <input name="name" required defaultValue={editingItem?.name} className="w-full bg-slate-800 border-2 border-slate-700 rounded-2xl py-4 px-6 text-slate-100 font-bold focus:border-blue-500/50 outline-none" placeholder="Ej: Julian Gomez" />
              </div>
              <div className="space-y-2">
                <label className="text-xs font-black text-slate-500 uppercase tracking-widest ml-1">Email Profesional</label>
                <input 
                  name="email" 
                  type="email" 
                  required 
                  defaultValue={editingItem?.email} 
                  disabled={!!(editingItem && isCloud)}
                  className={`w-full bg-slate-800 border-2 border-slate-700 rounded-2xl py-4 px-6 text-slate-100 font-bold focus:border-blue-500/50 outline-none ${editingItem && isCloud ? 'opacity-60 cursor-not-allowed' : ''}`}
                  placeholder="julian@local.com" 
                />
                {editingItem && isCloud && (
                  <p className="text-[10px] text-slate-500 font-medium mt-1">El email no puede modificarse una vez creado el usuario.</p>
                )}
              </div>
              {!editingItem && (
                <div className="space-y-2">
                  <label className="text-xs font-black text-slate-500 uppercase tracking-widest ml-1">Contraseña inicial</label>
                  <input 
                    name="password" 
                    type="password" 
                    minLength={6}
                    className="w-full bg-slate-800 border-2 border-slate-700 rounded-2xl py-4 px-6 text-slate-100 font-bold focus:border-blue-500/50 outline-none" 
                    placeholder="Define una clave para este integrante" 
                  />
                  {isCloud && (
                    <p className="text-[10px] text-slate-500 font-medium mt-1">Comparte esta contraseña con el integrante; luego podrá cambiarla desde "Olvidé mi contraseña".</p>
                  )}
                </div>
              )}
              <div className="space-y-2">
                <label className="text-xs font-black text-slate-500 uppercase tracking-widest ml-1">Asignar Perfil de Acceso</label>
                <select name="roleId" required defaultValue={editingItem?.roleId} className="w-full bg-slate-800 border-2 border-slate-700 rounded-2xl py-4 px-6 text-slate-100 font-bold outline-none appearance-none cursor-pointer">
                  <option value="">Seleccionar nivel...</option>
                  {roles.map(r => <option key={r.id} value={r.id}>{r.name}</option>)}
                </select>
              </div>
            </div>
            <button type="submit" className="w-full py-5 bg-blue-600 hover:bg-blue-500 text-white rounded-2xl font-black text-lg shadow-xl shadow-blue-900/20 transition-all active:scale-95">
              Finalizar Registro
            </button>
         </form>
      </Modal>
    </div>
  );
};

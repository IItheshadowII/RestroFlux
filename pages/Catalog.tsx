
import React, { useState, useEffect, useRef } from 'react';
import { 
  Plus, Edit2, Trash2, Search, X, Check, Loader2, 
  Image as ImageIcon, Hash, Filter, Package, 
  ArrowUpRight, ArrowDownRight, History, MoreVertical,
  ChevronDown, Layers, DollarSign, AlertCircle, PlusCircle, MinusCircle,
  Camera, Sparkles, Wand2, ImagePlus, RefreshCw as RefreshIcon,
  PlusSquare
} from 'lucide-react';
import { db } from '../services/db';
import { Product, Category, AuditLog, User, Tenant } from '../types';

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
}

const Modal: React.FC<ModalProps> = ({ isOpen, onClose, title, children }) => {
  if (!isOpen) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-slate-900 border border-slate-800 rounded-[2.5rem] w-full max-w-2xl overflow-hidden shadow-2xl animate-in zoom-in-95 duration-200">
        <div className="px-8 py-6 border-b border-slate-800 flex justify-between items-center">
          <h3 className="text-xl font-black text-slate-100 italic tracking-tight">{title}</h3>
          <button onClick={onClose} className="p-2 hover:bg-slate-800 rounded-xl text-slate-400 transition-colors">
            <X size={24} />
          </button>
        </div>
        <div className="p-8 max-h-[80vh] overflow-y-auto custom-scrollbar">
          {children}
        </div>
      </div>
    </div>
  );
};

export const CatalogPage: React.FC<{ tenantId: string; user: User; isCloud?: boolean; tenant?: Tenant | null }> = ({ tenantId, user, isCloud = false, tenant: tenantProp }) => {
  const [activeTab, setActiveTab] = useState<'products' | 'categories' | 'history'>('products');
  const [categories, setCategories] = useState<Category[]>([]);
  const [products, setProducts] = useState<Product[]>([]);
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [stockFilter, setStockFilter] = useState<'all' | 'low' | 'out'>('all');
  
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isAiModalOpen, setIsAiModalOpen] = useState(false);
  const [modalType, setModalType] = useState<'product' | 'category'>('product');
  const [editingItem, setEditingItem] = useState<any>(null);
  
  const [manualAdjustments, setManualAdjustments] = useState<Record<string, string>>({});

  const [aiLoading, setAiLoading] = useState(false);
  const [imgGenLoading, setImgGenLoading] = useState(false);
  const [capturedImage, setCapturedImage] = useState<string | null>(null);
  const [generatedImageUrl, setGeneratedImageUrl] = useState<string | null>(null);
  const videoRef = useRef<HTMLVideoElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  const productNameRef = useRef<HTMLInputElement>(null);
  const productDescRef = useRef<HTMLTextAreaElement>(null);

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
        const [catsRes, prodsRes, logsRes] = await Promise.all([
          fetch('/api/categories', { headers }),
          fetch('/api/products', { headers }),
          fetch('/api/audit_logs', { headers }).catch(() => null),
        ]);

        if (catsRes.ok) {
          const apiCats = await catsRes.json();
          setCategories(
            (apiCats as any[])
              .filter(c => c.is_active !== false)
              .map(c => ({
                id: c.id,
                tenantId: c.tenant_id,
                name: c.name,
                order: typeof c.sort_order === 'number' ? c.sort_order : 0,
              }))
              .sort((a, b) => a.order - b.order)
          );
        }

        if (prodsRes.ok) {
          const apiProducts = await prodsRes.json();
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

        if (logsRes && logsRes.ok) {
          const apiLogs = await logsRes.json();
          setLogs(
            (apiLogs as any[])
              .filter(l => l.action === 'STOCK_ADJUST')
              .map(l => ({
                id: l.id,
                tenantId: l.tenant_id,
                userId: l.user_id,
                action: l.action,
                entityType: l.entity_type,
                entityId: l.entity_id,
                before: l.payload?.before || {},
                after: l.payload?.after || {},
                timestamp: l.created_at,
              }))
              .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
          );
        } else {
          setLogs([]);
        }
      } catch (err) {
        console.error('Error cargando catálogo desde API:', err);
      }
      return;
    }

    // Modo local (demo)
    setCategories(db.query<Category>('categories', tenantId).sort((a, b) => a.order - b.order));
    setProducts(db.query<Product>('products', tenantId).filter(p => p.isActive));
    setLogs(db.query<AuditLog>('audit_logs', tenantId)
      .filter(l => l.action === 'STOCK_ADJUST')
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    );
  };

  useEffect(() => {
    refreshData();
  }, [tenantId, isCloud]);

  // Realtime: actualizar catálogo cuando lleguen eventos de products desde el servidor (cloud)
  useEffect(() => {
    if (!isCloud) return;

    const handler = (e: any) => {
      const type = e?.detail?.type;
      if (type === 'products.changed' || type === 'categories.changed') {
        refreshData();
      }
    };

    window.addEventListener('tenant:event', handler);
    return () => window.removeEventListener('tenant:event', handler);
  }, [tenantId, isCloud]);

  const handleQuickStock = (productId: string, amount: number) => {
    if (isCloud) {
      const product = products.find(p => p.id === productId);
      if (!product || !product.stockEnabled) return;
      const newQty = (product.stockQuantity || 0) + amount;
      const headers = getAuthHeaders();
      fetch(`/api/products/${productId}`, {
        method: 'PUT',
        headers,
        body: JSON.stringify({ stock_quantity: newQty }),
      })
        .then(res => {
          if (!res.ok) return res.json().then(d => { throw new Error(d?.error || 'No se pudo ajustar stock'); });
        })
        .then(() => refreshData())
        .catch(err => {
          console.error(err);
          alert(err.message || 'Error al ajustar stock');
        });
      return;
    }

    db.adjustStock(productId, tenantId, user.id, amount, 'Ajuste rápido desde catálogo');
    refreshData();
  };

  const handleManualStockApply = (productId: string) => {
    const val = parseInt(manualAdjustments[productId]);
    if (isNaN(val) || val === 0) return;

    if (isCloud) {
      const product = products.find(p => p.id === productId);
      if (!product || !product.stockEnabled) return;
      const newQty = (product.stockQuantity || 0) + val;
      const headers = getAuthHeaders();
      fetch(`/api/products/${productId}`, {
        method: 'PUT',
        headers,
        body: JSON.stringify({ stock_quantity: newQty }),
      })
        .then(res => {
          if (!res.ok) return res.json().then(d => { throw new Error(d?.error || 'No se pudo ajustar stock'); });
        })
        .then(() => refreshData())
        .catch(err => {
          console.error(err);
          alert(err.message || 'Error al ajustar stock');
        });
    } else {
      db.adjustStock(productId, tenantId, user.id, val, 'Ajuste manual por teclado');
      refreshData();
    }

    setManualAdjustments(prev => {
      const next = { ...prev };
      delete next[productId];
      return next;
    });
    refreshData();
  };

  const handleDelete = (type: 'products' | 'categories', id: string) => {
    if (window.confirm(`¿Seguro que deseas eliminar este elemento?`)) {
      try {
        if (isCloud) {
          const headers = getAuthHeaders();
          const resource = type === 'products' ? 'products' : 'categories';
          fetch(`/api/${resource}/${id}`, { method: 'DELETE', headers })
            .then(res => {
              if (!res.ok) return res.json().then(d => { throw new Error(d?.error || 'No se pudo eliminar'); });
            })
            .then(() => refreshData())
            .catch((e: any) => alert(e.message || 'Error al eliminar'));
        } else {
          if (type === 'products') {
            db.removeProduct(id, tenantId);
          } else {
            db.removeCategory(id, tenantId);
          }
          refreshData();
        }
      } catch (e: any) {
        alert(e.message);
      }
    }
  };

  const startCamera = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
      if (videoRef.current) {
        videoRef.current.srcObject = stream;
        videoRef.current.play();
      }
    } catch (err) {
      console.error("Error al acceder a la cámara:", err);
      alert("No se pudo acceder a la cámara.");
    }
  };

  const stopCamera = () => {
    if (videoRef.current && videoRef.current.srcObject) {
      const tracks = (videoRef.current.srcObject as MediaStream).getTracks();
      tracks.forEach(track => track.stop());
    }
  };

  const capturePhoto = () => {
    if (videoRef.current && canvasRef.current) {
      const context = canvasRef.current.getContext('2d');
      if (context) {
        canvasRef.current.width = videoRef.current.videoWidth;
        canvasRef.current.height = videoRef.current.videoHeight;
        context.drawImage(videoRef.current, 0, 0, canvasRef.current.width, canvasRef.current.height);
        const dataUrl = canvasRef.current.toDataURL('image/jpeg');
        setCapturedImage(dataUrl);
        stopCamera();
      }
    }
  };

  const generateProductImage = async () => {
    const name = productNameRef.current?.value;
    const desc = productDescRef.current?.value;
    if (!name) return alert("Ingresa el nombre del producto.");

    setImgGenLoading(true);
    try {
      const token = localStorage.getItem('gastroflow_token');
      const res = await fetch('/api/app/ai/generate-product-image', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ name, description: desc || '' }),
      });

      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        alert(data?.error || 'Error al generar imagen (IA).');
        return;
      }

      if (data?.imageDataUrl) {
        setGeneratedImageUrl(String(data.imageDataUrl));
      } else {
        alert('La IA no devolvió imagen.');
      }
    } catch (err) {
      console.error(err);
      alert("Error al generar imagen.");
    } finally {
      setImgGenLoading(false);
    }
  };

  const analyzeWithAi = async () => {
    if (!capturedImage) return;

    setAiLoading(true);
    try {
      const token = localStorage.getItem('gastroflow_token');
      const res = await fetch('/api/app/ai/analyze-product-image', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ imageDataUrl: capturedImage, mimeType: 'image/jpeg' }),
      });

      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        alert(data?.error || 'Error al analizar imagen (IA).');
        return;
      }

      const result = data?.result || {};
      const safeCategoryName = (typeof result.category === 'string' && result.category.trim())
        ? result.category.trim()
        : 'General';

      let category = categories.find(c => c.name.toLowerCase() === safeCategoryName.toLowerCase());
      if (!category) {
        category = db.insert<Category>('categories', {
          id: `cat-ai-${Date.now()}`,
          tenantId,
          name: safeCategoryName,
          order: categories.length + 1
        });
      }

      const safeName = (typeof result.name === 'string' && result.name.trim()) ? result.name.trim() : 'Producto';
      const safeDescription = typeof result.description === 'string' ? result.description : '';
      const priceNumber = typeof result.price === 'number' ? result.price : parseFloat(String(result.price ?? ''));
      const safePrice = Number.isFinite(priceNumber) ? priceNumber : 0;

      setEditingItem({
        name: safeName,
        description: safeDescription,
        price: safePrice,
        categoryId: category.id,
        stockEnabled: true,
        stockQuantity: 0,
        stockMin: 5,
        imageUrl: capturedImage
      });
      setGeneratedImageUrl(capturedImage);
      setIsAiModalOpen(false);
      setModalType('product');
      setIsModalOpen(true);
      setCapturedImage(null);
    } catch (err) {
      console.error(err);
      alert("Error al analizar imagen.");
    } finally {
      setAiLoading(false);
    }
  };

  const filteredProducts = products.filter(p => {
    const term = searchTerm.toLowerCase();
    const matchesSearch = p.name.toLowerCase().includes(term) || (p.sku && p.sku.toLowerCase().includes(term));
    const matchesCat = selectedCategory === 'all' || p.categoryId === selectedCategory;
    const isLow = p.stockEnabled && p.stockQuantity <= p.stockMin && p.stockQuantity > 0;
    const isOut = p.stockEnabled && p.stockQuantity <= 0;
    if (stockFilter === 'low') return matchesSearch && matchesCat && isLow;
    if (stockFilter === 'out') return matchesSearch && matchesCat && isOut;
    return matchesSearch && matchesCat;
  });

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
        <div className="flex bg-slate-900 p-1.5 rounded-2xl border border-slate-800">
          <button data-tour="tab-products" onClick={() => setActiveTab('products')} className={`px-6 py-2.5 rounded-xl text-xs font-black uppercase tracking-widest transition-all ${activeTab === 'products' ? 'bg-blue-600 text-white shadow-lg' : 'text-slate-500 hover:text-slate-300'}`}>Productos</button>
          <button data-tour="tab-categories" onClick={() => setActiveTab('categories')} className={`px-6 py-2.5 rounded-xl text-xs font-black uppercase tracking-widest transition-all ${activeTab === 'categories' ? 'bg-blue-600 text-white shadow-lg' : 'text-slate-500 hover:text-slate-300'}`}>Categorías</button>
          <button data-tour="tab-history" onClick={() => setActiveTab('history')} className={`px-6 py-2.5 rounded-xl text-xs font-black uppercase tracking-widest transition-all ${activeTab === 'history' ? 'bg-blue-600 text-white shadow-lg' : 'text-slate-500 hover:text-slate-300'}`}>Historial</button>
        </div>

        <div className="flex items-center gap-3 w-full md:w-auto">
          <button onClick={() => { setCapturedImage(null); setIsAiModalOpen(true); startCamera(); }} className="flex-1 md:flex-none px-6 py-3 bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-500 hover:to-blue-500 text-white rounded-2xl font-black text-xs uppercase tracking-widest border border-white/10 transition-all shadow-xl shadow-purple-600/20 flex items-center justify-center gap-2">
            <Sparkles size={16} /> Añadir por Foto (IA)
          </button>
          <button 
            data-tour={activeTab === 'categories' ? 'add-category' : 'add-product'}
            onClick={() => { 
              setModalType(activeTab === 'categories' ? 'category' : 'product'); 
              setEditingItem(null); 
              setGeneratedImageUrl(null); 
              setIsModalOpen(true); 
            }} 
            className="flex-1 md:flex-none px-8 py-3 bg-blue-600 hover:bg-blue-500 text-white rounded-2xl font-black text-xs uppercase tracking-widest transition-all shadow-xl shadow-blue-600/20"
          >
            {activeTab === 'categories' ? '+ Categoría' : '+ Producto'}
          </button>
        </div>
      </div>

      {activeTab === 'products' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            <div className="lg:col-span-5 relative group">
              <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500 group-focus-within:text-blue-500 transition-colors" size={20} />
              <input type="text" placeholder="Buscar producto..." className="w-full bg-slate-900 border border-slate-800 rounded-2xl py-4 pl-12 pr-4 text-slate-200 outline-none focus:ring-4 focus:ring-blue-500/10 focus:border-blue-500/50 transition-all shadow-inner font-medium" value={searchTerm} onChange={(e) => setSearchTerm(e.target.value)} />
            </div>
            <div className="lg:col-span-3">
               <select value={selectedCategory} onChange={(e) => setSelectedCategory(e.target.value)} className="w-full h-full bg-slate-900 border border-slate-800 rounded-2xl px-6 text-slate-300 font-bold appearance-none outline-none focus:border-blue-500/50 transition-all">
                 <option value="all">Categorías</option>
                 {categories.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
               </select>
            </div>
            <div className="lg:col-span-4 flex bg-slate-900 p-1.5 rounded-2xl border border-slate-800">
               <button onClick={() => setStockFilter('all')} className={`flex-1 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all ${stockFilter === 'all' ? 'bg-slate-800 text-white' : 'text-slate-500'}`}>Todos</button>
               <button onClick={() => setStockFilter('low')} className={`flex-1 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all ${stockFilter === 'low' ? 'bg-amber-500/20 text-amber-500' : 'text-slate-500'}`}>Bajo</button>
               <button onClick={() => setStockFilter('out')} className={`flex-1 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all ${stockFilter === 'out' ? 'bg-red-500/20 text-red-500' : 'text-slate-500'}`}>Agotado</button>
            </div>
          </div>

          <div className="bg-slate-900/50 border border-slate-800 rounded-[2.5rem] overflow-hidden shadow-2xl overflow-x-auto">
            <table className="w-full text-left min-w-[800px]">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-800/20 text-slate-500 text-[10px] font-black uppercase tracking-[0.2em]">
                  <th className="px-8 py-6">Producto</th>
                  <th className="px-8 py-6">Categoría</th>
                  <th className="px-8 py-6">Precio</th>
                  <th className="px-8 py-6">Stock Actual e Ingreso Manual</th>
                  <th className="px-8 py-6 text-right">Acciones</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50 text-slate-300">
                {filteredProducts.map(product => {
                  const isLow = product.stockEnabled && product.stockQuantity <= product.stockMin && product.stockQuantity > 0;
                  const isOut = product.stockEnabled && product.stockQuantity <= 0;
                  const manualVal = manualAdjustments[product.id] || "";

                  return (
                    <tr key={product.id} className="hover:bg-slate-800/30 transition-colors group">
                      <td className="px-8 py-6">
                        <div className="flex items-center gap-4">
                          <div className="w-12 h-12 bg-slate-800 rounded-xl overflow-hidden border border-slate-700 flex items-center justify-center flex-shrink-0">
                            {product.imageUrl ? <img src={product.imageUrl} className="w-full h-full object-cover" /> : <Layers size={20} className="text-slate-600" />}
                          </div>
                          <div>
                            <span className="font-bold text-slate-100 block">{product.name}</span>
                            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">SKU: {product.sku || '---'}</span>
                          </div>
                        </div>
                      </td>
                      <td className="px-8 py-6">
                        <span className="px-3 py-1 bg-slate-800 rounded-lg text-[10px] font-black uppercase tracking-widest text-slate-400 border border-slate-700">
                          {categories.find(c => c.id === product.categoryId)?.name || 'Sin cat.'}
                        </span>
                      </td>
                      <td className="px-8 py-6 font-black text-emerald-400 text-lg">${product.price.toLocaleString()}</td>
                      <td className="px-8 py-6">
                        {!product.stockEnabled ? (
                          <span className="text-slate-600 font-black italic text-xs uppercase tracking-widest">Ilimitado</span>
                        ) : (
                          <div className="flex items-center gap-6">
                            <div className="flex flex-col">
                              <span className={`text-xl font-black ${isOut ? 'text-red-500' : (isLow ? 'text-amber-500' : 'text-slate-200')}`}>{product.stockQuantity}</span>
                              <span className="text-[8px] font-black text-slate-600 uppercase tracking-[0.2em]">unidades</span>
                            </div>
                            
                            <div className="flex items-center gap-2">
                              {/* Quick Adjustment Input */}
                              <div className="relative group/input">
                                <input 
                                  type="text"
                                  placeholder="+/-"
                                  value={manualVal}
                                  onChange={(e) => setManualAdjustments(prev => ({ ...prev, [product.id]: e.target.value }))}
                                  onKeyDown={(e) => e.key === 'Enter' && handleManualStockApply(product.id)}
                                  className="w-16 bg-slate-800 border border-slate-700 rounded-lg py-1 px-2 text-center text-xs font-bold text-white focus:ring-2 focus:ring-blue-500/50 outline-none transition-all placeholder:text-slate-600"
                                />
                                {manualVal && (
                                  <button 
                                    onClick={() => handleManualStockApply(product.id)}
                                    className="absolute -right-8 top-1/2 -translate-y-1/2 p-1.5 bg-emerald-600 text-white rounded-md hover:bg-emerald-500 shadow-lg animate-in zoom-in-50 duration-200"
                                  >
                                    <Check size={12} />
                                  </button>
                                )}
                              </div>

                              <div className="flex items-center gap-1 ml-2 opacity-30 group-hover:opacity-100 transition-opacity">
                                <button onClick={() => handleQuickStock(product.id, -1)} className="p-1.5 bg-slate-800 hover:bg-red-500/20 text-slate-500 hover:text-red-400 rounded-lg transition-all"><MinusCircle size={16} /></button>
                                <button onClick={() => handleQuickStock(product.id, 1)} className="p-1.5 bg-slate-800 hover:bg-emerald-500/20 text-slate-500 hover:text-emerald-400 rounded-lg transition-all"><PlusCircle size={16} /></button>
                              </div>
                            </div>
                          </div>
                        )}
                      </td>
                      <td className="px-8 py-6 text-right">
                        <div className="flex items-center justify-end gap-2">
                           <button onClick={() => { setModalType('product'); setEditingItem(product); if (product.imageUrl) { setGeneratedImageUrl(product.imageUrl); } setIsModalOpen(true); }} className="p-3 bg-slate-800 hover:bg-blue-600 text-slate-400 hover:text-white rounded-xl transition-all shadow-lg active:scale-90"><Edit2 size={18} /></button>
                           <button onClick={() => handleDelete('products', product.id)} className="p-3 bg-slate-800 hover:bg-red-600 text-slate-400 hover:text-white rounded-xl transition-all shadow-lg active:scale-90"><Trash2 size={18} /></button>
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

      {activeTab === 'categories' && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {/* Add Category Quick Card */}
          <button 
            data-tour="add-category"
            onClick={() => { setModalType('category'); setEditingItem(null); setIsModalOpen(true); }}
            className="bg-slate-900/40 border-2 border-dashed border-slate-800 p-8 rounded-[2rem] hover:border-blue-500/50 hover:bg-blue-500/5 transition-all group flex flex-col items-center justify-center gap-4 min-h-[160px]"
          >
            <div className="p-4 bg-slate-800 text-slate-500 rounded-2xl group-hover:bg-blue-600 group-hover:text-white transition-all">
              <PlusSquare size={32} />
            </div>
            <span className="text-sm font-black uppercase tracking-widest text-slate-500 group-hover:text-blue-400 transition-colors">Nueva Categoría</span>
          </button>

          {categories.map(cat => (
            <div key={cat.id} className="bg-slate-900 border border-slate-800 p-8 rounded-[2rem] hover:border-blue-500/50 transition-all group relative shadow-xl hover:shadow-blue-500/5">
               <div className="flex items-center justify-between mb-4">
                 <div className="p-3 bg-blue-600/10 text-blue-400 rounded-xl"><Layers size={24} /></div>
                 <div className="flex gap-2">
                    <button onClick={() => { setModalType('category'); setEditingItem(cat); setIsModalOpen(true); }} className="p-2 text-slate-500 hover:text-blue-400 transition-colors"><Edit2 size={16} /></button>
                    <button onClick={() => handleDelete('categories', cat.id)} className="p-2 text-slate-500 hover:text-red-400 transition-colors"><Trash2 size={16} /></button>
                 </div>
               </div>
               <h4 className="text-xl font-black text-slate-100 italic mb-2 tracking-tight">{cat.name}</h4>
               <p className="text-[10px] font-black text-slate-500 uppercase tracking-widest">{products.filter(p => p.categoryId === cat.id).length} Productos asociados</p>
            </div>
          ))}
        </div>
      )}

      {activeTab === 'history' && (
        <div className="bg-slate-900/50 border border-slate-800 rounded-[2.5rem] overflow-hidden shadow-2xl">
           <table className="w-full text-left">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-800/20 text-slate-500 text-[10px] font-black uppercase tracking-[0.2em]">
                  <th className="px-8 py-6">Fecha / Hora</th>
                  <th className="px-8 py-6">Producto</th>
                  <th className="px-8 py-6">Movimiento</th>
                  <th className="px-8 py-6">Motivo / Usuario</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50 text-slate-300">
                {logs.map(log => {
                  const prod = products.find(p => p.id === log.entityId);
                  const diff = log.after.stock - log.before.stock;
                  return (
                    <tr key={log.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="px-8 py-6"><span className="text-xs font-bold text-slate-400">{new Date(log.timestamp).toLocaleString()}</span></td>
                      <td className="px-8 py-6 font-bold text-slate-100">{prod?.name || 'Item eliminado'}</td>
                      <td className="px-8 py-6"><div className={`flex items-center gap-2 font-black ${diff > 0 ? 'text-emerald-400' : 'text-red-400'}`}>{diff > 0 ? <ArrowUpRight size={16} /> : <ArrowDownRight size={16} />}{diff > 0 ? `+${diff}` : diff} unidades</div></td>
                      <td className="px-8 py-6"><div className="flex flex-col"><span className="text-sm font-medium text-slate-300 italic">"{log.after.reason}"</span><span className="text-[10px] text-slate-500 uppercase font-black tracking-widest mt-1">ID: {log.userId}</span></div></td>
                    </tr>
                  );
                })}
              </tbody>
           </table>
        </div>
      )}

      {/* AI Photo Modal */}
      <Modal isOpen={isAiModalOpen} onClose={() => { stopCamera(); setIsAiModalOpen(false); }} title="Añadir con IA">
        <div className="space-y-6">
          <div className="relative aspect-video bg-slate-950 rounded-[1.5rem] overflow-hidden border border-slate-800 shadow-2xl">
            {!capturedImage ? (
              <>
                <video ref={videoRef} className="w-full h-full object-cover" muted playsInline />
                <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                  <div className="w-48 h-48 border-2 border-dashed border-white/20 rounded-3xl"></div>
                </div>
                <button onClick={capturePhoto} className="absolute bottom-6 left-1/2 -translate-x-1/2 w-16 h-16 bg-white rounded-full border-4 border-slate-300 shadow-xl active:scale-90 transition-all flex items-center justify-center">
                  <Camera className="text-slate-900" size={24} />
                </button>
              </>
            ) : (
              <div className="relative w-full h-full">
                <img src={capturedImage} className="w-full h-full object-cover" />
                <button onClick={() => { setCapturedImage(null); startCamera(); }} className="absolute top-4 right-4 p-2 bg-slate-900/80 text-white rounded-full hover:bg-slate-800 transition-colors">
                  <RefreshIcon size={18} />
                </button>
              </div>
            )}
            <canvas ref={canvasRef} className="hidden" />
          </div>
          <button disabled={!capturedImage || aiLoading} onClick={analyzeWithAi} className="w-full py-5 bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-500 hover:to-blue-500 disabled:opacity-50 text-white rounded-2xl font-black text-lg flex items-center justify-center gap-3">
            {aiLoading ? <Loader2 className="animate-spin" /> : <Sparkles />} Procesar Imagen
          </button>
        </div>
      </Modal>

      {/* Main Modal (Categoría o Producto) */}
      <Modal 
        isOpen={isModalOpen} 
        onClose={() => setIsModalOpen(false)} 
        title={editingItem ? `Editar ${modalType === 'product' ? 'Producto' : 'Categoría'}` : `Nuevo ${modalType === 'product' ? 'Producto' : 'Categoría'}`}
      >
        {modalType === 'category' ? (
          <form onSubmit={async (e) => {
            e.preventDefault();
            const name = new FormData(e.currentTarget).get('name') as string;
            if (isCloud) {
              try {
                const headers = getAuthHeaders();
                if (editingItem) {
                  await fetch(`/api/categories/${editingItem.id}`, {
                    method: 'PUT',
                    headers,
                    body: JSON.stringify({ name }),
                  });
                } else {
                  await fetch('/api/categories', {
                    method: 'POST',
                    headers,
                    body: JSON.stringify({ name, sort_order: categories.length }),
                  });
                }
                await refreshData();
                setIsModalOpen(false);
              } catch (err: any) {
                console.error(err);
                alert(err.message || 'No se pudo guardar la categoría');
              }
            } else {
              if (editingItem) db.update<Category>('categories', editingItem.id, tenantId, { name });
              else db.insert<Category>('categories', { id: `cat-${Date.now()}`, tenantId, name, order: categories.length + 1 });
              refreshData(); setIsModalOpen(false);
            }
          }} className="space-y-6">
            <div className="space-y-2">
              <label className="text-xs font-black text-slate-500 uppercase tracking-widest ml-1">Nombre de la Categoría</label>
              <input name="name" required autoFocus defaultValue={editingItem?.name} className="w-full bg-slate-800 border border-slate-700 rounded-2xl py-4 px-6 text-slate-100 font-bold focus:ring-2 focus:ring-blue-500/50 outline-none transition-all" placeholder="Ej: Hamburguesas, Ensaladas..." />
            </div>
            <button type="submit" className="w-full py-5 bg-blue-600 hover:bg-blue-500 text-white rounded-2xl font-black text-lg shadow-xl shadow-blue-600/20 transition-all active:scale-95 flex items-center justify-center gap-2">
              <Check size={20} /> Guardar Categoría
            </button>
          </form>
        ) : (
          <form onSubmit={async (e) => {
            e.preventDefault();
            const fd = new FormData(e.currentTarget);
            const data: any = {
              name: fd.get('name'),
              sku: fd.get('sku'),
              categoryId: fd.get('categoryId'),
              price: Number(fd.get('price')),
              stockEnabled: fd.get('stockEnabled') === 'on',
              stockQuantity: Number(fd.get('stockQuantity') || 0),
              stockMin: Number(fd.get('stockMin') || 5),
              description: fd.get('description'),
              isActive: true,
              imageUrl: generatedImageUrl
            };

            if (isCloud) {
              try {
                const headers = getAuthHeaders();
                const payload: any = {
                  name: data.name,
                  sku: data.sku || undefined,
                  category_id: data.categoryId || null,
                  price: data.price,
                  description: data.description || '',
                  stock_enabled: data.stockEnabled,
                  stock_quantity: data.stockQuantity,
                  stock_min: data.stockMin,
                  is_active: true,
                  image_url: data.imageUrl || null,
                };

                if (editingItem?.id) {
                  await fetch(`/api/products/${editingItem.id}`, {
                    method: 'PUT',
                    headers,
                    body: JSON.stringify(payload),
                  });
                } else {
                  await fetch('/api/products', {
                    method: 'POST',
                    headers,
                    body: JSON.stringify(payload),
                  });
                }

                await refreshData();
                setIsModalOpen(false);
              } catch (err: any) {
                console.error(err);
                alert(err.message || 'No se pudo guardar el producto');
              }
            } else {
              if (editingItem?.id) db.update<Product>('products', editingItem.id, tenantId, data);
              else db.insert<Product>('products', { id: `p-${Date.now()}`, tenantId, ...data });
              refreshData(); setIsModalOpen(false);
            }
          }} className="space-y-6">
            <div className="grid grid-cols-2 gap-6">
              <div className="col-span-2 flex flex-col items-center gap-4">
                <div className="w-40 h-40 bg-slate-800 border border-slate-700 rounded-3xl overflow-hidden flex items-center justify-center relative shadow-inner">
                  {generatedImageUrl ? <img src={generatedImageUrl} className="w-full h-full object-cover" /> : <ImagePlus size={48} className="text-slate-700" />}
                  {imgGenLoading && <div className="absolute inset-0 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center text-white text-xs font-black uppercase tracking-widest"><Loader2 className="animate-spin mr-2" /> Generando...</div>}
                </div>
                <button type="button" onClick={generateProductImage} disabled={imgGenLoading} className="px-6 py-2.5 bg-purple-600/10 text-purple-400 hover:bg-purple-600/20 border border-purple-500/30 rounded-xl font-black text-[10px] uppercase tracking-widest flex items-center gap-2 transition-all active:scale-95">
                  <Sparkles size={14} /> Generar Imagen Ilustrativa (IA)
                </button>
              </div>
              <div className="col-span-2 space-y-2">
                <label className="text-xs font-black text-slate-500 uppercase tracking-widest">Nombre</label>
                <input ref={productNameRef} name="name" required defaultValue={editingItem?.name} className="w-full bg-slate-800 border border-slate-700 rounded-2xl py-4 px-6 text-slate-100 outline-none" />
              </div>
              <div className="col-span-2 space-y-2">
                <label className="text-xs font-black text-slate-500 uppercase tracking-widest">Descripción</label>
                <textarea ref={productDescRef} name="description" rows={2} defaultValue={editingItem?.description} className="w-full bg-slate-800 border border-slate-700 rounded-2xl py-4 px-6 text-slate-100 resize-none outline-none" />
              </div>
              <div className="space-y-2">
                <label className="text-xs font-black text-slate-500 uppercase tracking-widest">SKU / Código</label>
                <input name="sku" defaultValue={editingItem?.sku} className="w-full bg-slate-800 border border-slate-700 rounded-2xl py-4 px-6 text-slate-100 outline-none" />
              </div>
              <div className="space-y-2">
                <label className="text-xs font-black text-slate-500 uppercase tracking-widest">Categoría</label>
                <select name="categoryId" required defaultValue={editingItem?.categoryId} className="w-full bg-slate-800 border border-slate-700 rounded-2xl py-4 px-6 text-slate-100 outline-none">
                  <option value="">Seleccionar...</option>
                  {categories.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
                </select>
              </div>
              <div className="space-y-2">
                <label className="text-xs font-black text-slate-500 uppercase tracking-widest">Precio</label>
                <input name="price" type="number" required defaultValue={editingItem?.price} className="w-full bg-slate-800 border border-slate-700 rounded-2xl py-4 px-6 text-slate-100 outline-none" />
              </div>
              <div className="space-y-2">
                <label className="text-xs font-black text-slate-500 uppercase tracking-widest">Mínimo Stock</label>
                <input name="stockMin" type="number" defaultValue={editingItem?.stockMin || 5} className="w-full bg-slate-800 border border-slate-700 rounded-2xl py-4 px-6 text-slate-100 outline-none" />
              </div>
              {!editingItem?.id && (
                <div className="col-span-2 space-y-2">
                  <label className="text-xs font-black text-slate-500 uppercase tracking-widest">Existencia Inicial</label>
                  <input name="stockQuantity" type="number" defaultValue={0} className="w-full bg-slate-800 border border-slate-700 rounded-2xl py-4 px-6 text-slate-100 outline-none" />
                </div>
              )}
              <div className="col-span-2 flex items-center gap-3 p-5 bg-slate-800/40 rounded-3xl border border-slate-700/50">
                <input id="stockEnabled" name="stockEnabled" type="checkbox" defaultChecked={editingItem ? editingItem.stockEnabled : true} className="w-6 h-6 rounded-lg bg-slate-700" />
                <label htmlFor="stockEnabled" className="text-sm font-bold text-slate-300">Controlar Stock</label>
              </div>
            </div>
            <button type="submit" className="w-full py-5 bg-blue-600 hover:bg-blue-500 text-white rounded-2xl font-black text-lg transition-all active:scale-95 flex items-center justify-center gap-2">
              <Check size={20} /> Guardar Producto
            </button>
          </form>
        )}
      </Modal>
    </div>
  );
};

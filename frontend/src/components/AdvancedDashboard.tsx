import React, { useState, useEffect } from 'react';
import { 
  Shield, AlertTriangle, CheckCircle, Cpu, HardDrive, Activity, 
  Zap, TrendingUp, Users, FileText, Clock, RefreshCw, Eye, 
  Folder, Globe, Database, Settings, Search, Filter, 
  Download, Trash2, Info, BarChart3, PieChart, LineChart
} from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar } from 'recharts';
import axios from 'axios';
import DetailedView from './DetailedView';

interface SystemStatus {
  status: string;
  threats_detected: number;
  files_protected: number;
  last_scan: string;
  cpu_usage: number;
  memory_usage: number;
  disk_usage: number;
  network_activity: number;
  active_processes: number;
  protection_enabled: boolean;
  real_time_monitoring: boolean;
  last_threat_detected: string | null;
}

interface Threat {
  id: string;
  threat_type: string;
  severity: string;
  description: string;
  timestamp: string;
  file_path?: string;
  process_name?: string;
  confidence: number;
  quarantined: boolean;
  resolved: boolean;
}

interface ModelStatus {
  name: string;
  status: 'active' | 'inactive' | 'training';
  accuracy: number;
  last_updated: string;
  predictions_today: number;
}

interface MonitoringItem {
  id: string;
  type: 'folder' | 'process' | 'network' | 'file';
  name: string;
  path?: string;
  status: 'monitored' | 'alert' | 'clean' | 'suspicious';
  last_activity: string;
  threat_count: number;
  size?: number;
  details?: any;
}

interface ScanSummary {
  id: string;
  type: string;
  status: string;
  start_time: string;
  end_time?: string;
  files_scanned: number;
  threats_found: number;
  progress: number;
}

const AdvancedDashboard: React.FC = () => {
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [modelStatus, setModelStatus] = useState<ModelStatus[]>([]);
  const [monitoringItems, setMonitoringItems] = useState<MonitoringItem[]>([]);
  const [scanHistory, setScanHistory] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [advancedHooks, setAdvancedHooks] = useState<any>(null);
  const [threatIntel, setThreatIntel] = useState<any>(null);
  
  // État pour la vue détaillée
  const [detailedView, setDetailedView] = useState<{
    isOpen: boolean;
    viewType: 'scan' | 'threat' | 'folder' | 'process' | 'network' | 'system';
    itemId?: string;
    itemData?: any;
  }>({
    isOpen: false,
    viewType: 'scan'
  });

  // Filtres et recherche
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [typeFilter, setTypeFilter] = useState<string>('all');

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(() => {
      if (autoRefresh) {
        fetchDashboardData();
      }
    }, 10000);
    return () => clearInterval(interval);
  }, [autoRefresh]);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      
      // Récupérer le statut système
      const statusResponse = await axios.get('/api/status');
      setSystemStatus(statusResponse.data);
      
      // Récupérer les menaces récentes
      const threatsResponse = await axios.get('/api/threats');
      setThreats(threatsResponse.data.threats || []);
      
      // Récupérer le statut des modèles
      const modelsResponse = await axios.get('/api/models/status');
      setModelStatus(modelsResponse.data.models || []);

      // Récupérer les éléments surveillés
      try {
        const monitoringResponse = await axios.get('/api/system/stats');
        const stats = monitoringResponse.data;
        
        // Construire la liste des éléments surveillés
        const items: MonitoringItem[] = [];
        
        // Dossiers surveillés
        if (stats.file_monitor?.watched_paths) {
          stats.file_monitor.watched_paths.forEach((path: string) => {
            items.push({
              id: `folder-${path}`,
              type: 'folder',
              name: path.split('\\').pop() || path.split('/').pop() || path,
              path: path,
              status: 'monitored',
              last_activity: new Date().toISOString(),
              threat_count: 0
            });
          });
        }
        
        // Processus suspects
        if (stats.process_monitor?.processes) {
          stats.process_monitor.processes.forEach((proc: any) => {
            items.push({
              id: `process-${proc.pid}`,
              type: 'process',
              name: proc.name || 'Unknown',
              status: proc.suspicious_score > 0.7 ? 'suspicious' : 'monitored',
              last_activity: new Date().toISOString(),
              threat_count: proc.suspicious_score > 0.7 ? 1 : 0,
              details: proc
            });
          });
        }
        
        setMonitoringItems(items);
      } catch (error) {
        console.error('Erreur récupération monitoring:', error);
      }

      // Récupérer l'historique des scans
      try {
        const scansResponse = await axios.get('/api/scan/status');
        if (Array.isArray(scansResponse.data)) {
          setScanHistory(scansResponse.data);
        } else {
          setScanHistory([scansResponse.data]);
        }
      } catch (error) {
        console.error('Erreur récupération scans:', error);
      }

      // Récupérer hooks système avancés
      try {
        const hooksResp = await axios.get('/api/advanced-hooks/status');
        setAdvancedHooks(hooksResp.data);
      } catch {}

      // Récupérer threat intelligence
      try {
        const tiResp = await axios.get('/api/threat-intelligence/status');
        setThreatIntel(tiResp.data);
      } catch {}
      
      setError(null);
      setLastRefresh(new Date());
    } catch (err) {
      console.error('Erreur lors de la récupération des données:', err);
      setError('Erreur de connexion au serveur');
    } finally {
      setLoading(false);
    }
  };

  const handleQuickScan = async () => {
    try {
      await axios.post('/api/scan', {
        scan_type: 'quick',
        use_advanced_detection: true
      });
      // Rafraîchir les données après le scan
      setTimeout(fetchDashboardData, 2000);
    } catch (error) {
      console.error('Erreur lors du lancement du scan:', error);
    }
  };

  const handleQuarantineThreat = async (threatId: string) => {
    try {
      await axios.post(`/api/threats/${threatId}/quarantine`);
      fetchDashboardData(); // Rafraîchir
    } catch (error) {
      console.error('Erreur lors de la mise en quarantaine:', error);
    }
  };

  const openDetailedView = (viewType: 'scan' | 'threat' | 'folder' | 'process' | 'network' | 'system', itemId?: string, itemData?: any) => {
    setDetailedView({
      isOpen: true,
      viewType,
      itemId,
      itemData
    });
  };

  const closeDetailedView = () => {
    setDetailedView({
      isOpen: false,
      viewType: 'scan'
    });
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-200';
      case 'high': return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'low': return 'bg-blue-100 text-blue-800 border-blue-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'active': return 'bg-green-100 text-green-800';
      case 'inactive': return 'bg-red-100 text-red-800';
      case 'training': return 'bg-yellow-100 text-yellow-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status.toLowerCase()) {
      case 'monitored': return <Shield className="w-4 h-4 text-blue-500" />;
      case 'alert': return <AlertTriangle className="w-4 h-4 text-red-500" />;
      case 'clean': return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'suspicious': return <AlertTriangle className="w-4 h-4 text-orange-500" />;
      default: return <Info className="w-4 h-4 text-gray-500" />;
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'folder': return <Folder className="w-4 h-4 text-blue-500" />;
      case 'process': return <Cpu className="w-4 h-4 text-green-500" />;
      case 'network': return <Globe className="w-4 h-4 text-purple-500" />;
      case 'file': return <FileText className="w-4 h-4 text-gray-500" />;
      default: return <Info className="w-4 h-4 text-gray-500" />;
    }
  };

  // Filtrer les éléments
  const filteredItems = monitoringItems.filter(item => {
    const matchesSearch = item.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         (item.path && item.path.toLowerCase().includes(searchTerm.toLowerCase()));
    const matchesStatus = statusFilter === 'all' || item.status === statusFilter;
    const matchesType = typeFilter === 'all' || item.type === typeFilter;
    
    return matchesSearch && matchesStatus && matchesType;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <RefreshCw className="w-8 h-8 animate-spin text-blue-600" />
        <span className="ml-2 text-gray-600">Chargement du dashboard...</span>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* En-tête */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-gray-900">Dashboard Avancé</h1>
            <p className="text-gray-600">Vue d'ensemble complète du système de sécurité</p>
          </div>
          <div className="flex items-center space-x-3">
            <button
              onClick={handleQuickScan}
              className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors flex items-center space-x-2"
            >
              <Zap className="w-4 h-4" />
              <span>Scan Rapide</span>
            </button>
            <button
              onClick={fetchDashboardData}
              className="p-2 text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded-lg transition-colors"
              title="Actualiser"
            >
              <RefreshCw className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Statistiques principales */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <div className="bg-gradient-to-br from-blue-500 to-blue-600 rounded-xl p-6 text-white">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-blue-100 text-sm font-medium">Statut système</p>
                <p className="text-3xl font-bold">{systemStatus?.status || 'Unknown'}</p>
              </div>
              <Shield className="w-8 h-8 text-blue-200" />
            </div>
            <div className="mt-4">
              <span className="text-xs text-blue-200">
                Protection: {systemStatus?.protection_enabled ? 'Active' : 'Inactive'}
              </span>
            </div>
          </div>

          <div className="bg-gradient-to-br from-green-500 to-green-600 rounded-xl p-6 text-white">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-green-100 text-sm font-medium">Fichiers protégés</p>
                <p className="text-3xl font-bold">{systemStatus?.files_protected || 0}</p>
              </div>
              <CheckCircle className="w-8 h-8 text-green-200" />
            </div>
            <div className="mt-4">
              <span className="text-xs text-green-200">
                Dernier scan: {systemStatus?.last_scan ? new Date(systemStatus.last_scan).toLocaleString('fr-FR') : 'Jamais'}
              </span>
            </div>
          </div>

          <div className="bg-gradient-to-br from-purple-500 to-purple-600 rounded-xl p-6 text-white">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-purple-100 text-sm font-medium">Utilisation système</p>
                <p className="text-3xl font-bold">{systemStatus?.cpu_usage?.toFixed(1) || '0'}%</p>
              </div>
              <Cpu className="w-8 h-8 text-purple-200" />
            </div>
            <div className="mt-4">
              <div className="w-full bg-purple-400 rounded-full h-2">
                <div 
                  className="bg-white h-2 rounded-full transition-all duration-300"
                  style={{ width: `${systemStatus?.cpu_usage || 0}%` }}
                ></div>
              </div>
            </div>
          </div>

          <div className="bg-gradient-to-br from-orange-500 to-orange-600 rounded-xl p-6 text-white">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-orange-100 text-sm font-medium">Mémoire</p>
                <p className="text-3xl font-bold">{systemStatus?.memory_usage?.toFixed(1) || '0'}%</p>
              </div>
              <HardDrive className="w-8 h-8 text-orange-200" />
            </div>
            <div className="mt-4">
              <div className="w-full bg-orange-400 rounded-full h-2">
                <div 
                  className="bg-white h-2 rounded-full transition-all duration-300"
                  style={{ width: `${systemStatus?.memory_usage || 0}%` }}
                ></div>
              </div>
            </div>
          </div>
        </div>

        {/* Section Éléments Surveillés */}
        <div className="bg-white rounded-lg shadow-sm border">
          <div className="p-6 border-b">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xl font-semibold text-gray-900">Éléments Surveillés</h2>
                <p className="text-gray-600">Dossiers, processus et connexions surveillés en temps réel</p>
              </div>
              <button
                onClick={() => openDetailedView('system')}
                className="text-blue-600 hover:text-blue-700 font-medium text-sm flex items-center space-x-2"
              >
                <Settings className="w-4 h-4" />
                <span>Voir détails système</span>
              </button>
            </div>
          </div>

          {/* Filtres et recherche */}
          <div className="p-6 border-b bg-gray-50">
            <div className="flex flex-col sm:flex-row gap-4">
              <div className="flex-1">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                  <input
                    type="text"
                    placeholder="Rechercher un élément..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>
              </div>
              <div className="flex gap-2">
                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                  <option value="all">Tous les statuts</option>
                  <option value="monitored">Surveillé</option>
                  <option value="alert">Alerte</option>
                  <option value="clean">Propre</option>
                  <option value="suspicious">Suspect</option>
                </select>
                <select
                  value={typeFilter}
                  onChange={(e) => setTypeFilter(e.target.value)}
                  className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                  <option value="all">Tous les types</option>
                  <option value="folder">Dossiers</option>
                  <option value="process">Processus</option>
                  <option value="network">Réseau</option>
                  <option value="file">Fichiers</option>
                </select>
              </div>
            </div>
          </div>

          {/* Liste des éléments */}
          <div className="p-6">
            {filteredItems.length > 0 ? (
              <div className="space-y-3">
                {filteredItems.map((item) => (
                  <div key={item.id} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg border hover:bg-gray-100 transition-colors">
                    <div className="flex items-center space-x-3">
                      {getTypeIcon(item.type)}
                      <div>
                        <p className="font-medium text-gray-900">{item.name}</p>
                        {item.path && (
                          <p className="text-sm text-gray-600 font-mono">{item.path}</p>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center space-x-4">
                      <div className="flex items-center space-x-2">
                        {getStatusIcon(item.status)}
                        <span className={`px-2 py-1 text-xs font-medium rounded-full ${getStatusColor(item.status)}`}>
                          {item.status}
                        </span>
                      </div>
                      <div className="text-right">
                        <p className="text-sm text-gray-600">
                          {item.threat_count > 0 ? (
                            <span className="text-red-600 font-medium">{item.threat_count} menace{item.threat_count > 1 ? 's' : ''}</span>
                          ) : (
                            <span className="text-green-600">Aucune menace</span>
                          )}
                        </p>
                        <p className="text-xs text-gray-500">
                          {new Date(item.last_activity).toLocaleString('fr-FR')}
                        </p>
                      </div>
                      <button
                        onClick={() => openDetailedView(item.type as any, item.id, item.details)}
                        className="p-2 text-gray-500 hover:text-gray-700 hover:bg-gray-200 rounded-lg transition-colors"
                        title="Voir les détails"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8">
                <Info className="w-12 h-12 text-gray-400 mx-auto mb-3" />
                <h3 className="text-lg font-medium text-gray-900">Aucun élément trouvé</h3>
                <p className="text-gray-500">Ajustez vos filtres ou ajoutez des éléments à surveiller</p>
              </div>
            )}
          </div>
        </div>

        {/* Section Historique des Scans */}
        <div className="bg-white rounded-lg shadow-sm border">
          <div className="p-6 border-b">
            <h2 className="text-xl font-semibold text-gray-900">Historique des Scans</h2>
            <p className="text-gray-600">Résultats des derniers scans effectués</p>
          </div>
          <div className="p-6">
            {scanHistory.length > 0 ? (
              <div className="space-y-3">
                {scanHistory.slice(0, 5).map((scan) => (
                  <div key={scan.id} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg border">
                    <div className="flex items-center space-x-3">
                      <Activity className="w-5 h-5 text-blue-500" />
                      <div>
                        <p className="font-medium text-gray-900">{scan.type} - {scan.status}</p>
                        <p className="text-sm text-gray-600">
                          {new Date(scan.start_time).toLocaleString('fr-FR')}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-4">
                      <div className="text-right">
                        <p className="text-sm text-gray-600">
                          {scan.files_scanned} fichiers scannés
                        </p>
                        <p className="text-sm text-gray-600">
                          {scan.threats_found} menaces trouvées
                        </p>
                      </div>
                      <button
                        onClick={() => openDetailedView('scan', scan.id)}
                        className="p-2 text-gray-500 hover:text-gray-700 hover:bg-gray-200 rounded-lg transition-colors"
                        title="Voir les détails"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8">
                <Activity className="w-12 h-12 text-gray-400 mx-auto mb-3" />
                <h3 className="text-lg font-medium text-gray-900">Aucun scan effectué</h3>
                <p className="text-gray-500">Lancez votre premier scan pour commencer</p>
              </div>
            )}
          </div>
        </div>

        {/* Section Menaces Récentes */}
        <div className="bg-white rounded-lg shadow-sm border">
          <div className="p-6 border-b">
            <div className="flex items-center justify-between">
              <h2 className="text-xl font-semibold text-gray-900">Menaces Récentes</h2>
              <button className="text-sm text-blue-600 hover:text-blue-700 font-medium">
                Voir toutes
              </button>
            </div>
          </div>
          <div className="p-6">
            {threats.length > 0 ? (
              <div className="space-y-3">
                {threats.slice(0, 5).map((threat) => (
                  <div key={threat.id} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg border-l-4 border-red-500">
                    <div className="flex items-center space-x-3">
                      <AlertTriangle className="w-5 h-5 text-red-500" />
                      <div>
                        <p className="text-sm font-medium text-gray-900">{threat.description}</p>
                        <p className="text-xs text-gray-500">
                          {new Date(threat.timestamp).toLocaleString('fr-FR')} • Confiance: {(threat.confidence * 100).toFixed(1)}%
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getSeverityColor(threat.severity)}`}>
                        {threat.severity}
                      </span>
                      <button
                        onClick={() => openDetailedView('threat', threat.id)}
                        className="p-2 text-gray-500 hover:text-gray-700 hover:bg-gray-200 rounded-lg transition-colors"
                        title="Voir les détails"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                      {!threat.quarantined && (
                        <button
                          onClick={() => handleQuarantineThreat(threat.id)}
                          className="text-xs bg-red-600 text-white px-2 py-1 rounded hover:bg-red-700 transition-colors"
                        >
                          Quarantaine
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8">
                <CheckCircle className="w-12 h-12 text-green-500 mx-auto mb-3" />
                <h3 className="text-lg font-medium text-gray-900">Aucune menace détectée</h3>
                <p className="text-gray-500">Votre système est actuellement protégé</p>
              </div>
            )}
          </div>
        </div>

        {/* Graphiques et analyses */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Activité système */}
          <div className="bg-white rounded-lg shadow-sm border p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-gray-900">Activité système</h3>
              <Activity className="w-5 h-5 text-blue-600" />
            </div>
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={[
                { time: '00:00', cpu: systemStatus?.cpu_usage || 0, memory: systemStatus?.memory_usage || 0 },
                { time: '04:00', cpu: (systemStatus?.cpu_usage || 0) * 0.8, memory: (systemStatus?.memory_usage || 0) * 0.9 },
                { time: '08:00', cpu: (systemStatus?.cpu_usage || 0) * 1.2, memory: (systemStatus?.memory_usage || 0) * 1.1 },
                { time: '12:00', cpu: systemStatus?.cpu_usage || 0, memory: systemStatus?.memory_usage || 0 },
                { time: '16:00', cpu: (systemStatus?.cpu_usage || 0) * 1.1, memory: (systemStatus?.memory_usage || 0) * 1.05 },
                { time: '20:00', cpu: (systemStatus?.cpu_usage || 0) * 0.9, memory: (systemStatus?.memory_usage || 0) * 0.95 },
                { time: '24:00', cpu: (systemStatus?.cpu_usage || 0) * 0.7, memory: (systemStatus?.memory_usage || 0) * 0.9 },
              ]}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis />
                <Tooltip />
                <Line type="monotone" dataKey="cpu" stroke="#3b82f6" strokeWidth={2} name="CPU" />
                <Line type="monotone" dataKey="memory" stroke="#10b981" strokeWidth={2} name="Mémoire" />
              </LineChart>
            </ResponsiveContainer>
          </div>

          {/* Statut des modèles IA */}
          <div className="bg-white rounded-lg shadow-sm border p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-gray-900">Modèles IA</h3>
              <Zap className="w-5 h-5 text-purple-600" />
            </div>
            <div className="space-y-3">
              {modelStatus.map((model) => (
                <div key={model.name} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center space-x-3">
                    <div className={`w-3 h-3 rounded-full ${getStatusColor(model.status).split(' ')[0]}`}></div>
                    <div>
                      <p className="text-sm font-medium text-gray-900">{model.name}</p>
                      <p className="text-xs text-gray-500">{model.predictions_today} prédictions aujourd'hui</p>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="text-sm font-bold text-gray-900">{model.accuracy.toFixed(1)}%</p>
                    <p className="text-xs text-gray-500">Précision</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Informations système */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="bg-white rounded-lg shadow-sm border p-6">
            <div className="flex items-center space-x-3 mb-3">
              <Clock className="w-5 h-5 text-blue-600" />
              <h3 className="text-lg font-semibold text-gray-900">Dernière activité</h3>
            </div>
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-sm text-gray-600">Dernier scan:</span>
                <span className="text-sm font-medium">
                  {systemStatus?.last_scan ? new Date(systemStatus.last_scan).toLocaleString('fr-FR') : 'Jamais'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-gray-600">Dernière menace:</span>
                <span className="text-sm font-medium">
                  {systemStatus?.last_threat_detected ? new Date(systemStatus.last_threat_detected).toLocaleString('fr-FR') : 'Aucune'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-gray-600">Actualisation:</span>
                <span className="text-sm font-medium">
                  {lastRefresh.toLocaleTimeString('fr-FR')}
                </span>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow-sm border p-6">
            <div className="flex items-center space-x-3 mb-3">
              <Users className="w-5 h-5 text-green-600" />
              <h3 className="text-lg font-semibold text-gray-900">Processus actifs</h3>
            </div>
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-sm text-gray-600">Processus:</span>
                <span className="text-sm font-medium">{systemStatus?.active_processes || 0}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-gray-600">Réseau:</span>
                <span className="text-sm font-medium">{systemStatus?.network_activity?.toFixed(1) || 0} MB/s</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-gray-600">Disque:</span>
                <span className="text-sm font-medium">{systemStatus?.disk_usage?.toFixed(1) || 0}%</span>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow-sm border p-6">
            <div className="flex items-center space-x-3 mb-3">
              <FileText className="w-5 h-5 text-purple-600" />
              <h3 className="text-lg font-semibold text-gray-900">Protection</h3>
            </div>
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-sm text-gray-600">Temps réel:</span>
                <span className={`text-sm font-medium ${systemStatus?.real_time_monitoring ? 'text-green-600' : 'text-red-600'}`}>
                  {systemStatus?.real_time_monitoring ? 'Actif' : 'Inactif'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-gray-600">Protection:</span>
                <span className={`text-sm font-medium ${systemStatus?.protection_enabled ? 'text-green-600' : 'text-red-600'}`}>
                  {systemStatus?.protection_enabled ? 'Active' : 'Inactive'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-gray-600">Statut:</span>
                <span className={`text-sm font-medium ${systemStatus?.status === 'active' ? 'text-green-600' : 'text-red-600'}`}>
                  {systemStatus?.status === 'active' ? 'Opérationnel' : 'Erreur'}
                </span>
              </div>
            </div>
          </div>
        </div>

        {error && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-4">
            <div className="flex">
              <AlertTriangle className="w-5 h-5 text-red-400" />
              <div className="ml-3">
                <p className="text-sm text-red-800">{error}</p>
                <p className="text-xs text-red-600 mt-1">Vérifiez la connexion au serveur</p>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Vue détaillée */}
      <DetailedView
        isOpen={detailedView.isOpen}
        onClose={closeDetailedView}
        viewType={detailedView.viewType}
        itemId={detailedView.itemId}
        itemData={detailedView.itemData}
      />
    </div>
  );
};

export default AdvancedDashboard;

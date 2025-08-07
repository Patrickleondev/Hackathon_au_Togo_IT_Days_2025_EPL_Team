import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, CheckCircle, Cpu, HardDrive, Activity, Zap, TrendingUp, Users, FileText, Clock, RefreshCw } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar } from 'recharts';
import axios from 'axios';

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

const Dashboard: React.FC = () => {
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [modelStatus, setModelStatus] = useState<ModelStatus[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());
  const [autoRefresh, setAutoRefresh] = useState(true);

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(() => {
      if (autoRefresh) {
        fetchDashboardData();
      }
    }, 10000); // Rafraîchir toutes les 10 secondes
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
      await axios.post('/api/scan', { scan_type: 'quick' });
      // Rafraîchir les données après le scan
      setTimeout(fetchDashboardData, 2000);
    } catch (err) {
      console.error('Erreur lors du scan rapide:', err);
    }
  };

  const handleQuarantineThreat = async (threatId: string) => {
    try {
      await axios.post(`/api/threats/${threatId}/quarantine`);
      fetchDashboardData(); // Rafraîchir les données
    } catch (err) {
      console.error('Erreur lors de la mise en quarantaine:', err);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'high': return 'text-red-600 bg-red-100 border-red-200';
      case 'medium': return 'text-yellow-600 bg-yellow-100 border-yellow-200';
      case 'low': return 'text-green-600 bg-green-100 border-green-200';
      default: return 'text-gray-600 bg-gray-100 border-gray-200';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'text-green-600 bg-green-100';
      case 'inactive': return 'text-red-600 bg-red-100';
      case 'training': return 'text-yellow-600 bg-yellow-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  if (loading && !systemStatus) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="flex items-center space-x-3">
          <RefreshCw className="w-6 h-6 text-blue-600 animate-spin" />
          <span className="text-gray-600">Chargement des données en temps réel...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* En-tête avec contrôles */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Tableau de bord</h1>
          <p className="text-gray-600">Protection intelligente en temps réel</p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <div className={`w-3 h-3 rounded-full ${systemStatus?.protection_enabled ? 'bg-green-500' : 'bg-red-500'}`}></div>
            <span className="text-sm text-gray-600">
              {systemStatus?.protection_enabled ? 'Protection active' : 'Protection inactive'}
            </span>
          </div>
          <button
            onClick={fetchDashboardData}
            className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            <span>Actualiser</span>
          </button>
        </div>
      </div>

      {/* Métriques principales */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-gradient-to-br from-blue-500 to-blue-600 rounded-xl p-6 text-white">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-blue-100 text-sm font-medium">Menaces détectées</p>
              <p className="text-3xl font-bold">{systemStatus?.threats_detected || 0}</p>
            </div>
            <Shield className="w-8 h-8 text-blue-200" />
          </div>
          <div className="mt-4">
            <button
              onClick={handleQuickScan}
              className="text-xs bg-blue-400 hover:bg-blue-300 px-3 py-1 rounded-full transition-colors"
            >
              Scan rapide
            </button>
          </div>
        </div>

        <div className="bg-gradient-to-br from-green-500 to-green-600 rounded-xl p-6 text-white">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-green-100 text-sm font-medium">Fichiers protégés</p>
              <p className="text-3xl font-bold">{systemStatus?.files_protected?.toLocaleString() || '0'}</p>
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

      {/* Graphiques et analyses */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Activité système */}
        <div className="card">
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
        <div className="card">
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

      {/* Menaces récentes */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-900">Menaces récentes</h3>
          <button className="text-sm text-blue-600 hover:text-blue-700 font-medium">
            Voir toutes
          </button>
        </div>
        
        {threats.length > 0 ? (
          <div className="space-y-3">
            {threats.slice(0, 5).map((threat) => (
              <div key={threat.id} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg border-l-4 border-red-500">
                <div className="flex items-center space-x-3">
                  <AlertTriangle className="w-5 h-5 text-red-500" />
                  <div>
                    <p className="text-sm font-medium text-gray-900">{threat.description}</p>
                    <p className="text-xs text-gray-500">
                      {new Date(threat.timestamp).toLocaleString('fr-FR')} • Confiance: {threat.confidence.toFixed(1)}%
                    </p>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getSeverityColor(threat.severity)}`}>
                    {threat.severity}
                  </span>
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

      {/* Informations système */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="card">
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

        <div className="card">
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

        <div className="card">
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
  );
};

export default Dashboard; 
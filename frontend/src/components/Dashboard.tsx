import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, CheckCircle, Activity, Cpu, HardDrive, Wifi } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import axios from 'axios';

interface SystemStatus {
  status: string;
  threats_detected: number;
  files_protected: number;
  last_scan: string;
  cpu_usage: number;
  memory_usage: number;
}

interface Threat {
  id: string;
  threat_type: string;
  severity: string;
  description: string;
  timestamp: string;
  file_path?: string;
  process_name?: string;
}

const Dashboard: React.FC = () => {
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Données simulées pour les graphiques
  const cpuData = [
    { time: '00:00', cpu: 25 },
    { time: '04:00', cpu: 30 },
    { time: '08:00', cpu: 45 },
    { time: '12:00', cpu: 60 },
    { time: '16:00', cpu: 55 },
    { time: '20:00', cpu: 40 },
    { time: '24:00', cpu: 35 },
  ];

  const threatData = [
    { name: 'Ransomware', value: 65, color: '#ef4444' },
    { name: 'Malware', value: 20, color: '#f59e0b' },
    { name: 'Spyware', value: 10, color: '#10b981' },
    { name: 'Autres', value: 5, color: '#6b7280' },
  ];

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 5000); // Rafraîchir toutes les 5 secondes
    return () => clearInterval(interval);
  }, []);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      
      // Récupérer le statut système
      const statusResponse = await axios.get('/api/status');
      setSystemStatus(statusResponse.data);
      
      // Récupérer les menaces
      const threatsResponse = await axios.get('/api/threats');
      setThreats(threatsResponse.data.threats || []);
      
      setError(null);
    } catch (err) {
      console.error('Erreur lors de la récupération des données:', err);
      setError('Erreur de connexion au serveur');
      
      // Données simulées en cas d'erreur
      setSystemStatus({
        status: 'active',
        threats_detected: 3,
        files_protected: 15420,
        last_scan: new Date().toISOString(),
        cpu_usage: 45.2,
        memory_usage: 67.8
      });
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'high': return 'text-red-600 bg-red-100';
      case 'medium': return 'text-yellow-600 bg-yellow-100';
      case 'low': return 'text-green-600 bg-green-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  if (loading && !systemStatus) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="loading-spinner"></div>
        <span className="ml-3 text-gray-600">Chargement...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* En-tête du tableau de bord */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Tableau de bord</h1>
          <p className="text-gray-600">Vue d'ensemble de la protection système</p>
        </div>
        <div className="flex items-center space-x-2">
          <div className="w-2 h-2 bg-green-500 rounded-full"></div>
          <span className="text-sm text-gray-600">Système protégé</span>
        </div>
      </div>

      {/* Cartes de métriques principales */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="card card-hover">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <div className="w-8 h-8 bg-blue-100 rounded-lg flex items-center justify-center">
                <Shield className="w-5 h-5 text-blue-600" />
              </div>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Menaces détectées</p>
              <p className="text-2xl font-bold text-gray-900">
                {systemStatus?.threats_detected || 0}
              </p>
            </div>
          </div>
        </div>

        <div className="card card-hover">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <div className="w-8 h-8 bg-green-100 rounded-lg flex items-center justify-center">
                <CheckCircle className="w-5 h-5 text-green-600" />
              </div>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Fichiers protégés</p>
              <p className="text-2xl font-bold text-gray-900">
                {systemStatus?.files_protected?.toLocaleString() || '0'}
              </p>
            </div>
          </div>
        </div>

        <div className="card card-hover">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <div className="w-8 h-8 bg-yellow-100 rounded-lg flex items-center justify-center">
                <Cpu className="w-5 h-5 text-yellow-600" />
              </div>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Utilisation CPU</p>
              <p className="text-2xl font-bold text-gray-900">
                {systemStatus?.cpu_usage?.toFixed(1) || '0'}%
              </p>
            </div>
          </div>
        </div>

        <div className="card card-hover">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <div className="w-8 h-8 bg-purple-100 rounded-lg flex items-center justify-center">
                <HardDrive className="w-5 h-5 text-purple-600" />
              </div>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Mémoire utilisée</p>
              <p className="text-2xl font-bold text-gray-900">
                {systemStatus?.memory_usage?.toFixed(1) || '0'}%
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Graphiques et alertes */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Graphique CPU */}
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Utilisation CPU</h3>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={cpuData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" />
              <YAxis />
              <Tooltip />
              <Line type="monotone" dataKey="cpu" stroke="#3b82f6" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Répartition des menaces */}
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Types de menaces</h3>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie
                data={threatData}
                cx="50%"
                cy="50%"
                outerRadius={60}
                dataKey="value"
                label={({ name, value }) => `${name}: ${value}%`}
              >
                {threatData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Alertes récentes */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-900">Alertes récentes</h3>
          <button className="text-sm text-blue-600 hover:text-blue-700">
            Voir toutes
          </button>
        </div>
        
        {threats.length > 0 ? (
          <div className="space-y-3">
            {threats.slice(0, 5).map((threat) => (
              <div key={threat.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                <div className="flex items-center space-x-3">
                  <AlertTriangle className="w-5 h-5 text-red-500" />
                  <div>
                    <p className="text-sm font-medium text-gray-900">{threat.description}</p>
                    <p className="text-xs text-gray-500">
                      {new Date(threat.timestamp).toLocaleString('fr-FR')}
                    </p>
                  </div>
                </div>
                <span className={`px-2 py-1 text-xs font-medium rounded-full ${getSeverityColor(threat.severity)}`}>
                  {threat.severity}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <div className="empty-state">
            <CheckCircle className="empty-state-icon" />
            <h3 className="empty-state-title">Aucune menace détectée</h3>
            <p className="empty-state-description">Votre système est actuellement protégé</p>
          </div>
        )}
      </div>

      {/* Statut des services */}
      <div className="card">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Statut des services</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="flex items-center space-x-3">
            <div className="w-3 h-3 bg-green-500 rounded-full"></div>
            <span className="text-sm text-gray-700">Détecteur IA</span>
          </div>
          <div className="flex items-center space-x-3">
            <div className="w-3 h-3 bg-green-500 rounded-full"></div>
            <span className="text-sm text-gray-700">Monitoring système</span>
          </div>
          <div className="flex items-center space-x-3">
            <div className="w-3 h-3 bg-green-500 rounded-full"></div>
            <span className="text-sm text-gray-700">Protection en temps réel</span>
          </div>
        </div>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <div className="flex">
            <AlertTriangle className="w-5 h-5 text-red-400" />
            <div className="ml-3">
              <p className="text-sm text-red-800">{error}</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Dashboard; 
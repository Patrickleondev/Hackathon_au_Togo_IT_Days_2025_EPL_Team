import React, { useState, useEffect } from 'react';
import { Shield, Play, AlertTriangle, CheckCircle, Clock, FileText, Folder, Zap, Target, Settings, BarChart3, Activity } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';
import axios from 'axios';

interface ScanStatus {
  is_scanning: boolean;
  progress: number;
  threats_detected: number;
  files_scanned: number;
  total_files: number;
  current_path: string;
  scan_type: string;
  start_time: string;
  estimated_completion: string;
}

interface ScanResult {
  id: string;
  scan_type: string;
  start_time: string;
  end_time: string;
  duration: number;
  files_scanned: number;
  threats_detected: number;
  status: 'completed' | 'failed' | 'cancelled';
  details: {
    suspicious_files: number;
    quarantined_files: number;
    cleaned_files: number;
  };
}

const Scan: React.FC = () => {
  const [scanStatus, setScanStatus] = useState<ScanStatus>({
    is_scanning: false,
    progress: 0,
    threats_detected: 0,
    files_scanned: 0,
    total_files: 0,
    current_path: '',
    scan_type: '',
    start_time: '',
    estimated_completion: ''
  });
  const [scanType, setScanType] = useState<'quick' | 'full' | 'custom'>('quick');
  const [customPaths, setCustomPaths] = useState<string>('');
  const [scanHistory, setScanHistory] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);

  useEffect(() => {
    fetchScanStatus();
    const interval = setInterval(fetchScanStatus, 2000);
    return () => clearInterval(interval);
  }, []);

  const fetchScanStatus = async () => {
    try {
      const response = await axios.get('/api/scan/status');
      setScanStatus(response.data);
    } catch (err) {
      console.error('Erreur lors de la récupération du statut du scan:', err);
    }
  };

  const startScan = async () => {
    try {
      setLoading(true);
      setError(null);

      const scanRequest = {
        scan_type: scanType,
        target_paths: scanType === 'custom' ? customPaths.split('\n').filter(path => path.trim()) : []
      };

      await axios.post('/api/scan', scanRequest);
      
      // Ajouter à l'historique
      const newScan: ScanResult = {
        id: Date.now().toString(),
        scan_type: scanType,
        start_time: new Date().toISOString(),
        end_time: '',
        duration: 0,
        files_scanned: 0,
        threats_detected: 0,
        status: 'completed',
        details: {
          suspicious_files: 0,
          quarantined_files: 0,
          cleaned_files: 0
        }
      };
      setScanHistory(prev => [newScan, ...prev.slice(0, 9)]);

    } catch (err) {
      console.error('Erreur lors du démarrage du scan:', err);
      setError('Erreur lors du démarrage du scan');
    } finally {
      setLoading(false);
    }
  };

  const stopScan = async () => {
    try {
      await axios.post('/api/scan/stop');
    } catch (err) {
      console.error('Erreur lors de l\'arrêt du scan:', err);
    }
  };

  const getScanTypeInfo = (type: string) => {
    switch (type) {
      case 'quick':
        return {
          icon: <Clock className="w-6 h-6" />,
          title: 'Scan Rapide',
          description: 'Analyse des dossiers critiques (Documents, Desktop, Downloads)',
          duration: '2-5 minutes',
          coverage: 'Dossiers essentiels'
        };
      case 'full':
        return {
          icon: <Shield className="w-6 h-6" />,
          title: 'Scan Complet',
          description: 'Analyse complète de tout le système',
          duration: '30-60 minutes',
          coverage: 'Système entier'
        };
      case 'custom':
        return {
          icon: <Target className="w-6 h-6" />,
          title: 'Scan Personnalisé',
          description: 'Analyse des chemins spécifiés',
          duration: 'Variable',
          coverage: 'Chemins sélectionnés'
        };
      default:
        return {
          icon: <FileText className="w-6 h-6" />,
          title: 'Scan Standard',
          description: 'Analyse de base du système',
          duration: '5-10 minutes',
          coverage: 'Fichiers système'
        };
    }
  };

  const getProgressColor = (progress: number) => {
    if (progress < 30) return 'bg-blue-600';
    if (progress < 70) return 'bg-yellow-600';
    return 'bg-green-600';
  };

  const formatDuration = (seconds: number) => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    
    if (hours > 0) return `${hours}h ${minutes}m`;
    if (minutes > 0) return `${minutes}m ${secs}s`;
    return `${secs}s`;
  };

  return (
    <div className="space-y-6">
      {/* En-tête */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Scanner le système</h1>
        <p className="text-gray-600">Protection proactive contre les menaces</p>
      </div>

      {/* Statut du scan en cours */}
      {scanStatus.is_scanning && (
        <div className="card bg-gradient-to-r from-blue-50 to-purple-50 border-blue-200">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-3">
              <Activity className="w-6 h-6 text-blue-600 animate-pulse" />
              <div>
                <h3 className="text-lg font-semibold text-gray-900">Scan en cours</h3>
                <p className="text-sm text-gray-600">{scanStatus.current_path}</p>
              </div>
            </div>
            <button
              onClick={stopScan}
              className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors"
            >
              Arrêter
            </button>
          </div>

          {/* Barre de progression */}
          <div className="mb-4">
            <div className="flex justify-between text-sm text-gray-600 mb-2">
              <span>Progression</span>
              <span>{scanStatus.progress.toFixed(1)}%</span>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-3">
              <div
                className={`h-3 rounded-full transition-all duration-300 ${getProgressColor(scanStatus.progress)}`}
                style={{ width: `${scanStatus.progress}%` }}
              ></div>
            </div>
          </div>

          {/* Statistiques en temps réel */}
          <div className="grid grid-cols-3 gap-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-600">{scanStatus.files_scanned}</div>
              <div className="text-xs text-gray-600">Fichiers scannés</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-red-600">{scanStatus.threats_detected}</div>
              <div className="text-xs text-gray-600">Menaces détectées</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-green-600">
                {scanStatus.total_files > 0 ? Math.round((scanStatus.files_scanned / scanStatus.total_files) * 100) : 0}%
              </div>
              <div className="text-xs text-gray-600">Complété</div>
            </div>
          </div>
        </div>
      )}

      {/* Types de scan */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {(['quick', 'full', 'custom'] as const).map((type) => {
          const info = getScanTypeInfo(type);
          return (
            <div
              key={type}
              className={`card cursor-pointer transition-all duration-200 ${
                scanType === type 
                  ? 'ring-2 ring-blue-500 bg-blue-50' 
                  : 'hover:shadow-md hover:border-gray-300'
              }`}
              onClick={() => setScanType(type)}
            >
              <div className="flex items-center space-x-3 mb-3">
                <div className={`p-2 rounded-lg ${scanType === type ? 'bg-blue-100' : 'bg-gray-100'}`}>
                  {info.icon}
                </div>
                <div>
                  <h3 className="font-semibold text-gray-900">{info.title}</h3>
                  <p className="text-xs text-gray-500">{info.duration}</p>
                </div>
              </div>
              <p className="text-sm text-gray-600 mb-3">{info.description}</p>
              <div className="flex items-center justify-between text-xs text-gray-500">
                <span>{info.coverage}</span>
                {scanType === type && (
                  <CheckCircle className="w-4 h-4 text-blue-600" />
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Configuration personnalisée */}
      {scanType === 'custom' && (
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Chemins personnalisés</h3>
          <div className="space-y-4">
            <div>
              <label className="form-label">Chemins à scanner (un par ligne)</label>
              <textarea
                value={customPaths}
                onChange={(e) => setCustomPaths(e.target.value)}
                className="form-input h-32"
                placeholder="/chemin/vers/dossier1&#10;/chemin/vers/dossier2&#10;C:\Users\Documents"
              />
            </div>
            <p className="text-xs text-gray-500">
              Entrez les chemins absolus des dossiers ou fichiers à scanner
            </p>
          </div>
        </div>
      )}

      {/* Options avancées */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-900">Options avancées</h3>
          <button
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="flex items-center space-x-2 text-sm text-blue-600 hover:text-blue-700"
          >
            <Settings className="w-4 h-4" />
            <span>{showAdvanced ? 'Masquer' : 'Afficher'}</span>
          </button>
        </div>
        
        {showAdvanced && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="form-label">Profondeur de scan</label>
              <select className="form-input">
                <option value="shallow">Surface (rapide)</option>
                <option value="normal">Normal</option>
                <option value="deep">Profond (complet)</option>
              </select>
            </div>
            <div>
              <label className="form-label">Types de fichiers</label>
              <select className="form-input">
                <option value="all">Tous les fichiers</option>
                <option value="executable">Exécutables uniquement</option>
                <option value="documents">Documents</option>
                <option value="archives">Archives</option>
              </select>
            </div>
          </div>
        )}
      </div>

      {/* Bouton de démarrage */}
      <div className="flex items-center justify-center">
        <button
          onClick={startScan}
          disabled={loading || scanStatus.is_scanning}
          className="flex items-center space-x-3 px-8 py-4 bg-gradient-to-r from-blue-600 to-purple-600 text-white rounded-xl hover:from-blue-700 hover:to-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 shadow-lg"
        >
          <Zap className="w-6 h-6" />
          <span className="text-lg font-semibold">
            {loading ? 'Démarrage...' : scanStatus.is_scanning ? 'Scan en cours...' : 'Démarrer le scan'}
          </span>
        </button>
      </div>

      {/* Historique des scans */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-900">Historique des scans</h3>
          <BarChart3 className="w-5 h-5 text-gray-400" />
        </div>
        
        {scanHistory.length > 0 ? (
          <div className="space-y-3">
            {scanHistory.map((scan) => (
              <div key={scan.id} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                <div className="flex items-center space-x-3">
                  <div className={`p-2 rounded-lg ${
                    scan.status === 'completed' ? 'bg-green-100' : 
                    scan.status === 'failed' ? 'bg-red-100' : 'bg-yellow-100'
                  }`}>
                    {scan.status === 'completed' ? (
                      <CheckCircle className="w-5 h-5 text-green-600" />
                    ) : scan.status === 'failed' ? (
                      <AlertTriangle className="w-5 h-5 text-red-600" />
                    ) : (
                      <Clock className="w-5 h-5 text-yellow-600" />
                    )}
                  </div>
                  <div>
                    <p className="text-sm font-medium text-gray-900">
                      {getScanTypeInfo(scan.scan_type).title}
                    </p>
                    <p className="text-xs text-gray-500">
                      {new Date(scan.start_time).toLocaleString('fr-FR')}
                    </p>
                  </div>
                </div>
                <div className="text-right">
                  <div className="flex items-center space-x-4 text-sm">
                    <div>
                      <span className="font-medium">{scan.files_scanned}</span>
                      <span className="text-gray-500"> fichiers</span>
                    </div>
                    <div>
                      <span className="font-medium text-red-600">{scan.threats_detected}</span>
                      <span className="text-gray-500"> menaces</span>
                    </div>
                    <div>
                      <span className="font-medium">{formatDuration(scan.duration)}</span>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-8">
            <FileText className="w-12 h-12 text-gray-400 mx-auto mb-3" />
            <h3 className="text-lg font-medium text-gray-900">Aucun scan effectué</h3>
            <p className="text-gray-500">Lancez votre premier scan pour commencer</p>
          </div>
        )}
      </div>

      {/* Conseils de sécurité */}
      <div className="card">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Conseils de sécurité</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="flex items-start space-x-3">
            <CheckCircle className="w-5 h-5 text-green-500 mt-0.5" />
            <div>
              <p className="text-sm font-medium text-gray-900">Scans réguliers</p>
              <p className="text-xs text-gray-600">Effectuez des scans quotidiens pour maintenir la sécurité</p>
            </div>
          </div>
          <div className="flex items-start space-x-3">
            <CheckCircle className="w-5 h-5 text-green-500 mt-0.5" />
            <div>
              <p className="text-sm font-medium text-gray-900">Surveillance continue</p>
              <p className="text-xs text-gray-600">Le monitoring en temps réel détecte les menaces automatiquement</p>
            </div>
          </div>
          <div className="flex items-start space-x-3">
            <CheckCircle className="w-5 h-5 text-green-500 mt-0.5" />
            <div>
              <p className="text-sm font-medium text-gray-900">Mises à jour</p>
              <p className="text-xs text-gray-600">Gardez votre système à jour pour une protection optimale</p>
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
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Scan; 
import React, { useState, useEffect } from 'react';
import { Shield, Play, Pause, AlertTriangle, CheckCircle, Clock, FileText, Folder } from 'lucide-react';
import axios from 'axios';

interface ScanStatus {
  is_scanning: boolean;
  progress: number;
  threats_detected: number;
}

interface ScanRequest {
  scan_type: 'quick' | 'full' | 'custom';
  target_paths: string[];
}

const Scan: React.FC = () => {
  const [scanStatus, setScanStatus] = useState<ScanStatus>({
    is_scanning: false,
    progress: 0,
    threats_detected: 0
  });
  const [scanType, setScanType] = useState<'quick' | 'full' | 'custom'>('quick');
  const [customPaths, setCustomPaths] = useState<string>('');
  const [scanHistory, setScanHistory] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchScanStatus();
    const interval = setInterval(fetchScanStatus, 2000); // Rafraîchir toutes les 2 secondes
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

      const scanRequest: ScanRequest = {
        scan_type: scanType,
        target_paths: scanType === 'custom' ? customPaths.split('\n').filter(path => path.trim()) : []
      };

      await axios.post('/api/scan', scanRequest);
      
      // Ajouter à l'historique
      const newScan = {
        id: Date.now(),
        type: scanType,
        startTime: new Date().toISOString(),
        status: 'running'
      };
      setScanHistory(prev => [newScan, ...prev.slice(0, 9)]); // Garder les 10 derniers

    } catch (err) {
      console.error('Erreur lors du démarrage du scan:', err);
      setError('Erreur lors du démarrage du scan');
    } finally {
      setLoading(false);
    }
  };

  const getScanTypeDescription = (type: string) => {
    switch (type) {
      case 'quick':
        return 'Scan rapide des dossiers critiques (Documents, Desktop, Downloads)';
      case 'full':
        return 'Scan complet de tout le système (peut prendre plusieurs heures)';
      case 'custom':
        return 'Scan personnalisé des chemins spécifiés';
      default:
        return '';
    }
  };

  const getScanTypeIcon = (type: string) => {
    switch (type) {
      case 'quick':
        return <Clock className="w-5 h-5" />;
      case 'full':
        return <Shield className="w-5 h-5" />;
      case 'custom':
        return <Folder className="w-5 h-5" />;
      default:
        return <FileText className="w-5 h-5" />;
    }
  };

  const getProgressColor = (progress: number) => {
    if (progress < 30) return 'bg-blue-600';
    if (progress < 70) return 'bg-yellow-600';
    return 'bg-green-600';
  };

  return (
    <div className="space-y-6">
      {/* En-tête */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Scanner le système</h1>
        <p className="text-gray-600">Lancez un scan pour détecter les menaces potentielles</p>
      </div>

      {/* Statut du scan en cours */}
      {scanStatus.is_scanning && (
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-3">
              <div className="w-8 h-8 bg-blue-100 rounded-lg flex items-center justify-center">
                <Shield className="w-5 h-5 text-blue-600" />
              </div>
              <div>
                <h3 className="text-lg font-semibold text-gray-900">Scan en cours</h3>
                <p className="text-sm text-gray-600">Analyse du système en cours...</p>
              </div>
            </div>
            <div className="flex items-center space-x-2">
              <div className="w-2 h-2 bg-blue-500 rounded-full animate-pulse"></div>
              <span className="text-sm text-blue-600">En cours</span>
            </div>
          </div>

          {/* Barre de progression */}
          <div className="mb-4">
            <div className="flex justify-between text-sm text-gray-600 mb-2">
              <span>Progression</span>
              <span>{scanStatus.progress.toFixed(1)}%</span>
            </div>
            <div className="progress-bar">
              <div 
                className={`progress-fill ${getProgressColor(scanStatus.progress)}`}
                style={{ width: `${scanStatus.progress}%` }}
              ></div>
            </div>
          </div>

          {/* Statistiques du scan */}
          <div className="grid grid-cols-2 gap-4">
            <div className="text-center">
              <p className="text-2xl font-bold text-gray-900">{scanStatus.threats_detected}</p>
              <p className="text-sm text-gray-600">Menaces détectées</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-gray-900">
                {scanStatus.progress > 0 ? Math.floor(100 / scanStatus.progress * 100) : 0}
              </p>
              <p className="text-sm text-gray-600">Fichiers analysés</p>
            </div>
          </div>
        </div>
      )}

      {/* Configuration du scan */}
      <div className="card">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Configuration du scan</h3>
        
        {/* Types de scan */}
        <div className="space-y-4 mb-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[
              { type: 'quick', label: 'Scan rapide', description: '~5 minutes' },
              { type: 'full', label: 'Scan complet', description: '~2 heures' },
              { type: 'custom', label: 'Scan personnalisé', description: 'Variable' }
            ].map((option) => (
              <div
                key={option.type}
                className={`p-4 border-2 rounded-lg cursor-pointer transition-colors ${
                  scanType === option.type
                    ? 'border-blue-500 bg-blue-50'
                    : 'border-gray-200 hover:border-gray-300'
                }`}
                onClick={() => setScanType(option.type as any)}
              >
                <div className="flex items-center space-x-3">
                  {getScanTypeIcon(option.type)}
                  <div>
                    <h4 className="font-medium text-gray-900">{option.label}</h4>
                    <p className="text-sm text-gray-500">{option.description}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Description du type de scan */}
        <div className="mb-6">
          <p className="text-sm text-gray-600 bg-gray-50 p-3 rounded-lg">
            {getScanTypeDescription(scanType)}
          </p>
        </div>

        {/* Chemins personnalisés */}
        {scanType === 'custom' && (
          <div className="mb-6">
            <label className="form-label">Chemins à scanner (un par ligne)</label>
            <textarea
              className="form-input h-32"
              placeholder="/chemin/vers/dossier1&#10;/chemin/vers/dossier2&#10;/chemin/vers/fichier.txt"
              value={customPaths}
              onChange={(e) => setCustomPaths(e.target.value)}
            />
            <p className="text-xs text-gray-500 mt-1">
              Entrez les chemins absolus des dossiers ou fichiers à scanner
            </p>
          </div>
        )}

        {/* Bouton de démarrage */}
        <div className="flex items-center space-x-4">
          <button
            onClick={startScan}
            disabled={loading || scanStatus.is_scanning}
            className={`btn-primary flex items-center space-x-2 ${
              (loading || scanStatus.is_scanning) ? 'opacity-50 cursor-not-allowed' : ''
            }`}
          >
            {loading ? (
              <div className="loading-spinner w-4 h-4"></div>
            ) : (
              <Play className="w-4 h-4" />
            )}
            <span>
              {scanStatus.is_scanning ? 'Scan en cours...' : 'Démarrer le scan'}
            </span>
          </button>

          {scanStatus.is_scanning && (
            <div className="flex items-center space-x-2 text-sm text-gray-600">
              <Clock className="w-4 h-4" />
              <span>Temps estimé: {scanType === 'quick' ? '5 min' : scanType === 'full' ? '2h' : 'Variable'}</span>
            </div>
          )}
        </div>
      </div>

      {/* Historique des scans */}
      <div className="card">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Historique des scans</h3>
        
        {scanHistory.length > 0 ? (
          <div className="space-y-3">
            {scanHistory.map((scan) => (
              <div key={scan.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                <div className="flex items-center space-x-3">
                  {scan.status === 'completed' ? (
                    <CheckCircle className="w-5 h-5 text-green-500" />
                  ) : scan.status === 'running' ? (
                    <div className="w-5 h-5 border-2 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
                  ) : (
                    <AlertTriangle className="w-5 h-5 text-yellow-500" />
                  )}
                  <div>
                    <p className="text-sm font-medium text-gray-900">
                      Scan {scan.type} - {new Date(scan.startTime).toLocaleString('fr-FR')}
                    </p>
                    <p className="text-xs text-gray-500">
                      {scan.status === 'completed' ? 'Terminé' : 
                       scan.status === 'running' ? 'En cours' : 'Erreur'}
                    </p>
                  </div>
                </div>
                <span className={`badge ${
                  scan.status === 'completed' ? 'badge-green' :
                  scan.status === 'running' ? 'badge-blue' : 'badge-yellow'
                }`}>
                  {scan.status}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <div className="empty-state">
            <FileText className="empty-state-icon" />
            <h3 className="empty-state-title">Aucun scan effectué</h3>
            <p className="empty-state-description">Lancez votre premier scan pour commencer</p>
          </div>
        )}
      </div>

      {/* Conseils de sécurité */}
      <div className="card">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Conseils de sécurité</h3>
        <div className="space-y-3">
          <div className="flex items-start space-x-3">
            <CheckCircle className="w-5 h-5 text-green-500 mt-0.5" />
            <div>
              <p className="text-sm font-medium text-gray-900">Effectuez des scans réguliers</p>
              <p className="text-xs text-gray-600">Un scan rapide quotidien est recommandé</p>
            </div>
          </div>
          <div className="flex items-start space-x-3">
            <CheckCircle className="w-5 h-5 text-green-500 mt-0.5" />
            <div>
              <p className="text-sm font-medium text-gray-900">Surveillez les activités suspectes</p>
              <p className="text-xs text-gray-600">Le monitoring en temps réel détecte les menaces automatiquement</p>
            </div>
          </div>
          <div className="flex items-start space-x-3">
            <CheckCircle className="w-5 h-5 text-green-500 mt-0.5" />
            <div>
              <p className="text-sm font-medium text-gray-900">Gardez votre système à jour</p>
              <p className="text-xs text-gray-600">Les mises à jour de sécurité sont essentielles</p>
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
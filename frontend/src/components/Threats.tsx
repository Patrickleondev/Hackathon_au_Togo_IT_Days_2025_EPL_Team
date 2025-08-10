import React, { useState, useEffect } from 'react';
import { AlertTriangle, Shield, Eye, Download, Clock } from 'lucide-react';
import axios from 'axios';

interface Threat {
  id: string;
  threat_type: string;
  severity: string;
  description: string;
  timestamp: string;
  file_path?: string;
  process_name?: string;
  confidence?: number;
  quarantined?: boolean;
}

const Threats: React.FC = () => {
  const [threats, setThreats] = useState<Threat[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null);
  const [filter, setFilter] = useState<'all' | 'high' | 'medium' | 'low'>('all');

  useEffect(() => {
    fetchThreats();
    const interval = setInterval(fetchThreats, 10000); // Rafraîchir toutes les 10 secondes
    return () => clearInterval(interval);
  }, []);

  const fetchThreats = async () => {
    try {
      const response = await axios.get('/api/threats');
      const raw = response.data.threats || [];
      const normalized: Threat[] = raw.map((t: any) => ({
        id: t.id,
        threat_type: t.threat_type || t.type_translated || t.type || 'unknown',
        severity: t.severity || 'low',
        description: t.description || '',
        timestamp: t.timestamp || new Date().toISOString(),
        file_path: t.file_path,
        process_name: t.process_name,
        confidence: typeof t.confidence === 'number' ? t.confidence : undefined,
        quarantined: Boolean(t.quarantined)
      }));
      setThreats(normalized);
      setError(null);
    } catch (err) {
      console.error('Erreur lors de la récupération des menaces:', err);
      setError('Erreur de connexion au serveur');
      
      // Données simulées en cas d'erreur
      setThreats([
        {
          id: '1',
          threat_type: 'ransomware',
          severity: 'high',
          description: 'Fichier suspect détecté: document_encrypted.exe',
          timestamp: new Date().toISOString(),
          file_path: '/home/user/Documents/document_encrypted.exe',
          confidence: 0.95
        },
        {
          id: '2',
          threat_type: 'malware',
          severity: 'medium',
          description: 'Processus suspect: crypto_miner.exe',
          timestamp: new Date(Date.now() - 3600000).toISOString(),
          process_name: 'crypto_miner.exe',
          confidence: 0.78
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  const quarantineThreat = async (threatId: string) => {
    try {
      await axios.post(`/api/threats/${threatId}/quarantine`);
      
      // Mettre à jour la liste des menaces
      setThreats(prev => prev.map(threat => 
        threat.id === threatId 
          ? { ...threat, quarantined: true }
          : threat
      ));
      
      alert('Menace mise en quarantaine avec succès');
    } catch (err) {
      console.error('Erreur lors de la mise en quarantaine:', err);
      alert('Erreur lors de la mise en quarantaine');
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

  const getThreatTypeIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case 'ransomware': return <AlertTriangle className="w-5 h-5 text-red-500" />;
      case 'malware': return <Shield className="w-5 h-5 text-orange-500" />;
      case 'spyware': return <Eye className="w-5 h-5 text-purple-500" />;
      default: return <AlertTriangle className="w-5 h-5 text-gray-500" />;
    }
  };

  const filteredThreats = threats.filter(threat => {
    if (filter === 'all') return true;
    return threat.severity.toLowerCase() === filter;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="loading-spinner"></div>
        <span className="ml-3 text-gray-600">Chargement des menaces...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* En-tête */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">{require('react-i18next').useTranslation().t('titles.threats')}</h1>
          <p className="text-gray-600">
            {threats.length} menace{threats.length !== 1 ? 's' : ''} détectée{threats.length !== 1 ? 's' : ''}
          </p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <span className="text-sm text-gray-600">Filtrer:</span>
            <select
              value={filter}
              onChange={(e) => setFilter(e.target.value as any)}
              className="form-input text-sm"
            >
              <option value="all">Toutes</option>
              <option value="high">Élevées</option>
              <option value="medium">Moyennes</option>
              <option value="low">Faibles</option>
            </select>
          </div>
        </div>
      </div>

      {/* Statistiques des menaces */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="card">
          <div className="text-center">
            <p className="text-2xl font-bold text-red-600">
              {threats.filter(t => t.severity === 'high').length}
            </p>
            <p className="text-sm text-gray-600">Menaces élevées</p>
          </div>
        </div>
        <div className="card">
          <div className="text-center">
            <p className="text-2xl font-bold text-yellow-600">
              {threats.filter(t => t.severity === 'medium').length}
            </p>
            <p className="text-sm text-gray-600">Menaces moyennes</p>
          </div>
        </div>
        <div className="card">
          <div className="text-center">
            <p className="text-2xl font-bold text-green-600">
              {threats.filter(t => t.severity === 'low').length}
            </p>
            <p className="text-sm text-gray-600">Menaces faibles</p>
          </div>
        </div>
        <div className="card">
          <div className="text-center">
            <p className="text-2xl font-bold text-blue-600">
              {threats.filter(t => t.quarantined).length}
            </p>
            <p className="text-sm text-gray-600">En quarantaine</p>
          </div>
        </div>
      </div>

      {/* Liste des menaces */}
      <div className="card">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Détails des menaces</h3>
        
        {filteredThreats.length > 0 ? (
          <div className="space-y-4">
            {filteredThreats.map((threat) => (
              <div key={threat.id} className="border border-gray-200 rounded-lg p-4">
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-3">
                    {getThreatTypeIcon(threat.threat_type)}
                    <div className="flex-1">
                      <div className="flex items-center space-x-2 mb-2">
                        <h4 className="font-medium text-gray-900">{threat.description}</h4>
                        <span className={`badge ${getSeverityColor(threat.severity)}`}>
                          {threat.severity}
                        </span>
                        {threat.confidence && (
                          <span className="text-xs text-gray-500">
                            Confiance: {(threat.confidence * 100).toFixed(0)}%
                          </span>
                        )}
                      </div>
                      
                      <div className="text-sm text-gray-600 space-y-1">
                        <p>
                          <span className="font-medium">Type:</span> {threat.threat_type}
                        </p>
                        {threat.file_path && (
                          <p>
                            <span className="font-medium">Fichier:</span> {threat.file_path}
                          </p>
                        )}
                        {threat.process_name && (
                          <p>
                            <span className="font-medium">Processus:</span> {threat.process_name}
                          </p>
                        )}
                        <p>
                          <span className="font-medium">Détecté:</span>{' '}
                          {new Date(threat.timestamp).toLocaleString('fr-FR')}
                        </p>
                      </div>
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => setSelectedThreat(threat)}
                      className="btn-secondary text-sm"
                    >
                      <Eye className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => quarantineThreat(threat.id)}
                      disabled={threat.quarantined}
                      className={`btn-danger text-sm ${
                        threat.quarantined ? 'opacity-50 cursor-not-allowed' : ''
                      }`}
                    >
                      <Shield className="w-4 h-4" />
                    </button>
                  </div>
                </div>
                
                {threat.quarantined && (
                  <div className="mt-3 p-2 bg-green-50 border border-green-200 rounded">
                    <p className="text-sm text-green-800">
                      ✓ Cette menace a été mise en quarantaine
                    </p>
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="empty-state">
            <AlertTriangle className="empty-state-icon" />
            <h3 className="empty-state-title">Aucune menace trouvée</h3>
            <p className="empty-state-description">
              {filter === 'all' 
                ? 'Aucune menace n\'a été détectée sur votre système'
                : `Aucune menace de niveau "${filter}" n'a été détectée`
              }
            </p>
          </div>
        )}
      </div>

      {/* Actions recommandées */}
      {threats.length > 0 && (
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Actions recommandées</h3>
          <div className="space-y-3">
            <div className="flex items-start space-x-3">
              <Shield className="w-5 h-5 text-blue-500 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-gray-900">Mettre en quarantaine les menaces</p>
                <p className="text-xs text-gray-600">
                  Isolez les fichiers suspects pour éviter la propagation
                </p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <Download className="w-5 h-5 text-green-500 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-gray-900">Sauvegarder vos données</p>
                <p className="text-xs text-gray-600">
                  Créez une sauvegarde de vos fichiers importants
                </p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <Clock className="w-5 h-5 text-yellow-500 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-gray-900">Scanner régulièrement</p>
                <p className="text-xs text-gray-600">
                  Effectuez des scans quotidiens pour maintenir la sécurité
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Modal de détails */}
      {selectedThreat && (
        <div className="modal-overlay" onClick={() => setSelectedThreat(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-gray-900">Détails de la menace</h3>
              <button
                onClick={() => setSelectedThreat(null)}
                className="text-gray-400 hover:text-gray-600"
              >
                ×
              </button>
            </div>
            
            <div className="space-y-4">
              <div>
                <h4 className="font-medium text-gray-900 mb-2">Description</h4>
                <p className="text-sm text-gray-600">{selectedThreat.description}</p>
              </div>
              
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <h4 className="font-medium text-gray-900 mb-1">Type</h4>
                  <p className="text-sm text-gray-600">{selectedThreat.threat_type}</p>
                </div>
                <div>
                  <h4 className="font-medium text-gray-900 mb-1">Sévérité</h4>
                  <span className={`badge ${getSeverityColor(selectedThreat.severity)}`}>
                    {selectedThreat.severity}
                  </span>
                </div>
                {selectedThreat.file_path && (
                  <div className="col-span-2">
                    <h4 className="font-medium text-gray-900 mb-1">Fichier</h4>
                    <p className="text-sm text-gray-600 break-all">{selectedThreat.file_path}</p>
                  </div>
                )}
                {selectedThreat.process_name && (
                  <div className="col-span-2">
                    <h4 className="font-medium text-gray-900 mb-1">Processus</h4>
                    <p className="text-sm text-gray-600">{selectedThreat.process_name}</p>
                  </div>
                )}
                <div className="col-span-2">
                  <h4 className="font-medium text-gray-900 mb-1">Détecté le</h4>
                  <p className="text-sm text-gray-600">
                    {new Date(selectedThreat.timestamp).toLocaleString('fr-FR')}
                  </p>
                </div>
              </div>
              
              <div className="flex justify-end space-x-3 pt-4 border-t">
                <button
                  onClick={() => setSelectedThreat(null)}
                  className="btn-secondary"
                >
                  Fermer
                </button>
                <button
                  onClick={() => {
                    quarantineThreat(selectedThreat.id);
                    setSelectedThreat(null);
                  }}
                  className="btn-danger"
                >
                  Mettre en quarantaine
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

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

export default Threats; 
import React, { useState, useEffect } from 'react';
import { 
  Shield, AlertTriangle, CheckCircle, FileText, Folder, 
  Cpu, HardDrive, Activity, Eye, Search, Filter, 
  Download, Trash2, RefreshCw, Info, Clock, User,
  Globe, Wifi, Database, Settings, Zap, X
} from 'lucide-react';
import axios from 'axios';

interface DetailedViewProps {
  isOpen: boolean;
  onClose: () => void;
  viewType: 'scan' | 'threat' | 'folder' | 'process' | 'network' | 'system';
  itemId?: string;
  itemData?: any;
}

interface ScanDetail {
  scan_id: string;
  status: string;
  progress: number;
  files_scanned: number;
  threats_found: number;
  start_time: string;
  end_time?: string;
  scan_type: string;
  target_paths: string[];
  threats: ThreatDetail[];
  scan_logs: string[];
  performance_metrics: {
    duration: number;
    files_per_second: number;
    memory_usage: number;
    cpu_usage: number;
  };
}

interface ThreatDetail {
  id: string;
  type: string;
  severity: string;
  file_path?: string;
  process_name?: string;
  confidence: number;
  description: string;
  timestamp: string;
  detection_method: string;
  evasion_techniques: string[];
  ioc_indicators: string[];
  threat_intelligence: {
    category: string;
    family: string;
    risk_score: number;
    related_threats: string[];
  };
  remediation_steps: string[];
  status: 'active' | 'quarantined' | 'resolved';
}

interface FolderDetail {
  path: string;
  status: 'monitored' | 'alert' | 'clean';
  files_count: number;
  suspicious_files: number;
  last_scan: string;
  permissions: string;
  size: number;
  subfolders: string[];
  recent_activity: {
    timestamp: string;
    action: string;
    details: string;
  }[];
  threats_detected: ThreatDetail[];
}

interface ProcessDetail {
  pid: number;
  name: string;
  command_line: string;
  parent_pid: number;
  start_time: string;
  cpu_usage: number;
  memory_usage: number;
  status: string;
  suspicious_score: number;
  network_connections: any[];
  loaded_modules: string[];
  behavior_analysis: {
    file_operations: string[];
    registry_access: string[];
    network_activity: string[];
    suspicious_patterns: string[];
  };
}

interface NetworkDetail {
  connection_id: string;
  local_address: string;
  remote_address: string;
  local_port: number;
  remote_port: number;
  protocol: string;
  process_name: string;
  status: string;
  risk_score: number;
  threat_intelligence: {
    ip_reputation: string;
    geolocation: string;
    asn: string;
    known_malicious: boolean;
  };
  traffic_analysis: {
    bytes_sent: number;
    bytes_received: number;
    packets_sent: number;
    packets_received: number;
    connection_duration: number;
  };
}

const DetailedView: React.FC<DetailedViewProps> = ({ 
  isOpen, onClose, viewType, itemId, itemData 
}) => {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    if (isOpen && itemId) {
      fetchDetailedData();
    } else if (isOpen && itemData) {
      setData(itemData);
    }
  }, [isOpen, itemId, itemData]);

  const fetchDetailedData = async () => {
    if (!itemId) return;
    
    setLoading(true);
    setError(null);
    
    try {
      let endpoint = '';
      switch (viewType) {
        case 'scan':
          endpoint = `/api/scan/status/${itemId}`;
          break;
        case 'threat':
          endpoint = `/api/threats/${itemId}`;
          break;
        case 'folder':
          endpoint = `/api/monitoring/folder/${itemId}`;
          break;
        case 'process':
          endpoint = `/api/monitoring/process/${itemId}`;
          break;
        case 'network':
          endpoint = `/api/monitoring/network/${itemId}`;
          break;
        case 'system':
          endpoint = `/api/system/info`;
          break;
      }
      
      const response = await axios.get(endpoint);
      setData(response.data);
    } catch (err: any) {
      console.error('Erreur lors de la récupération des détails:', err);
      setError(err.response?.data?.detail || 'Erreur de connexion');
    } finally {
      setLoading(false);
    }
  };

  const getViewTitle = () => {
    switch (viewType) {
      case 'scan': return 'Détails du Scan';
      case 'threat': return 'Détails de la Menace';
      case 'folder': return 'Détails du Dossier';
      case 'process': return 'Détails du Processus';
      case 'network': return 'Détails de la Connexion';
      case 'system': return 'Informations Système';
      default: return 'Vue Détaillée';
    }
  };

  const getViewIcon = () => {
    switch (viewType) {
      case 'scan': return <Activity className="w-6 h-6" />;
      case 'threat': return <AlertTriangle className="w-6 h-6" />;
      case 'folder': return <Folder className="w-6 h-6" />;
      case 'process': return <Cpu className="w-6 h-6" />;
      case 'network': return <Globe className="w-6 h-6" />;
      case 'system': return <Settings className="w-6 h-6" />;
      default: return <Info className="w-6 h-6" />;
    }
  };

  const renderScanDetails = () => (
    <div className="space-y-6">
      {/* Informations générales */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-blue-50 p-4 rounded-lg">
          <div className="flex items-center space-x-2 mb-2">
            <Clock className="w-5 h-5 text-blue-600" />
            <span className="font-medium text-blue-900">Statut</span>
          </div>
          <p className="text-2xl font-bold text-blue-900">{data?.status}</p>
          <p className="text-sm text-blue-600">Progression: {data?.progress}%</p>
        </div>
        
        <div className="bg-green-50 p-4 rounded-lg">
          <div className="flex items-center space-x-2 mb-2">
            <FileText className="w-5 h-5 text-green-600" />
            <span className="font-medium text-green-900">Fichiers</span>
          </div>
          <p className="text-2xl font-bold text-green-900">{data?.files_scanned}</p>
          <p className="text-sm text-green-600">Scannés</p>
        </div>
        
        <div className="bg-red-50 p-4 rounded-lg">
          <div className="flex items-center space-x-2 mb-2">
            <AlertTriangle className="w-5 h-5 text-red-600" />
            <span className="font-medium text-red-900">Menaces</span>
          </div>
          <p className="text-2xl font-bold text-red-900">{data?.threats_found}</p>
          <p className="text-sm text-red-600">Détectées</p>
        </div>
      </div>

      {/* Chemins cibles */}
      <div className="bg-gray-50 p-4 rounded-lg">
        <h4 className="font-medium text-gray-900 mb-3">Chemins cibles</h4>
        <div className="space-y-2">
          {data?.target_paths?.map((path: string, index: number) => (
            <div key={index} className="flex items-center space-x-2 text-sm">
              <Folder className="w-4 h-4 text-gray-500" />
              <span className="font-mono text-gray-700">{path}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Métriques de performance */}
      {data?.performance_metrics && (
        <div className="bg-gray-50 p-4 rounded-lg">
          <h4 className="font-medium text-gray-900 mb-3">Métriques de performance</h4>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div>
              <p className="text-sm text-gray-600">Durée</p>
              <p className="font-medium">{data.performance_metrics.duration}s</p>
            </div>
            <div>
              <p className="text-sm text-gray-600">Fichiers/s</p>
              <p className="font-medium">{data.performance_metrics.files_per_second}</p>
            </div>
            <div>
              <p className="text-sm text-gray-600">CPU</p>
              <p className="font-medium">{data.performance_metrics.cpu_usage}%</p>
            </div>
            <div>
              <p className="text-sm text-gray-600">Mémoire</p>
              <p className="font-medium">{data.performance_metrics.memory_usage}%</p>
            </div>
          </div>
        </div>
      )}

      {/* Logs du scan */}
      {data?.scan_logs && (
        <div className="bg-gray-50 p-4 rounded-lg">
          <h4 className="font-medium text-gray-900 mb-3">Logs du scan</h4>
          <div className="max-h-40 overflow-y-auto space-y-1">
            {data.scan_logs.map((log: string, index: number) => (
              <div key={index} className="text-sm font-mono text-gray-700 bg-white p-2 rounded">
                {log}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );

  const renderThreatDetails = () => (
    <div className="space-y-6">
      {/* En-tête de la menace */}
      <div className="bg-red-50 p-6 rounded-lg border-l-4 border-red-500">
        <div className="flex items-center space-x-3 mb-4">
          <AlertTriangle className="w-8 h-8 text-red-600" />
          <div>
            <h3 className="text-xl font-bold text-red-900">{data?.description}</h3>
            <p className="text-red-700">Type: {data?.type} • Sévérité: {data?.severity}</p>
          </div>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div>
            <p className="text-sm text-red-600">Confiance</p>
            <p className="font-bold text-red-900">{(data?.confidence * 100).toFixed(1)}%</p>
          </div>
          <div>
            <p className="text-sm text-red-600">Méthode</p>
            <p className="font-medium text-red-900">{data?.detection_method}</p>
          </div>
          <div>
            <p className="text-sm text-red-600">Statut</p>
            <p className="font-medium text-red-900">{data?.status}</p>
          </div>
          <div>
            <p className="text-sm text-red-600">Détecté le</p>
            <p className="font-medium text-red-900">
              {new Date(data?.timestamp).toLocaleString('fr-FR')}
            </p>
          </div>
        </div>
      </div>

      {/* Détails techniques */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Fichier/Processus concerné */}
        <div className="bg-gray-50 p-4 rounded-lg">
          <h4 className="font-medium text-gray-900 mb-3">Élément concerné</h4>
          {data?.file_path && (
            <div className="space-y-2">
              <div className="flex items-center space-x-2">
                <FileText className="w-4 h-4 text-gray-500" />
                <span className="font-mono text-sm">{data.file_path}</span>
              </div>
            </div>
          )}
          {data?.process_name && (
            <div className="space-y-2">
              <div className="flex items-center space-x-2">
                <Cpu className="w-4 h-4 text-gray-500" />
                <span className="font-medium">{data.process_name}</span>
              </div>
            </div>
          )}
        </div>

        {/* Techniques d'évasion */}
        <div className="bg-gray-50 p-4 rounded-lg">
          <h4 className="font-medium text-gray-900 mb-3">Techniques d'évasion</h4>
          <div className="space-y-2">
            {data?.evasion_techniques?.map((tech: string, index: number) => (
              <span key={index} className="inline-block bg-yellow-100 text-yellow-800 text-xs px-2 py-1 rounded mr-2 mb-2">
                {tech}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Threat Intelligence */}
      {data?.threat_intelligence && (
        <div className="bg-blue-50 p-4 rounded-lg">
          <h4 className="font-medium text-blue-900 mb-3">Threat Intelligence</h4>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div>
              <p className="text-sm text-blue-600">Catégorie</p>
              <p className="font-medium text-blue-900">{data.threat_intelligence.category}</p>
            </div>
            <div>
              <p className="text-sm text-blue-600">Famille</p>
              <p className="font-medium text-blue-900">{data.threat_intelligence.family}</p>
            </div>
            <div>
              <p className="text-sm text-blue-600">Score de risque</p>
              <p className="font-medium text-blue-900">{data.threat_intelligence.risk_score}</p>
            </div>
            <div>
              <p className="text-sm text-blue-600">Menaces liées</p>
              <p className="font-medium text-blue-900">{data.threat_intelligence.related_threats?.length || 0}</p>
            </div>
          </div>
        </div>
      )}

      {/* Étapes de remédiation */}
      {data?.remediation_steps && (
        <div className="bg-green-50 p-4 rounded-lg">
          <h4 className="font-medium text-green-900 mb-3">Étapes de remédiation</h4>
          <div className="space-y-2">
            {data.remediation_steps.map((step: string, index: number) => (
              <div key={index} className="flex items-start space-x-2">
                <span className="bg-green-600 text-white text-xs rounded-full w-5 h-5 flex items-center justify-center mt-0.5">
                  {index + 1}
                </span>
                <span className="text-green-800">{step}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );

  const renderFolderDetails = () => (
    <div className="space-y-6">
      {/* En-tête du dossier */}
      <div className="bg-blue-50 p-6 rounded-lg border-l-4 border-blue-500">
        <div className="flex items-center space-x-3 mb-4">
          <Folder className="w-8 h-8 text-blue-600" />
          <div>
            <h3 className="text-xl font-bold text-blue-900">{data?.path}</h3>
            <p className="text-blue-700">Statut: {data?.status} • {data?.files_count} fichiers</p>
          </div>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div>
            <p className="text-sm text-blue-600">Fichiers suspects</p>
            <p className="font-bold text-blue-900">{data?.suspicious_files}</p>
          </div>
          <div>
            <p className="text-sm text-blue-600">Taille</p>
            <p className="font-medium text-blue-900">{(data?.size / 1024 / 1024).toFixed(2)} MB</p>
          </div>
          <div>
            <p className="text-sm text-blue-600">Dernier scan</p>
            <p className="font-medium text-blue-900">
              {new Date(data?.last_scan).toLocaleString('fr-FR')}
            </p>
          </div>
          <div>
            <p className="text-sm text-blue-600">Permissions</p>
            <p className="font-medium text-blue-900">{data?.permissions}</p>
          </div>
        </div>
      </div>

      {/* Sous-dossiers */}
      {data?.subfolders && (
        <div className="bg-gray-50 p-4 rounded-lg">
          <h4 className="font-medium text-gray-900 mb-3">Sous-dossiers</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {data.subfolders.map((subfolder: string, index: number) => (
              <div key={index} className="flex items-center space-x-2 text-sm">
                <Folder className="w-4 h-4 text-gray-500" />
                <span className="font-mono text-gray-700">{subfolder}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Activité récente */}
      {data?.recent_activity && (
        <div className="bg-gray-50 p-4 rounded-lg">
          <h4 className="font-medium text-gray-900 mb-3">Activité récente</h4>
          <div className="space-y-2 max-h-40 overflow-y-auto">
            {data.recent_activity.map((activity: any, index: number) => (
              <div key={index} className="flex items-center justify-between p-2 bg-white rounded">
                <div className="flex items-center space-x-2">
                  <Activity className="w-4 h-4 text-gray-500" />
                  <span className="text-sm font-medium">{activity.action}</span>
                </div>
                <div className="text-right">
                  <p className="text-xs text-gray-500">
                    {new Date(activity.timestamp).toLocaleString('fr-FR')}
                  </p>
                  <p className="text-xs text-gray-600">{activity.details}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Menaces détectées */}
      {data?.threats_detected && data.threats_detected.length > 0 && (
        <div className="bg-red-50 p-4 rounded-lg">
          <h4 className="font-medium text-red-900 mb-3">Menaces détectées</h4>
          <div className="space-y-2">
            {data.threats_detected.map((threat: ThreatDetail, index: number) => (
              <div key={index} className="flex items-center justify-between p-3 bg-white rounded border-l-4 border-red-500">
                <div>
                  <p className="font-medium text-red-900">{threat.description}</p>
                  <p className="text-sm text-red-700">{threat.type} • {threat.severity}</p>
                </div>
                <span className="text-sm text-red-600">
                  {new Date(threat.timestamp).toLocaleString('fr-FR')}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );

  const renderProcessDetails = () => (
    <div className="space-y-6">
      {/* En-tête du processus */}
      <div className="bg-green-50 p-6 rounded-lg border-l-4 border-green-500">
        <div className="flex items-center space-x-3 mb-4">
          <Cpu className="w-8 h-8 text-green-600" />
          <div>
            <h3 className="text-xl font-bold text-green-900">{data?.name}</h3>
            <p className="text-green-700">PID: {data?.pid} • Parent: {data?.parent_pid}</p>
          </div>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div>
            <p className="text-sm text-green-600">Score suspect</p>
            <p className="font-bold text-green-900">{data?.suspicious_score}</p>
          </div>
          <div>
            <p className="text-sm text-green-600">CPU</p>
            <p className="font-medium text-green-900">{data?.cpu_usage}%</p>
          </div>
          <div>
            <p className="text-sm text-green-600">Mémoire</p>
            <p className="font-medium text-green-900">{data?.memory_usage}%</p>
          </div>
          <div>
            <p className="text-sm text-green-600">Statut</p>
            <p className="font-medium text-green-900">{data?.status}</p>
          </div>
        </div>
      </div>

      {/* Ligne de commande */}
      <div className="bg-gray-50 p-4 rounded-lg">
        <h4 className="font-medium text-gray-900 mb-3">Ligne de commande</h4>
        <div className="bg-white p-3 rounded border font-mono text-sm">
          {data?.command_line}
        </div>
      </div>

      {/* Analyse comportementale */}
      {data?.behavior_analysis && (
        <div className="bg-gray-50 p-4 rounded-lg">
          <h4 className="font-medium text-gray-900 mb-3">Analyse comportementale</h4>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div>
              <h5 className="font-medium text-gray-700 mb-2">Opérations sur fichiers</h5>
              <div className="space-y-1">
                {data.behavior_analysis.file_operations?.map((op: string, index: number) => (
                  <div key={index} className="text-sm text-gray-600 bg-white p-2 rounded">
                    {op}
                  </div>
                ))}
              </div>
            </div>
            <div>
              <h5 className="font-medium text-gray-700 mb-2">Accès au registre</h5>
              <div className="space-y-1">
                {data.behavior_analysis.registry_access?.map((access: string, index: number) => (
                  <div key={index} className="text-sm text-gray-600 bg-white p-2 rounded">
                    {access}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Modules chargés */}
      {data?.loaded_modules && (
        <div className="bg-gray-50 p-4 rounded-lg">
          <h4 className="font-medium text-gray-900 mb-3">Modules chargés</h4>
          <div className="max-h-40 overflow-y-auto space-y-1">
            {data.loaded_modules.map((module: string, index: number) => (
              <div key={index} className="text-sm text-gray-600 bg-white p-2 rounded">
                {module}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );

  const renderNetworkDetails = () => (
    <div className="space-y-6">
      {/* En-tête de la connexion */}
      <div className="bg-purple-50 p-6 rounded-lg border-l-4 border-purple-500">
        <div className="flex items-center space-x-3 mb-4">
          <Globe className="w-8 h-8 text-purple-600" />
          <div>
            <h3 className="text-xl font-bold text-purple-900">
              {data?.local_address}:{data?.local_port} → {data?.remote_address}:{data?.remote_port}
            </h3>
            <p className="text-purple-700">{data?.protocol} • {data?.process_name}</p>
          </div>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div>
            <p className="text-sm text-purple-600">Score de risque</p>
            <p className="font-bold text-purple-900">{data?.risk_score}</p>
          </div>
          <div>
            <p className="text-sm text-purple-600">Statut</p>
            <p className="font-medium text-purple-900">{data?.status}</p>
          </div>
          <div>
            <p className="text-sm text-purple-600">Processus</p>
            <p className="font-medium text-purple-900">{data?.process_name}</p>
          </div>
          <div>
            <p className="text-sm text-purple-600">Protocole</p>
            <p className="font-medium text-purple-900">{data?.protocol}</p>
          </div>
        </div>
      </div>

      {/* Threat Intelligence */}
      {data?.threat_intelligence && (
        <div className="bg-red-50 p-4 rounded-lg">
          <h4 className="font-medium text-red-900 mb-3">Threat Intelligence</h4>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div>
              <p className="text-sm text-red-600">Réputation IP</p>
              <p className="font-medium text-red-900">{data.threat_intelligence.ip_reputation}</p>
            </div>
            <div>
              <p className="text-sm text-red-600">Géolocalisation</p>
              <p className="font-medium text-red-900">{data.threat_intelligence.geolocation}</p>
            </div>
            <div>
              <p className="text-sm text-red-600">ASN</p>
              <p className="font-medium text-red-900">{data.threat_intelligence.asn}</p>
            </div>
            <div>
              <p className="text-sm text-red-600">Malveillant connu</p>
              <p className={`font-medium ${data.threat_intelligence.known_malicious ? 'text-red-900' : 'text-green-900'}`}>
                {data.threat_intelligence.known_malicious ? 'Oui' : 'Non'}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Analyse du trafic */}
      {data?.traffic_analysis && (
        <div className="bg-gray-50 p-4 rounded-lg">
          <h4 className="font-medium text-gray-900 mb-3">Analyse du trafic</h4>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
            <div>
              <p className="text-sm text-gray-600">Octets envoyés</p>
              <p className="font-medium">{(data.traffic_analysis.bytes_sent / 1024).toFixed(2)} KB</p>
            </div>
            <div>
              <p className="text-sm text-gray-600">Octets reçus</p>
              <p className="font-medium">{(data.traffic_analysis.bytes_received / 1024).toFixed(2)} KB</p>
            </div>
            <div>
              <p className="text-sm text-gray-600">Durée</p>
              <p className="font-medium">{data.traffic_analysis.connection_duration}s</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );

  const renderSystemDetails = () => (
    <div className="space-y-6">
      {/* Informations générales */}
      <div className="bg-blue-50 p-6 rounded-lg">
        <div className="flex items-center space-x-3 mb-4">
          <Settings className="w-8 h-8 text-blue-600" />
          <h3 className="text-xl font-bold text-blue-900">Informations système</h3>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <p className="text-sm text-blue-600">Système d'exploitation</p>
            <p className="font-medium text-blue-900">{data?.os_type}</p>
          </div>
          <div>
            <p className="text-sm text-blue-600">Version</p>
            <p className="font-medium text-blue-900">{data?.os_version}</p>
          </div>
          <div>
            <p className="text-sm text-blue-600">Privilèges admin</p>
            <p className={`font-medium ${data?.is_admin ? 'text-green-900' : 'text-red-900'}`}>
              {data?.is_admin ? 'Oui' : 'Non'}
            </p>
          </div>
          <div>
            <p className="text-sm text-blue-600">Capacités</p>
            <p className="font-medium text-blue-900">{data?.capabilities?.join(', ')}</p>
          </div>
        </div>
      </div>
    </div>
  );

  const renderContent = () => {
    if (loading) {
      return (
        <div className="flex items-center justify-center py-12">
          <RefreshCw className="w-8 h-8 animate-spin text-blue-600" />
          <span className="ml-2 text-gray-600">Chargement des détails...</span>
        </div>
      );
    }

    if (error) {
      return (
        <div className="bg-red-50 border border-red-200 rounded-lg p-6">
          <div className="flex items-center space-x-2">
            <AlertTriangle className="w-6 h-6 text-red-500" />
            <div>
              <h3 className="font-medium text-red-900">Erreur</h3>
              <p className="text-red-700">{error}</p>
            </div>
          </div>
        </div>
      );
    }

    if (!data) {
      return (
        <div className="text-center py-12">
          <Info className="w-12 h-12 text-gray-400 mx-auto mb-3" />
          <h3 className="text-lg font-medium text-gray-900">Aucune donnée</h3>
          <p className="text-gray-500">Aucune information disponible pour cet élément</p>
        </div>
      );
    }

    switch (viewType) {
      case 'scan':
        return renderScanDetails();
      case 'threat':
        return renderThreatDetails();
      case 'folder':
        return renderFolderDetails();
      case 'process':
        return renderProcessDetails();
      case 'network':
        return renderNetworkDetails();
      case 'system':
        return renderSystemDetails();
      default:
        return (
          <div className="text-center py-12">
            <Info className="w-12 h-12 text-gray-400 mx-auto mb-3" />
            <h3 className="text-lg font-medium text-gray-900">Type de vue non supporté</h3>
            <p className="text-gray-500">Ce type de vue n'est pas encore implémenté</p>
          </div>
        );
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-6xl max-h-[90vh] overflow-hidden">
        {/* En-tête */}
        <div className="flex items-center justify-between p-6 border-b bg-gray-50">
          <div className="flex items-center space-x-3">
            {getViewIcon()}
            <div>
              <h2 className="text-xl font-bold text-gray-900">{getViewTitle()}</h2>
              {itemId && (
                <p className="text-sm text-gray-600">ID: {itemId}</p>
              )}
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={fetchDetailedData}
              className="p-2 text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded-lg transition-colors"
              title="Actualiser"
            >
              <RefreshCw className="w-5 h-5" />
            </button>
            <button
              onClick={onClose}
              className="p-2 text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded-lg transition-colors"
              title="Fermer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Onglets */}
        <div className="border-b">
          <nav className="flex space-x-8 px-6">
            {['overview', 'details', 'history', 'actions'].map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`py-3 px-1 border-b-2 font-medium text-sm transition-colors ${
                  activeTab === tab
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                {tab === 'overview' && 'Vue d\'ensemble'}
                {tab === 'details' && 'Détails'}
                {tab === 'history' && 'Historique'}
                {tab === 'actions' && 'Actions'}
              </button>
            ))}
          </nav>
        </div>

        {/* Contenu */}
        <div className="p-6 overflow-y-auto max-h-[calc(90vh-200px)]">
          {activeTab === 'overview' && renderContent()}
          {activeTab === 'details' && (
            <div className="bg-gray-50 p-4 rounded-lg">
              <h4 className="font-medium text-gray-900 mb-3">Détails techniques</h4>
              <pre className="bg-white p-4 rounded border overflow-x-auto text-sm">
                {JSON.stringify(data, null, 2)}
              </pre>
            </div>
          )}
          {activeTab === 'history' && (
            <div className="bg-gray-50 p-4 rounded-lg">
              <h4 className="font-medium text-gray-900 mb-3">Historique des événements</h4>
              <p className="text-gray-600">Historique non disponible pour ce type d'élément</p>
            </div>
          )}
          {activeTab === 'actions' && (
            <div className="bg-gray-50 p-4 rounded-lg">
              <h4 className="font-medium text-gray-900 mb-3">Actions disponibles</h4>
              <div className="space-y-3">
                <button className="w-full bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors">
                  Analyser plus en détail
                </button>
                <button className="w-full bg-green-600 text-white px-4 py-2 rounded-lg hover:bg-green-700 transition-colors">
                  Marquer comme résolu
                </button>
                <button className="w-full bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 transition-colors">
                  Quarantaine
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default DetailedView;

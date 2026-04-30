import React, { useState, useEffect } from 'react';
import { Card, Alert, Button, Table, Badge, ProgressBar } from 'react-bootstrap';
import { Shield, AlertTriangle, CheckCircle, FileX, Trash2 } from 'lucide-react';
import axios from 'axios';

interface ScanResult {
  scan_id: string;
  status: string;
  progress: number;
  files_scanned: number;
  threats_found: number;
  start_time: string;
  scan_type: string;
  threats?: Threat[];
}

interface Threat {
  id: string;
  type: string;
  severity: string;
  file_path: string;
  confidence: number;
  description: string;
  timestamp: string;
}

const ScanResults: React.FC<{ scanId?: string }> = ({ scanId }) => {
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [loading, setLoading] = useState(false);
  const [showEradication, setShowEradication] = useState(false);
  const [eradicationResult, setEradicationResult] = useState<any>(null);

  useEffect(() => {
    if (scanId) {
      fetchScanResult();
      const interval = setInterval(fetchScanResult, 2000);
      return () => clearInterval(interval);
    } else {
      fetchAllThreats();
    }
  }, [scanId]);

  const fetchScanResult = async () => {
    try {
      const response = await axios.get(`/api/scan/status/${scanId || 'current'}`);
      setScanResult(response.data);
      
      // Si le scan est terminé, récupérer les menaces
      if (response.data.status === 'completed' || response.data.threats_found > 0) {
        fetchAllThreats();
      }
    } catch (error) {
      console.error('Erreur lors de la récupération des résultats:', error);
    }
  };

  const fetchAllThreats = async () => {
    try {
      const response = await axios.get('/api/threats');
      setThreats(response.data.threats || []);
    } catch (error) {
      console.error('Erreur lors de la récupération des menaces:', error);
    }
  };

  const handleEradication = async (paths: string[], dryRun = true) => {
    setLoading(true);
    try {
      const response = await axios.post('/api/eradications', {
        alert_id: `UI-${Date.now()}`,
        scope: {
          hosts: ['localhost'],
          paths: paths
        },
        actions: ['kill_processes', 'quarantine_files'],
        dry_run: dryRun,
        min_confidence: 0.7
      });
      
      setEradicationResult(response.data);
      setShowEradication(true);
      
      if (!dryRun) {
        // Rafraîchir les menaces après éradication
        setTimeout(fetchAllThreats, 1000);
      }
    } catch (error) {
      console.error('Erreur lors de l\'éradication:', error);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityBadge = (severity: string) => {
    const variants: any = {
      critical: 'danger',
      high: 'danger',
      medium: 'warning',
      low: 'info'
    };
    return <Badge bg={variants[severity] || 'secondary'}>{severity.toUpperCase()}</Badge>;
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'scanning':
        return <Shield className="text-primary animate-pulse" size={20} />;
      case 'completed':
        return threats.length > 0 ? 
          <AlertTriangle className="text-warning" size={20} /> : 
          <CheckCircle className="text-success" size={20} />;
      default:
        return <Shield className="text-muted" size={20} />;
    }
  };

  return (
    <div className="scan-results">
      {/* Statut du scan */}
      {scanResult && (
        <Card className="mb-4">
          <Card.Body>
            <div className="d-flex justify-content-between align-items-center mb-3">
              <h5 className="mb-0 d-flex align-items-center gap-2">
                {getStatusIcon(scanResult.status)}
                Scan {scanResult.scan_type}
              </h5>
              <Badge bg={scanResult.status === 'scanning' ? 'primary' : 'secondary'}>
                {scanResult.status}
              </Badge>
            </div>
            
            {scanResult.status === 'scanning' && (
              <ProgressBar 
                now={scanResult.progress} 
                label={`${scanResult.progress}%`}
                animated 
                striped 
              />
            )}
            
            <div className="mt-3 row">
              <div className="col-md-3">
                <small className="text-muted">Fichiers scannés</small>
                <h6>{scanResult.files_scanned.toLocaleString()}</h6>
              </div>
              <div className="col-md-3">
                <small className="text-muted">Menaces trouvées</small>
                <h6 className={scanResult.threats_found > 0 ? 'text-danger' : 'text-success'}>
                  {scanResult.threats_found}
                </h6>
              </div>
              <div className="col-md-3">
                <small className="text-muted">Heure de début</small>
                <h6>{new Date(scanResult.start_time).toLocaleTimeString()}</h6>
              </div>
              <div className="col-md-3">
                <small className="text-muted">Type de scan</small>
                <h6>{scanResult.scan_type}</h6>
              </div>
            </div>
          </Card.Body>
        </Card>
      )}

      {/* Liste des menaces */}
      {threats.length > 0 && (
        <Card>
          <Card.Header className="d-flex justify-content-between align-items-center">
            <h5 className="mb-0">
              <AlertTriangle className="text-warning me-2" size={20} />
              Menaces détectées ({threats.length})
            </h5>
                          <Button 
                variant="danger" 
                size="sm"
                onClick={() => {
                const map: Record<string, boolean> = {};
                const paths = threats
                  .map(t => t.file_path)
                  .filter(p => p && p !== 'N/A')
                  .filter(p => (map[p] ? false : (map[p] = true)));
                handleEradication(paths, true);
              }}
                disabled={loading}
              >
                <Trash2 size={16} className="me-1" />
                Éradiquer toutes les menaces
              </Button>
          </Card.Header>
          <Card.Body>
            <Table responsive hover>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Fichier</th>
                  <th>Sévérité</th>
                  <th>Confiance</th>
                  <th>Description</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {threats.map(threat => (
                  <tr key={threat.id}>
                    <td>
                      <Badge bg="dark">{threat.type}</Badge>
                    </td>
                    <td className="text-truncate" style={{ maxWidth: '200px' }} title={threat.file_path}>
                      {threat.file_path}
                    </td>
                    <td>{getSeverityBadge(threat.severity)}</td>
                    <td>
                      <div className="d-flex align-items-center">
                        <ProgressBar 
                          now={threat.confidence * 100} 
                          variant={threat.confidence > 0.8 ? 'danger' : 'warning'}
                          style={{ width: '60px', height: '10px' }}
                          className="me-2"
                        />
                        <small>{(threat.confidence * 100).toFixed(0)}%</small>
                      </div>
                    </td>
                    <td className="text-truncate" style={{ maxWidth: '300px' }}>
                      {threat.description}
                    </td>
                    <td>
                      <Button
                        variant="outline-danger"
                        size="sm"
                        onClick={() => handleEradication([threat.file_path], true)}
                        disabled={loading || threat.file_path === 'N/A'}
                      >
                        <FileX size={16} />
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </Card.Body>
        </Card>
      )}

      {/* Aucune menace */}
      {scanResult?.status === 'completed' && threats.length === 0 && (
        <Alert variant="success">
          <CheckCircle className="me-2" size={20} />
          Aucune menace détectée. Votre système est sûr !
        </Alert>
      )}

      {/* Modal d'éradication */}
      {showEradication && eradicationResult && (
        <div className="modal show d-block" style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}>
          <div className="modal-dialog modal-lg">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title">
                  {eradicationResult.dry_run ? 'Aperçu de l\'éradication' : 'Résultat de l\'éradication'}
                </h5>
                <button type="button" className="btn-close" onClick={() => setShowEradication(false)} />
              </div>
              <div className="modal-body">
                <Alert variant={eradicationResult.dry_run ? 'info' : 'success'}>
                  {eradicationResult.dry_run ? 
                    'Mode simulation - Aucune action destructive n\'a été effectuée' :
                    'Éradication terminée avec succès'
                  }
                </Alert>
                
                <div className="row mb-3">
                  <div className="col-md-4">
                    <Card className="text-center">
                      <Card.Body>
                        <h3 className="text-primary">{eradicationResult.stats.files_evaluated}</h3>
                        <small>Fichiers analysés</small>
                      </Card.Body>
                    </Card>
                  </div>
                  <div className="col-md-4">
                    <Card className="text-center">
                      <Card.Body>
                        <h3 className="text-warning">{eradicationResult.stats.files_to_quarantine}</h3>
                        <small>Fichiers à mettre en quarantaine</small>
                      </Card.Body>
                    </Card>
                  </div>
                  <div className="col-md-4">
                    <Card className="text-center">
                      <Card.Body>
                        <h3 className="text-danger">{eradicationResult.stats.processes_to_kill}</h3>
                        <small>Processus à terminer</small>
                      </Card.Body>
                    </Card>
                  </div>
                </div>

                {eradicationResult.steps.map((step: any, idx: number) => (
                  <Card key={idx} className="mb-2">
                    <Card.Body>
                      <h6>Chemin: {step.path}</h6>
                      {step.suspicious_files.length > 0 && (
                        <div>
                          <strong>Fichiers suspects:</strong>
                          <ul>
                            {step.suspicious_files.map((file: any, i: number) => (
                              <li key={i}>
                                {file.file_path} - Confiance: {(file.confidence * 100).toFixed(0)}%
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </Card.Body>
                  </Card>
                ))}
              </div>
              <div className="modal-footer">
                <Button variant="secondary" onClick={() => setShowEradication(false)}>
                  Fermer
                </Button>
                {eradicationResult.dry_run && (
                  <Button 
                    variant="danger" 
                    onClick={() => {
                      const paths = eradicationResult.paths;
                      setShowEradication(false);
                      handleEradication(paths, false);
                    }}
                  >
                    Exécuter l'éradication
                  </Button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ScanResults;

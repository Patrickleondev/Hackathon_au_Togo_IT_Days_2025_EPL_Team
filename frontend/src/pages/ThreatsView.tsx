import React, { useState, useEffect } from 'react';
import { Container, Row, Col, Card, Alert, Button, Badge } from 'react-bootstrap';
import { AlertTriangle, Shield, RefreshCw, Trash2, FileX } from 'lucide-react';
import axios from 'axios';
import ScanResults from '../components/ScanResults';

const ThreatsView: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState({
    totalThreats: 0,
    criticalThreats: 0,
    highThreats: 0,
    mediumThreats: 0,
    lowThreats: 0,
    lastUpdate: new Date().toISOString()
  });

  useEffect(() => {
    fetchThreatsStats();
  }, []);

  const fetchThreatsStats = async () => {
    setLoading(true);
    try {
      const response = await axios.get('/api/threats');
      const threats = response.data.threats || [];
      
      setStats({
        totalThreats: threats.length,
        criticalThreats: threats.filter((t: any) => t.severity === 'critical').length,
        highThreats: threats.filter((t: any) => t.severity === 'high').length,
        mediumThreats: threats.filter((t: any) => t.severity === 'medium').length,
        lowThreats: threats.filter((t: any) => t.severity === 'low').length,
        lastUpdate: response.data.last_update || new Date().toISOString()
      });
    } catch (error) {
      console.error('Erreur lors de la récupération des statistiques:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleRefresh = () => {
    fetchThreatsStats();
    window.location.reload(); // Pour rafraîchir aussi le composant ScanResults
  };

  return (
    <Container fluid className="py-4">
      <Row className="mb-4">
        <Col>
          <div className="d-flex justify-content-between align-items-center">
            <h2 className="d-flex align-items-center gap-2">
              <AlertTriangle className="text-warning" size={28} />
              Centre de gestion des menaces
            </h2>
            <Button 
              variant="outline-primary" 
              onClick={handleRefresh}
              disabled={loading}
            >
              <RefreshCw size={16} className={loading ? 'spin' : ''} />
              Actualiser
            </Button>
          </div>
        </Col>
      </Row>

      {/* Statistiques */}
      <Row className="mb-4">
        <Col md={3}>
          <Card className="text-center border-0 shadow-sm">
            <Card.Body>
              <h3 className="text-primary mb-0">{stats.totalThreats}</h3>
              <small className="text-muted">Menaces totales</small>
            </Card.Body>
          </Card>
        </Col>
        <Col md={3}>
          <Card className="text-center border-0 shadow-sm">
            <Card.Body className="bg-danger bg-opacity-10">
              <h3 className="text-danger mb-0">{stats.criticalThreats}</h3>
              <small className="text-muted">Critiques</small>
            </Card.Body>
          </Card>
        </Col>
        <Col md={3}>
          <Card className="text-center border-0 shadow-sm">
            <Card.Body className="bg-warning bg-opacity-10">
              <h3 className="text-warning mb-0">{stats.highThreats + stats.mediumThreats}</h3>
              <small className="text-muted">Élevées/Moyennes</small>
            </Card.Body>
          </Card>
        </Col>
        <Col md={3}>
          <Card className="text-center border-0 shadow-sm">
            <Card.Body className="bg-info bg-opacity-10">
              <h3 className="text-info mb-0">{stats.lowThreats}</h3>
              <small className="text-muted">Faibles</small>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      {/* Alert si menaces critiques */}
      {stats.criticalThreats > 0 && (
        <Alert variant="danger" className="d-flex align-items-center">
          <AlertTriangle className="me-2" size={20} />
          <strong>Attention !</strong> {stats.criticalThreats} menace(s) critique(s) détectée(s). 
          Action immédiate recommandée.
        </Alert>
      )}

      {/* Dernière mise à jour */}
      <div className="text-end mb-3">
        <small className="text-muted">
          Dernière mise à jour : {new Date(stats.lastUpdate).toLocaleString()}
        </small>
      </div>

      {/* Composant de résultats */}
      <ScanResults />

      {/* Styles inline supprimés pour compatibilité CRA */}
    </Container>
  );
};

export default ThreatsView;

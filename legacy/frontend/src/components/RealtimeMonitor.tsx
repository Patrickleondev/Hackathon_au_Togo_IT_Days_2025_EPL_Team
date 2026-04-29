import React, { useState, useEffect } from 'react';
import { Card, Badge, Alert, Row, Col, ListGroup, ProgressBar } from 'react-bootstrap';
import { Activity, AlertTriangle, Shield, FileText, Globe, Cpu, HardDrive, Wifi } from 'lucide-react';
import { useWebSocket } from '../hooks/useWebSocket';
import axios from 'axios';

interface SystemInfo {
  os_type: string;
  os_version: any;
  is_admin: boolean;
  capabilities: any;
}

interface SystemStats {
  file_monitor: {
    is_monitoring: boolean;
    watched_paths: string[];
    total_events: number;
  };
  process_monitor: {
    is_monitoring: boolean;
    total_processes: number;
    suspicious_processes: number;
    processes: any[];
  };
  network_monitor: {
    is_monitoring: boolean;
    stats: any;
  };
  websocket: {
    active_connections: number;
    channels: string[];
  };
}

interface Event {
  type: string;
  timestamp: string;
  severity?: string;
  [key: string]: any;
}

const RealtimeMonitor: React.FC = () => {
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
  const [systemStats, setSystemStats] = useState<SystemStats | null>(null);
  const [events, setEvents] = useState<Event[]>([]);
  const [alerts, setAlerts] = useState<Event[]>([]);
  
  // WebSocket connection
  const { isConnected, subscribe, lastMessage } = useWebSocket('/ws', {
    onOpen: () => {
      // S'abonner aux canaux
      subscribe('threats');
      subscribe('file_system');
      subscribe('processes');
      subscribe('alerts');
    },
    onMessage: (data) => {
      // Ajouter l'événement à la liste
      setEvents(prev => [data, ...prev].slice(0, 100));
      
      // Si c'est une alerte ou une menace
      if (data.type === 'threat_detected' || data.severity === 'high' || data.severity === 'critical') {
        setAlerts(prev => [data, ...prev].slice(0, 20));
      }
    }
  });
  
  // Charger les infos système
  useEffect(() => {
    const loadSystemInfo = async () => {
      try {
        const [infoRes, statsRes] = await Promise.all([
          axios.get('/api/system/info'),
          axios.get('/api/system/stats')
        ]);
        
        setSystemInfo(infoRes.data);
        setSystemStats(statsRes.data);
      } catch (error) {
        console.error('Erreur chargement infos système:', error);
      }
    };
    
    loadSystemInfo();
    
    // Rafraîchir les stats toutes les 5 secondes
    const interval = setInterval(async () => {
      try {
        const res = await axios.get('/api/system/stats');
        setSystemStats(res.data);
      } catch (error) {
        console.error('Erreur rafraîchissement stats:', error);
      }
    }, 5000);
    
    return () => clearInterval(interval);
  }, []);
  
  // Traiter le dernier message WebSocket
  useEffect(() => {
    if (lastMessage) {
      console.log('Message WebSocket reçu:', lastMessage);
    }
  }, [lastMessage]);
  
  const getEventIcon = (type: string) => {
    if (type.includes('file')) return <FileText size={16} />;
    if (type.includes('process')) return <Cpu size={16} />;
    if (type.includes('network')) return <Globe size={16} />;
    if (type.includes('threat')) return <AlertTriangle size={16} />;
    return <Activity size={16} />;
  };
  
  const getEventColor = (event: Event) => {
    if (event.severity === 'critical') return 'danger';
    if (event.severity === 'high') return 'warning';
    if (event.suspicious) return 'warning';
    if (event.type.includes('threat')) return 'danger';
    return 'info';
  };
  
  const formatTime = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString();
  };
  
  return (
    <div className="realtime-monitor">
      {/* Status Bar */}
      <Card className="mb-3 bg-dark text-white">
        <Card.Body className="d-flex justify-content-between align-items-center py-2">
          <div className="d-flex align-items-center">
            <Activity className={`me-2 ${isConnected ? 'text-success' : 'text-danger'}`} />
            <span>
              {isConnected ? 'Monitoring en temps réel actif' : 'Déconnecté'}
            </span>
          </div>
          
          {systemInfo && (
            <div className="d-flex align-items-center gap-3">
              <Badge bg={systemInfo.is_admin ? 'success' : 'warning'}>
                {systemInfo.is_admin ? 'Admin' : 'Limité'}
              </Badge>
              <span className="text-muted">{systemInfo.os_type}</span>
            </div>
          )}
        </Card.Body>
      </Card>
      
      {/* Stats Overview */}
      {systemStats && (
        <Row className="mb-3">
          <Col md={4}>
            <Card className="h-100">
              <Card.Body>
                <div className="d-flex justify-content-between align-items-center mb-2">
                  <h6 className="mb-0">
                    <HardDrive size={20} className="me-2" />
                    Surveillance Fichiers
                  </h6>
                  <Badge bg={systemStats.file_monitor.is_monitoring ? 'success' : 'secondary'}>
                    {systemStats.file_monitor.is_monitoring ? 'Actif' : 'Inactif'}
                  </Badge>
                </div>
                <div className="small text-muted">
                  {systemStats.file_monitor.watched_paths.length} chemins surveillés
                </div>
                <div className="mt-2">
                  <strong>{systemStats.file_monitor.total_events}</strong> événements
                </div>
              </Card.Body>
            </Card>
          </Col>
          
          <Col md={4}>
            <Card className="h-100">
              <Card.Body>
                <div className="d-flex justify-content-between align-items-center mb-2">
                  <h6 className="mb-0">
                    <Cpu size={20} className="me-2" />
                    Surveillance Processus
                  </h6>
                  <Badge bg={systemStats.process_monitor.is_monitoring ? 'success' : 'secondary'}>
                    {systemStats.process_monitor.is_monitoring ? 'Actif' : 'Inactif'}
                  </Badge>
                </div>
                <div className="small text-muted">
                  {systemStats.process_monitor.total_processes} processus actifs
                </div>
                <div className="mt-2">
                  <Badge bg="danger">
                    {systemStats.process_monitor.suspicious_processes} suspects
                  </Badge>
                </div>
              </Card.Body>
            </Card>
          </Col>
          
          <Col md={4}>
            <Card className="h-100">
              <Card.Body>
                <div className="d-flex justify-content-between align-items-center mb-2">
                  <h6 className="mb-0">
                    <Wifi size={20} className="me-2" />
                    Surveillance Réseau
                  </h6>
                  <Badge bg={systemStats.network_monitor.is_monitoring ? 'success' : 'secondary'}>
                    {systemStats.network_monitor.is_monitoring ? 'Actif' : 'Inactif'}
                  </Badge>
                </div>
                <div className="small text-muted">
                  {systemStats.network_monitor.stats?.active_connections || 0} connexions
                </div>
                <div className="mt-2">
                  {systemStats.network_monitor.stats?.total_packets || 0} paquets
                </div>
              </Card.Body>
            </Card>
          </Col>
        </Row>
      )}
      
      {/* Alerts */}
      {alerts.length > 0 && (
        <Alert variant="danger" className="mb-3">
          <Alert.Heading className="h6">
            <AlertTriangle className="me-2" />
            Alertes Récentes ({alerts.length})
          </Alert.Heading>
          <ListGroup variant="flush" className="mt-2">
            {alerts.slice(0, 3).map((alert, idx) => (
              <ListGroup.Item key={idx} className="px-0 py-2 bg-transparent border-danger">
                <div className="d-flex justify-content-between">
                  <span>{alert.details?.description || alert.type}</span>
                  <small className="text-muted">{formatTime(alert.timestamp)}</small>
                </div>
              </ListGroup.Item>
            ))}
          </ListGroup>
        </Alert>
      )}
      
      {/* Live Events Stream */}
      <Card>
        <Card.Header className="d-flex justify-content-between align-items-center">
          <h5 className="mb-0">
            <Activity size={20} className="me-2" />
            Flux d'événements en temps réel
          </h5>
          <Badge bg="primary">{events.length} événements</Badge>
        </Card.Header>
        <Card.Body style={{ maxHeight: '400px', overflowY: 'auto' }}>
          <ListGroup variant="flush">
            {events.map((event, idx) => (
              <ListGroup.Item 
                key={idx} 
                className={`px-0 py-2 border-${getEventColor(event)}`}
              >
                <div className="d-flex align-items-start">
                  <div className="me-3 mt-1">
                    {getEventIcon(event.type)}
                  </div>
                  <div className="flex-grow-1">
                    <div className="d-flex justify-content-between align-items-start">
                      <div>
                        <Badge bg={getEventColor(event)} className="me-2">
                          {event.type}
                        </Badge>
                        {event.path && (
                          <small className="text-muted">{event.path}</small>
                        )}
                        {event.process?.name && (
                          <small className="text-muted">{event.process.name} (PID: {event.process.pid})</small>
                        )}
                        {event.details?.description && (
                          <div className="small mt-1">{event.details.description}</div>
                        )}
                      </div>
                      <small className="text-muted">{formatTime(event.timestamp)}</small>
                    </div>
                  </div>
                </div>
              </ListGroup.Item>
            ))}
            
            {events.length === 0 && (
              <div className="text-center text-muted py-4">
                En attente d'événements...
              </div>
            )}
          </ListGroup>
        </Card.Body>
      </Card>
      
      {/* Processus suspects */}
      {Boolean(systemStats?.process_monitor?.processes && systemStats.process_monitor.processes.length > 0) && (
        <Card className="mt-3">
          <Card.Header>
            <h5 className="mb-0">
              <AlertTriangle size={20} className="me-2 text-warning" />
              Processus Suspects Détectés
            </h5>
          </Card.Header>
          <Card.Body>
            <ListGroup>
              {systemStats?.process_monitor?.processes?.map((proc, idx) => (
                <ListGroup.Item key={idx} className="d-flex justify-content-between align-items-center">
                  <div>
                    <strong>{proc.name}</strong>
                    <span className="text-muted ms-2">PID: {proc.pid}</span>
                    <div className="small text-muted">
                      Score: {proc.suspicious_score} | {proc.behaviors?.join(', ')}
                    </div>
                  </div>
                  <Badge bg="warning">Suspect</Badge>
                </ListGroup.Item>
              ))}
            </ListGroup>
          </Card.Body>
        </Card>
      )}
    </div>
  );
};

export default RealtimeMonitor;

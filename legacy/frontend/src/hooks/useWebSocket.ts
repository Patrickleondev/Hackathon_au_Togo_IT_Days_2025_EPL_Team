import { useState, useEffect, useCallback, useRef } from 'react';

interface WebSocketOptions {
  onOpen?: () => void;
  onClose?: () => void;
  onError?: (error: Event) => void;
  onMessage?: (data: any) => void;
  reconnect?: boolean;
  reconnectInterval?: number;
  reconnectAttempts?: number;
}

interface WebSocketHook {
  isConnected: boolean;
  send: (data: any) => void;
  subscribe: (channel: string) => void;
  unsubscribe: (channel: string) => void;
  reconnect: () => void;
  disconnect: () => void;
  lastMessage: any;
  error: Error | null;
}

export const useWebSocket = (
  url: string,
  options: WebSocketOptions = {}
): WebSocketHook => {
  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<any>(null);
  const [error, setError] = useState<Error | null>(null);
  
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  
  const {
    onOpen,
    onClose,
    onError,
    onMessage,
    reconnect = true,
    reconnectInterval = 5000,
    reconnectAttempts = 5
  } = options;
  
  const connect = useCallback(() => {
    try {
      // Générer un ID client unique
      const clientId = `client_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      // Construire dynamiquement l'URL WebSocket
      let baseUrl = url;
      const envWs = (typeof process !== 'undefined' && (process as any).env && (process as any).env.REACT_APP_WS_URL) ? (process as any).env.REACT_APP_WS_URL : '';
      if (!baseUrl || baseUrl === '') {
        baseUrl = envWs || '/ws';
      }
      let wsUrl = '';
      if (baseUrl.startsWith('ws://') || baseUrl.startsWith('wss://')) {
        wsUrl = `${baseUrl.replace(/\/$/, '')}/${clientId}`;
      } else {
        const isHttps = typeof window !== 'undefined' && window.location && window.location.protocol === 'https:';
        const protocol = isHttps ? 'wss' : 'ws';
        const host = typeof window !== 'undefined' && window.location ? window.location.host : 'localhost:8000';
        const path = baseUrl.startsWith('/') ? baseUrl : `/${baseUrl}`;
        wsUrl = `${protocol}://${host}${path.replace(/\/$/, '')}/${clientId}`;
      }
      
      console.log(`🔌 Connexion WebSocket à ${wsUrl}`);
      
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;
      
      ws.onopen = () => {
        console.log('✅ WebSocket connecté');
        setIsConnected(true);
        setError(null);
        reconnectAttemptsRef.current = 0;
        
        // Ping périodique pour maintenir la connexion
        const pingInterval = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'ping' }));
          }
        }, 30000);
        
        // Stocker l'intervalle pour le nettoyer plus tard
        (ws as any).pingInterval = pingInterval;
        
        onOpen?.();
      };
      
      ws.onclose = () => {
        console.log('🔌 WebSocket déconnecté');
        setIsConnected(false);
        
        // Nettoyer le ping
        if ((ws as any).pingInterval) {
          clearInterval((ws as any).pingInterval);
        }
        
        onClose?.();
        
        // Tentative de reconnexion
        if (reconnect && reconnectAttemptsRef.current < reconnectAttempts) {
          reconnectAttemptsRef.current++;
          console.log(`🔄 Tentative de reconnexion ${reconnectAttemptsRef.current}/${reconnectAttempts}`);
          
          reconnectTimeoutRef.current = setTimeout(() => {
            connect();
          }, reconnectInterval);
        }
      };
      
      ws.onerror = (event) => {
        console.error('❌ Erreur WebSocket:', event);
        setError(new Error('WebSocket connection error'));
        onError?.(event);
      };
      
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          setLastMessage(data);
          
          // Log spécifique selon le type de message
          switch (data.type) {
            case 'threat_detected':
              console.warn('⚠️ Menace détectée:', data);
              break;
            case 'file_created':
            case 'file_modified':
            case 'file_deleted':
              console.log('📁 Événement fichier:', data);
              break;
            case 'process_created':
            case 'process_terminated':
            case 'suspicious_process_detected':
              console.log('⚙️ Événement processus:', data);
              break;
            case 'network_anomaly_detected':
            case 'port_scan_detected':
            case 'c2_communication':
              console.log('🌐 Événement réseau:', data);
              break;
            case 'pong':
              // Ignorer les pongs
              break;
            default:
              console.log('📨 Message reçu:', data);
          }
          
          onMessage?.(data);
        } catch (err) {
          console.error('Erreur parsing message:', err);
        }
      };
      
    } catch (err) {
      console.error('Erreur création WebSocket:', err);
      setError(err as Error);
    }
  }, [url, onOpen, onClose, onError, onMessage, reconnect, reconnectInterval, reconnectAttempts]);
  
  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    
    setIsConnected(false);
  }, []);
  
  const send = useCallback((data: any) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data));
    } else {
      console.warn('WebSocket non connecté');
    }
  }, []);
  
  const subscribe = useCallback((channel: string) => {
    send({
      type: 'subscribe',
      channel
    });
    console.log(`📢 Abonnement au canal: ${channel}`);
  }, [send]);
  
  const unsubscribe = useCallback((channel: string) => {
    send({
      type: 'unsubscribe',
      channel
    });
    console.log(`🔇 Désabonnement du canal: ${channel}`);
  }, [send]);
  
  const reconnectNow = useCallback(() => {
    reconnectAttemptsRef.current = 0;
    disconnect();
    connect();
  }, [connect, disconnect]);
  
  // Connexion initiale
  useEffect(() => {
    connect();
    
    return () => {
      disconnect();
    };
  }, [connect, disconnect]);
  
  return {
    isConnected,
    send,
    subscribe,
    unsubscribe,
    reconnect: reconnectNow,
    disconnect,
    lastMessage,
    error
  };
};

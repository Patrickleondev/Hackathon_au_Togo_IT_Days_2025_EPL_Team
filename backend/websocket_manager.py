"""
Gestionnaire WebSocket pour communication temps réel
Streaming des événements système et alertes
"""

import asyncio
import json
import logging
from typing import Dict, Set, Optional, Any
from datetime import datetime
from fastapi import WebSocket, WebSocketDisconnect
from collections import defaultdict

logger = logging.getLogger(__name__)

class ConnectionManager:
    """Gestionnaire des connexions WebSocket"""
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.subscriptions: Dict[str, Set[str]] = defaultdict(set)
        self.connection_stats: Dict[str, Dict] = {}
        
    async def connect(self, websocket: WebSocket, client_id: str):
        """Accepter une nouvelle connexion"""
        await websocket.accept()
        self.active_connections[client_id] = websocket
        self.connection_stats[client_id] = {
            'connected_at': datetime.now().isoformat(),
            'messages_sent': 0,
            'messages_received': 0,
            'subscriptions': set()
        }
        logger.info(f"Client {client_id} connecté via WebSocket")
        
        # Envoyer un message de bienvenue
        await self.send_personal_message({
            'type': 'connection',
            'status': 'connected',
            'client_id': client_id,
            'timestamp': datetime.now().isoformat()
        }, websocket)
    
    def disconnect(self, client_id: str):
        """Déconnecter un client"""
        if client_id in self.active_connections:
            del self.active_connections[client_id]
            
        # Nettoyer les souscriptions
        for channel in list(self.subscriptions.keys()):
            self.subscriptions[channel].discard(client_id)
            if not self.subscriptions[channel]:
                del self.subscriptions[channel]
        
        if client_id in self.connection_stats:
            del self.connection_stats[client_id]
            
        logger.info(f"Client {client_id} déconnecté")
    
    async def send_personal_message(self, message: Dict, websocket: WebSocket):
        """Envoyer un message à un client spécifique"""
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.error(f"Erreur envoi message personnel: {e}")
    
    async def broadcast(self, message: Dict, channel: Optional[str] = None):
        """Diffuser un message à tous les clients ou à un canal"""
        if channel:
            # Envoyer seulement aux abonnés du canal
            subscribers = self.subscriptions.get(channel, set())
            connections = [
                self.active_connections[client_id]
                for client_id in subscribers
                if client_id in self.active_connections
            ]
        else:
            # Envoyer à tous
            connections = list(self.active_connections.values())
        
        # Envoyer en parallèle
        tasks = []
        for connection in connections:
            tasks.append(self._send_safe(connection, message))
        
        await asyncio.gather(*tasks)
    
    async def _send_safe(self, websocket: WebSocket, message: Dict):
        """Envoyer un message de manière sécurisée"""
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.debug(f"Erreur envoi broadcast: {e}")
    
    def subscribe(self, client_id: str, channel: str):
        """S'abonner à un canal"""
        self.subscriptions[channel].add(client_id)
        if client_id in self.connection_stats:
            self.connection_stats[client_id]['subscriptions'].add(channel)
        logger.info(f"Client {client_id} abonné au canal {channel}")
    
    def unsubscribe(self, client_id: str, channel: str):
        """Se désabonner d'un canal"""
        self.subscriptions[channel].discard(client_id)
        if not self.subscriptions[channel]:
            del self.subscriptions[channel]
        
        if client_id in self.connection_stats:
            self.connection_stats[client_id]['subscriptions'].discard(channel)
        
        logger.info(f"Client {client_id} désabonné du canal {channel}")
    
    def get_stats(self) -> Dict:
        """Obtenir les statistiques de connexion"""
        return {
            'active_connections': len(self.active_connections),
            'total_subscriptions': sum(len(subs) for subs in self.subscriptions.values()),
            'channels': list(self.subscriptions.keys()),
            'clients': self.connection_stats
        }

# Instance globale
manager = ConnectionManager()

class SystemEventStreamer:
    """Streamer d'événements système en temps réel"""
    
    def __init__(self, connection_manager: ConnectionManager):
        self.manager = connection_manager
        self.event_queue = asyncio.Queue()
        self.is_streaming = False
        
    async def start_streaming(self):
        """Démarrer le streaming des événements"""
        if self.is_streaming:
            return
            
        self.is_streaming = True
        asyncio.create_task(self._stream_events())
        logger.info("🚀 Streaming d'événements démarré")
    
    async def stop_streaming(self):
        """Arrêter le streaming"""
        self.is_streaming = False
        logger.info("🛑 Streaming d'événements arrêté")
    
    async def _stream_events(self):
        """Boucle de streaming des événements"""
        while self.is_streaming:
            try:
                # Récupérer l'événement de la queue
                event = await asyncio.wait_for(
                    self.event_queue.get(),
                    timeout=1.0
                )
                
                # Déterminer le canal
                channel = self._get_event_channel(event)
                
                # Enrichir l'événement
                event['streamed_at'] = datetime.now().isoformat()
                
                # Diffuser
                await self.manager.broadcast(event, channel)
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Erreur streaming: {e}")
                await asyncio.sleep(1)
    
    def _get_event_channel(self, event: Dict) -> str:
        """Déterminer le canal pour un événement"""
        event_type = event.get('type', 'unknown')
        
        # Mapping des types d'événements vers les canaux
        channel_mapping = {
            'file_created': 'file_system',
            'file_modified': 'file_system',
            'file_deleted': 'file_system',
            'suspicious_file': 'threats',
            'process_created': 'processes',
            'process_terminated': 'processes',
            'suspicious_process_detected': 'threats',
            'network_anomaly_detected': 'threats',
            'port_scan_detected': 'threats',
            'c2_communication': 'threats',
            'dga_domain': 'threats',
            'registry_modified': 'registry',
            'system_log': 'logs',
            'threat_detected': 'threats',
            'scan_progress': 'scans',
            'alert': 'alerts'
        }
        
        return channel_mapping.get(event_type, 'general')
    
    async def queue_event(self, event: Dict):
        """Ajouter un événement à la queue"""
        try:
            await self.event_queue.put(event)
        except Exception as e:
            logger.error(f"Erreur ajout événement: {e}")

# Instance globale du streamer
event_streamer = SystemEventStreamer(manager)

async def handle_websocket_connection(websocket: WebSocket, client_id: str):
    """Gérer une connexion WebSocket"""
    await manager.connect(websocket, client_id)
    
    try:
        while True:
            # Recevoir les messages du client
            data = await websocket.receive_json()
            
            # Traiter le message
            message_type = data.get('type')
            
            if message_type == 'subscribe':
                channel = data.get('channel')
                if channel:
                    manager.subscribe(client_id, channel)
                    await manager.send_personal_message({
                        'type': 'subscription',
                        'channel': channel,
                        'status': 'subscribed',
                        'timestamp': datetime.now().isoformat()
                    }, websocket)
            
            elif message_type == 'unsubscribe':
                channel = data.get('channel')
                if channel:
                    manager.unsubscribe(client_id, channel)
                    await manager.send_personal_message({
                        'type': 'subscription',
                        'channel': channel,
                        'status': 'unsubscribed',
                        'timestamp': datetime.now().isoformat()
                    }, websocket)
            
            elif message_type == 'ping':
                await manager.send_personal_message({
                    'type': 'pong',
                    'timestamp': datetime.now().isoformat()
                }, websocket)
            
            # Mettre à jour les stats
            if client_id in manager.connection_stats:
                manager.connection_stats[client_id]['messages_received'] += 1
                
    except WebSocketDisconnect:
        manager.disconnect(client_id)
    except Exception as e:
        logger.error(f"Erreur WebSocket {client_id}: {e}")
        manager.disconnect(client_id)

# Fonctions utilitaires pour envoyer des événements
async def send_file_event(action: str, path: str, suspicious: bool = False):
    """Envoyer un événement fichier"""
    event = {
        'type': f'file_{action}',
        'path': path,
        'suspicious': suspicious,
        'timestamp': datetime.now().isoformat()
    }
    
    if suspicious:
        event['type'] = 'suspicious_file'
        event['severity'] = 'high'
    
    await event_streamer.queue_event(event)

async def send_process_event(event_type: str, process_info: Dict):
    """Envoyer un événement processus"""
    event = {
        'type': event_type,
        'process': process_info,
        'timestamp': datetime.now().isoformat()
    }
    
    await event_streamer.queue_event(event)

async def send_network_event(event_type: str, details: Dict):
    """Envoyer un événement réseau"""
    event = {
        'type': event_type,
        'details': details,
        'timestamp': datetime.now().isoformat()
    }
    
    await event_streamer.queue_event(event)

async def send_threat_alert(threat_type: str, severity: str, details: Dict):
    """Envoyer une alerte de menace"""
    alert = {
        'type': 'threat_detected',
        'threat_type': threat_type,
        'severity': severity,
        'details': details,
        'timestamp': datetime.now().isoformat(),
        'requires_action': severity in ['critical', 'high']
    }
    
    await event_streamer.queue_event(alert)

async def send_scan_progress(scan_id: str, progress: float, files_scanned: int, threats_found: int):
    """Envoyer la progression d'un scan"""
    event = {
        'type': 'scan_progress',
        'scan_id': scan_id,
        'progress': progress,
        'files_scanned': files_scanned,
        'threats_found': threats_found,
        'timestamp': datetime.now().isoformat()
    }
    
    await event_streamer.queue_event(event)

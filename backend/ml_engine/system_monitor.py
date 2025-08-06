"""
Module de monitoring système en temps réel
RansomGuard AI - Hackathon Togo IT Days 2025

"""

import psutil
import asyncio
import logging
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
import os
import json
from collections import defaultdict

logger = logging.getLogger(__name__)

class SystemMonitor:
    """
    Moniteur système pour détecter les activités suspectes
    """
    
    def __init__(self):
        self.is_monitoring = False
        self.monitoring_task = None
        self.suspicious_activities = []
        self.process_history = defaultdict(list)
        self.file_access_history = defaultdict(list)
        self.network_connections = []
        self.system_stats = {
            'cpu_usage': 0.0,
            'memory_usage': 0.0,
            'disk_usage': 0.0,
            'network_io': {'bytes_sent': 0, 'bytes_recv': 0}
        }
        self.alert_callbacks = []
        
    async def start_monitoring(self):
        """Démarrer le monitoring système"""
        if self.is_monitoring:
            logger.warning("Le monitoring est déjà actif")
            return
        
        self.is_monitoring = True
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())
        logger.info(" Monitoring système démarré")
    
    async def stop_monitoring(self):
        """Arrêter le monitoring système"""
        if not self.is_monitoring:
            return
        
        self.is_monitoring = False
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        
        logger.info(" Monitoring système arrêté")
    
    async def _monitoring_loop(self):
        """Boucle principale de monitoring"""
        while self.is_monitoring:
            try:
                # Collecter les statistiques système
                await self._collect_system_stats()
                
                # Analyser les processus
                await self._analyze_processes()
                
                # Surveiller les accès aux fichiers
                await self._monitor_file_access()
                
                # Surveiller les connexions réseau
                await self._monitor_network()
                
                # Détecter les activités suspectes
                await self._detect_suspicious_activities()
                
                # Pause entre les cycles
                await asyncio.sleep(1)  # 1 seconde d'intervalle
                
            except Exception as e:
                logger.error(f"Erreur dans la boucle de monitoring: {e}")
                await asyncio.sleep(5)  # Pause plus longue en cas d'erreur
    
    async def _collect_system_stats(self):
        """Collecter les statistiques système"""
        try:
            # CPU
            self.system_stats['cpu_usage'] = psutil.cpu_percent(interval=1)
            
            # Mémoire
            memory = psutil.virtual_memory()
            self.system_stats['memory_usage'] = memory.percent
            
            # Disque
            disk = psutil.disk_usage('/')
            self.system_stats['disk_usage'] = disk.percent
            
            # Réseau
            network = psutil.net_io_counters()
            self.system_stats['network_io'] = {
                'bytes_sent': network.bytes_sent,
                'bytes_recv': network.bytes_recv
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la collecte des stats système: {e}")
    
    async def _analyze_processes(self):
        """Analyser les processus en cours"""
        try:
            processes = []
            
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'create_time']):
                try:
                    proc_info = proc.info
                    processes.append(proc_info)
                    
                    # Historique des processus
                    self.process_history[proc_info['pid']].append({
                        'timestamp': datetime.now().isoformat(),
                        'cpu_percent': proc_info['cpu_percent'],
                        'memory_percent': proc_info['memory_percent']
                    })
                    
                    # Limiter l'historique à 100 entrées par processus
                    if len(self.process_history[proc_info['pid']]) > 100:
                        self.process_history[proc_info['pid']] = self.process_history[proc_info['pid']][-100:]
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Détecter les processus suspects
            await self._detect_suspicious_processes(processes)
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse des processus: {e}")
    
    async def _detect_suspicious_processes(self, processes: List[Dict]):
        """Détecter les processus suspects"""
        suspicious_indicators = [
            'encrypt', 'crypt', 'lock', 'ransom', 'wanna', 'crypto',
            'bitcoin', 'wallet', 'miner', 'cryptominer', 'crypto'
        ]
        
        for proc in processes:
            proc_name = proc['name'].lower()
            
            # Vérifier les indicateurs suspects
            for indicator in suspicious_indicators:
                if indicator in proc_name:
                    await self._create_alert(
                        'suspicious_process',
                        f"Processus suspect détecté: {proc['name']} (PID: {proc['pid']})",
                        'medium',
                        {
                            'process_name': proc['name'],
                            'pid': proc['pid'],
                            'cpu_usage': proc['cpu_percent'],
                            'memory_usage': proc['memory_percent']
                        }
                    )
                    break
            
            # Vérifier l'utilisation excessive de CPU
            if proc['cpu_percent'] > 80:
                await self._create_alert(
                    'high_cpu_usage',
                    f"Utilisation CPU élevée: {proc['name']} ({proc['cpu_percent']:.1f}%)",
                    'low',
                    {
                        'process_name': proc['name'],
                        'pid': proc['pid'],
                        'cpu_usage': proc['cpu_percent']
                    }
                )
    
    async def _monitor_file_access(self):
        """Surveiller les accès aux fichiers"""
        try:
            # Simulation de surveillance des fichiers
            # Dans une implémentation réelle, on utiliserait des hooks système
            
            # Analyser les fichiers récemment modifiés
            recent_files = await self._get_recently_modified_files()
            
            for file_path in recent_files:
                # Vérifier les patterns suspects
                if await self._is_file_suspicious(file_path):
                    await self._create_alert(
                        'suspicious_file_activity',
                        f"Activité suspecte détectée sur le fichier: {file_path}",
                        'high',
                        {'file_path': file_path}
                    )
                
                # Historique des accès
                self.file_access_history[file_path].append({
                    'timestamp': datetime.now().isoformat(),
                    'action': 'modified'
                })
                
                # Limiter l'historique
                if len(self.file_access_history[file_path]) > 50:
                    self.file_access_history[file_path] = self.file_access_history[file_path][-50:]
                    
        except Exception as e:
            logger.error(f"Erreur lors de la surveillance des fichiers: {e}")
    
    async def _get_recently_modified_files(self) -> List[str]:
        """Obtenir les fichiers récemment modifiés"""
        recent_files = []
        
        try:
            # Dossiers à surveiller
            watch_dirs = [
                os.path.expanduser("~/Documents"),
                os.path.expanduser("~/Desktop"),
                os.path.expanduser("~/Downloads"),
                os.path.expanduser("~/Pictures"),
            ]
            
            current_time = time.time()
            
            for directory in watch_dirs:
                if os.path.exists(directory):
                    for root, dirs, files in os.walk(directory):
                        for file in files:
                            file_path = os.path.join(root, file)
                            try:
                                stat = os.stat(file_path)
                                # Fichiers modifiés dans les dernières 5 minutes
                                if current_time - stat.st_mtime < 300:
                                    recent_files.append(file_path)
                            except:
                                continue
                        break  # Ne pas aller trop profondément
                        
        except Exception as e:
            logger.error(f"Erreur lors de la recherche de fichiers récents: {e}")
        
        return recent_files
    
    async def _is_file_suspicious(self, file_path: str) -> bool:
        """Vérifier si un fichier est suspect"""
        try:
            filename = os.path.basename(file_path).lower()
            
            # Extensions suspectes
            suspicious_extensions = [
                '.encrypted', '.locked', '.crypto', '.ransom',
                '.bitcoin', '.wallet', '.miner'
            ]
            
            # Vérifier l'extension
            for ext in suspicious_extensions:
                if filename.endswith(ext):
                    return True
            
            # Vérifier les noms suspects
            suspicious_names = [
                'readme', 'decrypt', 'pay', 'bitcoin', 'wallet',
                'ransom', 'encrypt', 'crypto', 'lock'
            ]
            
            for name in suspicious_names:
                if name in filename:
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Erreur lors de la vérification du fichier: {e}")
            return False
    
    async def _monitor_network(self):
        """Surveiller les connexions réseau"""
        try:
            connections = psutil.net_connections()
            
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    # Vérifier les connexions suspectes
                    if await self._is_connection_suspicious(conn):
                        await self._create_alert(
                            'suspicious_network_connection',
                            f"Connexion réseau suspecte: {conn.raddr.ip}:{conn.raddr.port}",
                            'medium',
                            {
                                'remote_ip': conn.raddr.ip,
                                'remote_port': conn.raddr.port,
                                'local_port': conn.laddr.port,
                                'status': conn.status
                            }
                        )
                    
                    # Stocker la connexion
                    self.network_connections.append({
                        'timestamp': datetime.now().isoformat(),
                        'remote_ip': conn.raddr.ip,
                        'remote_port': conn.raddr.port,
                        'local_port': conn.laddr.port,
                        'status': conn.status
                    })
            
            # Limiter l'historique des connexions
            if len(self.network_connections) > 1000:
                self.network_connections = self.network_connections[-1000:]
                
        except Exception as e:
            logger.error(f"Erreur lors de la surveillance réseau: {e}")
    
    async def _is_connection_suspicious(self, connection) -> bool:
        """Vérifier si une connexion est suspecte"""
        try:
            # Ports suspects
            suspicious_ports = [22, 23, 3389, 5900, 8080, 4444, 6667]
            
            if connection.raddr.port in suspicious_ports:
                return True
            
            # IPs suspectes (exemple)
            suspicious_ips = [
                '192.168.1.100',  # Exemple d'IP suspecte
                '10.0.0.1'
            ]
            
            if connection.raddr.ip in suspicious_ips:
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Erreur lors de la vérification de connexion: {e}")
            return False
    
    async def _detect_suspicious_activities(self):
        """Détecter les activités suspectes globales"""
        try:
            # Vérifier l'utilisation excessive de ressources
            if self.system_stats['cpu_usage'] > 90:
                await self._create_alert(
                    'high_system_cpu',
                    f"Utilisation CPU système élevée: {self.system_stats['cpu_usage']:.1f}%",
                    'medium',
                    {'cpu_usage': self.system_stats['cpu_usage']}
                )
            
            if self.system_stats['memory_usage'] > 90:
                await self._create_alert(
                    'high_system_memory',
                    f"Utilisation mémoire système élevée: {self.system_stats['memory_usage']:.1f}%",
                    'medium',
                    {'memory_usage': self.system_stats['memory_usage']}
                )
            
            # Vérifier les patterns d'activité suspecte
            await self._check_activity_patterns()
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection d'activités suspectes: {e}")
    
    async def _check_activity_patterns(self):
        """Vérifier les patterns d'activité suspecte"""
        try:
            # Vérifier les accès massifs aux fichiers
            for file_path, history in self.file_access_history.items():
                if len(history) > 10:  # Plus de 10 accès
                    recent_accesses = [h for h in history if 
                                     (datetime.now() - datetime.fromisoformat(h['timestamp'])).seconds < 60]
                    
                    if len(recent_accesses) > 5:  # Plus de 5 accès en 1 minute
                        await self._create_alert(
                            'mass_file_access',
                            f"Accès massif détecté sur: {file_path}",
                            'high',
                            {
                                'file_path': file_path,
                                'access_count': len(recent_accesses),
                                'time_window': '1 minute'
                            }
                        )
            
            # Vérifier les processus avec comportement suspect
            for pid, history in self.process_history.items():
                if len(history) > 5:
                    recent_activity = [h for h in history if 
                                     (datetime.now() - datetime.fromisoformat(h['timestamp'])).seconds < 30]
                    
                    if len(recent_activity) > 3:
                        avg_cpu = sum(h['cpu_percent'] for h in recent_activity) / len(recent_activity)
                        if avg_cpu > 50:  # CPU moyen élevé
                            await self._create_alert(
                                'suspicious_process_activity',
                                f"Activité suspecte du processus PID {pid}",
                                'medium',
                                {
                                    'pid': pid,
                                    'avg_cpu': avg_cpu,
                                    'activity_count': len(recent_activity)
                                }
                            )
                            
        except Exception as e:
            logger.error(f"Erreur lors de la vérification des patterns: {e}")
    
    async def _create_alert(self, alert_type: str, message: str, severity: str, details: Dict):
        """Créer une alerte"""
        alert = {
            'id': f"{alert_type}_{int(time.time())}",
            'type': alert_type,
            'message': message,
            'severity': severity,
            'timestamp': datetime.now().isoformat(),
            'details': details
        }
        
        self.suspicious_activities.append(alert)
        
        # Limiter le nombre d'alertes stockées
        if len(self.suspicious_activities) > 1000:
            self.suspicious_activities = self.suspicious_activities[-1000:]
        
        logger.warning(f"🚨 ALERTE {severity.upper()}: {message}")
        
        # Notifier les callbacks
        for callback in self.alert_callbacks:
            try:
                await callback(alert)
            except Exception as e:
                logger.error(f"Erreur dans le callback d'alerte: {e}")
    
    def add_alert_callback(self, callback):
        """Ajouter un callback pour les alertes"""
        self.alert_callbacks.append(callback)
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Obtenir le statut actuel du système"""
        return {
            'monitoring_active': self.is_monitoring,
            'cpu_usage': self.system_stats['cpu_usage'],
            'memory_usage': self.system_stats['memory_usage'],
            'disk_usage': self.system_stats['disk_usage'],
            'network_io': self.system_stats['network_io'],
            'active_processes': len(self.process_history),
            'suspicious_activities': len(self.suspicious_activities),
            'monitored_files': len(self.file_access_history),
            'network_connections': len(self.network_connections)
        }
    
    async def get_suspicious_activities(self) -> List[Dict[str, Any]]:
        """Obtenir la liste des activités suspectes"""
        return self.suspicious_activities
    
    async def get_process_history(self, pid: int = None) -> Dict[str, Any]:
        """Obtenir l'historique des processus"""
        if pid:
            return self.process_history.get(pid, [])
        else:
            return dict(self.process_history)
    
    async def get_file_access_history(self, file_path: str = None) -> Dict[str, Any]:
        """Obtenir l'historique des accès aux fichiers"""
        if file_path:
            return self.file_access_history.get(file_path, [])
        else:
            return dict(self.file_access_history)
    
    async def clear_history(self):
        """Effacer l'historique"""
        self.process_history.clear()
        self.file_access_history.clear()
        self.network_connections.clear()
        self.suspicious_activities.clear()
        logger.info("Historique effacé") 
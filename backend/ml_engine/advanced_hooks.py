"""
Hooks système avancés pour la surveillance en temps réel
RansomGuard AI - Hackathon Togo IT Days 2025
"""

import os
import sys
import logging
import asyncio
import threading
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
import psutil
import platform

# Imports spécifiques selon la plateforme
if platform.system() == 'Windows':
    import win32file
    import win32con
    import win32api
    import pywintypes
elif platform.system() == 'Linux':
    import inotify.adapters
    import inotify.constants

logger = logging.getLogger(__name__)

class AdvancedSystemHooks:
    """
    Hooks système avancés pour la surveillance en temps réel
    """
    
    def __init__(self):
        self.is_monitoring = False
        self.file_watchers = {}
        self.process_watchers = {}
        self.registry_watchers = {}
        self.callbacks = {
            'file_created': [],
            'file_modified': [],
            'file_deleted': [],
            'process_created': [],
            'process_terminated': [],
            'registry_modified': [],
            'network_connection': []
        }
        self.suspicious_patterns = {
            'file_extensions': ['.encrypted', '.locked', '.crypto', '.ransom', '.bitcoin'],
            'file_names': ['readme', 'decrypt', 'pay', 'bitcoin', 'wallet', 'ransom'],
            'process_names': ['encrypt', 'crypt', 'lock', 'ransom', 'wanna', 'crypto'],
            'registry_keys': [
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
            ]
        }
    
    async def start_advanced_monitoring(self):
        """Démarrer la surveillance avancée avec hooks système"""
        try:
            self.is_monitoring = True
            
            # Démarrer les différents watchers
            await asyncio.gather(
                self._start_file_monitoring(),
                self._start_process_monitoring(),
                self._start_registry_monitoring(),
                self._start_network_monitoring()
            )
            
            logger.info("🔍 Surveillance avancée démarrée avec hooks système")
            
        except Exception as e:
            logger.error(f"Erreur lors du démarrage de la surveillance avancée: {e}")
    
    async def stop_advanced_monitoring(self):
        """Arrêter la surveillance avancée"""
        self.is_monitoring = False
        
        # Arrêter tous les watchers
        for watcher in self.file_watchers.values():
            if hasattr(watcher, 'stop'):
                watcher.stop()
        
        logger.info("🛑 Surveillance avancée arrêtée")
    
    async def _start_file_monitoring(self):
        """Surveillance avancée des fichiers"""
        try:
            if platform.system() == 'Windows':
                await self._start_windows_file_monitoring()
            elif platform.system() == 'Linux':
                await self._start_linux_file_monitoring()
            else:
                logger.warning("Surveillance avancée des fichiers non supportée sur cette plateforme")
                
        except Exception as e:
            logger.error(f"Erreur lors de la surveillance des fichiers: {e}")
    
    async def _start_windows_file_monitoring(self):
        """Surveillance des fichiers sur Windows"""
        try:
            # Dossiers à surveiller
            watch_dirs = [
                os.path.expanduser("~/Documents"),
                os.path.expanduser("~/Desktop"),
                os.path.expanduser("~/Downloads"),
                os.path.expanduser("~/Pictures")
            ]
            
            for directory in watch_dirs:
                if os.path.exists(directory):
                    # Créer un thread de surveillance pour chaque dossier
                    thread = threading.Thread(
                        target=self._windows_file_watcher,
                        args=(directory,),
                        daemon=True
                    )
                    thread.start()
                    self.file_watchers[directory] = thread
                    
        except Exception as e:
            logger.error(f"Erreur lors de la surveillance Windows: {e}")
    
    def _windows_file_watcher(self, directory: str):
        """Watcher de fichiers Windows"""
        try:
            # Utiliser l'API Windows pour surveiller les changements
            handle = win32file.CreateFileW(
                directory,
                win32con.GENERIC_READ,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
                None,
                win32con.OPEN_EXISTING,
                win32con.FILE_FLAG_BACKUP_SEMANTICS,
                None
            )
            
            while self.is_monitoring:
                try:
                    # Attendre les changements
                    result = win32file.ReadDirectoryChangesW(
                        handle,
                        1024,
                        True,
                        win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                        win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                        win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                        win32con.FILE_NOTIFY_CHANGE_SIZE |
                        win32con.FILE_NOTIFY_CHANGE_LAST_WRITE,
                        None,
                        None
                    )
                    
                    for action, filename in result:
                        file_path = os.path.join(directory, filename)
                        
                        if action == win32con.FILE_ACTION_ADDED:
                            asyncio.run(self._handle_file_event('file_created', file_path))
                        elif action == win32con.FILE_ACTION_MODIFIED:
                            asyncio.run(self._handle_file_event('file_modified', file_path))
                        elif action == win32con.FILE_ACTION_REMOVED:
                            asyncio.run(self._handle_file_event('file_deleted', file_path))
                            
                except pywintypes.error:
                    break
                    
        except Exception as e:
            logger.error(f"Erreur dans le watcher Windows: {e}")
    
    async def _start_linux_file_monitoring(self):
        """Surveillance des fichiers sur Linux"""
        try:
            # Utiliser inotify pour Linux
            watch_dirs = [
                os.path.expanduser("~/Documents"),
                os.path.expanduser("~/Desktop"),
                os.path.expanduser("~/Downloads"),
                os.path.expanduser("~/Pictures")
            ]
            
            for directory in watch_dirs:
                if os.path.exists(directory):
                    thread = threading.Thread(
                        target=self._linux_file_watcher,
                        args=(directory,),
                        daemon=True
                    )
                    thread.start()
                    self.file_watchers[directory] = thread
                    
        except Exception as e:
            logger.error(f"Erreur lors de la surveillance Linux: {e}")
    
    def _linux_file_watcher(self, directory: str):
        """Watcher de fichiers Linux"""
        try:
            i = inotify.adapters.InotifyTree(directory)
            
            for event in i.event_gen():
                if not self.is_monitoring:
                    break
                    
                if event is not None:
                    (header, type_names, watch_path, filename) = event
                    
                    if filename:
                        file_path = os.path.join(watch_path, filename.decode('utf-8'))
                        
                        if 'IN_CREATE' in type_names:
                            asyncio.run(self._handle_file_event('file_created', file_path))
                        elif 'IN_MODIFY' in type_names:
                            asyncio.run(self._handle_file_event('file_modified', file_path))
                        elif 'IN_DELETE' in type_names:
                            asyncio.run(self._handle_file_event('file_deleted', file_path))
                            
        except Exception as e:
            logger.error(f"Erreur dans le watcher Linux: {e}")
    
    async def _start_process_monitoring(self):
        """Surveillance avancée des processus"""
        try:
            # Surveiller les nouveaux processus
            thread = threading.Thread(
                target=self._process_watcher,
                daemon=True
            )
            thread.start()
            self.process_watchers['main'] = thread
            
        except Exception as e:
            logger.error(f"Erreur lors de la surveillance des processus: {e}")
    
    def _process_watcher(self):
        """Watcher de processus"""
        try:
            # Obtenir la liste initiale des processus
            initial_processes = set(psutil.pids())
            
            while self.is_monitoring:
                try:
                    time.sleep(1)  # Vérifier toutes les secondes
                    
                    current_processes = set(psutil.pids())
                    new_processes = current_processes - initial_processes
                    
                    for pid in new_processes:
                        try:
                            process = psutil.Process(pid)
                            process_info = {
                                'pid': pid,
                                'name': process.name(),
                                'cmdline': process.cmdline(),
                                'create_time': process.create_time()
                            }
                            
                            asyncio.run(self._handle_process_event('process_created', process_info))
                            
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                    
                    initial_processes = current_processes
                    
                except Exception as e:
                    logger.error(f"Erreur dans le watcher de processus: {e}")
                    
        except Exception as e:
            logger.error(f"Erreur dans le watcher de processus: {e}")
    
    async def _start_registry_monitoring(self):
        """Surveillance du registre Windows"""
        if platform.system() != 'Windows':
            return
            
        try:
            # Surveiller les clés de registre sensibles
            thread = threading.Thread(
                target=self._registry_watcher,
                daemon=True
            )
            thread.start()
            self.registry_watchers['main'] = thread
            
        except Exception as e:
            logger.error(f"Erreur lors de la surveillance du registre: {e}")
    
    def _registry_watcher(self):
        """Watcher de registre Windows"""
        try:
            import winreg
            
            # Surveiller les clés de démarrage
            startup_keys = [
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")
            ]
            
            # Obtenir les valeurs initiales
            initial_values = {}
            for hkey, subkey in startup_keys:
                try:
                    key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ)
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            initial_values[f"{subkey}\\{name}"] = value
                            i += 1
                        except WindowsError:
                            break
                    winreg.CloseKey(key)
                except WindowsError:
                    continue
            
            while self.is_monitoring:
                try:
                    time.sleep(5)  # Vérifier toutes les 5 secondes
                    
                    # Vérifier les changements
                    for hkey, subkey in startup_keys:
                        try:
                            key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ)
                            i = 0
                            while True:
                                try:
                                    name, value, _ = winreg.EnumValue(key, i)
                                    key_path = f"{subkey}\\{name}"
                                    
                                    if key_path not in initial_values or initial_values[key_path] != value:
                                        # Changement détecté
                                        registry_info = {
                                            'key': key_path,
                                            'name': name,
                                            'value': value,
                                            'old_value': initial_values.get(key_path, 'N/A')
                                        }
                                        
                                        asyncio.run(self._handle_registry_event('registry_modified', registry_info))
                                        initial_values[key_path] = value
                                    
                                    i += 1
                                except WindowsError:
                                    break
                            winreg.CloseKey(key)
                        except WindowsError:
                            continue
                            
                except Exception as e:
                    logger.error(f"Erreur dans le watcher de registre: {e}")
                    
        except Exception as e:
            logger.error(f"Erreur dans le watcher de registre: {e}")
    
    async def _start_network_monitoring(self):
        """Surveillance avancée du réseau"""
        try:
            thread = threading.Thread(
                target=self._network_watcher,
                daemon=True
            )
            thread.start()
            
        except Exception as e:
            logger.error(f"Erreur lors de la surveillance réseau: {e}")
    
    def _network_watcher(self):
        """Watcher réseau"""
        try:
            # Surveiller les nouvelles connexions
            initial_connections = set()
            
            while self.is_monitoring:
                try:
                    time.sleep(2)  # Vérifier toutes les 2 secondes
                    
                    current_connections = set()
                    for conn in psutil.net_connections(kind='inet'):
                        if conn.status == 'ESTABLISHED' and conn.raddr:
                            conn_key = f"{conn.raddr.ip}:{conn.raddr.port}"
                            current_connections.add(conn_key)
                    
                    new_connections = current_connections - initial_connections
                    
                    for conn_key in new_connections:
                        try:
                            # Gérer les cas où l'IP peut contenir des ':' (IPv6)
                            if conn_key.count(':') > 1:
                                # IPv6 - prendre la dernière partie comme port
                                parts = conn_key.split(':')
                                ip = ':'.join(parts[:-1])
                                port = parts[-1]
                            else:
                                # IPv4 - format standard
                                ip, port = conn_key.split(':')
                            
                            connection_info = {
                                'remote_ip': ip,
                                'remote_port': int(port),
                                'timestamp': datetime.now().isoformat()
                            }
                        except (ValueError, IndexError) as e:
                            logger.debug(f"Connexion ignorée (format invalide): {conn_key}")
                            continue
                        
                        asyncio.run(self._handle_network_event('network_connection', connection_info))
                    
                    initial_connections = current_connections
                    
                except Exception as e:
                    logger.error(f"Erreur dans le watcher réseau: {e}")
                    
        except Exception as e:
            logger.error(f"Erreur dans le watcher réseau: {e}")
    
    async def _handle_file_event(self, event_type: str, file_path: str):
        """Gérer un événement de fichier"""
        try:
            # Vérifier si le fichier est suspect
            if await self._is_suspicious_file(file_path):
                logger.warning(f"🚨 Fichier suspect détecté: {file_path}")
                
                # Notifier tous les callbacks
                for callback in self.callbacks[event_type]:
                    try:
                        await callback({
                            'event_type': event_type,
                            'file_path': file_path,
                            'timestamp': datetime.now().isoformat(),
                            'suspicious': True
                        })
                    except Exception as e:
                        logger.error(f"Erreur dans le callback {event_type}: {e}")
            
        except Exception as e:
            logger.error(f"Erreur lors du traitement de l'événement fichier: {e}")
    
    async def _handle_process_event(self, event_type: str, process_info: Dict[str, Any]):
        """Gérer un événement de processus"""
        try:
            # Vérifier si le processus est suspect
            if await self._is_suspicious_process(process_info):
                logger.warning(f"🚨 Processus suspect détecté: {process_info['name']} (PID: {process_info['pid']})")
                
                # Notifier tous les callbacks
                for callback in self.callbacks[event_type]:
                    try:
                        await callback({
                            'event_type': event_type,
                            'process_info': process_info,
                            'timestamp': datetime.now().isoformat(),
                            'suspicious': True
                        })
                    except Exception as e:
                        logger.error(f"Erreur dans le callback {event_type}: {e}")
            
        except Exception as e:
            logger.error(f"Erreur lors du traitement de l'événement processus: {e}")
    
    async def _handle_registry_event(self, event_type: str, registry_info: Dict[str, Any]):
        """Gérer un événement de registre"""
        try:
            # Vérifier si la modification est suspecte
            if await self._is_suspicious_registry_change(registry_info):
                logger.warning(f"🚨 Modification suspecte du registre: {registry_info['key']}")
                
                # Notifier tous les callbacks
                for callback in self.callbacks[event_type]:
                    try:
                        await callback({
                            'event_type': event_type,
                            'registry_info': registry_info,
                            'timestamp': datetime.now().isoformat(),
                            'suspicious': True
                        })
                    except Exception as e:
                        logger.error(f"Erreur dans le callback {event_type}: {e}")
            
        except Exception as e:
            logger.error(f"Erreur lors du traitement de l'événement registre: {e}")
    
    async def _handle_network_event(self, event_type: str, connection_info: Dict[str, Any]):
        """Gérer un événement réseau"""
        try:
            # Vérifier si la connexion est suspecte
            if await self._is_suspicious_connection(connection_info):
                logger.warning(f"🚨 Connexion suspecte: {connection_info['remote_ip']}:{connection_info['remote_port']}")
                
                # Notifier tous les callbacks
                for callback in self.callbacks[event_type]:
                    try:
                        await callback({
                            'event_type': event_type,
                            'connection_info': connection_info,
                            'timestamp': datetime.now().isoformat(),
                            'suspicious': True
                        })
                    except Exception as e:
                        logger.error(f"Erreur dans le callback {event_type}: {e}")
            
        except Exception as e:
            logger.error(f"Erreur lors du traitement de l'événement réseau: {e}")
    
    async def _is_suspicious_file(self, file_path: str) -> bool:
        """Vérifier si un fichier est suspect"""
        try:
            filename = os.path.basename(file_path).lower()
            
            # Vérifier les extensions suspectes
            for ext in self.suspicious_patterns['file_extensions']:
                if filename.endswith(ext):
                    return True
            
            # Vérifier les noms suspects
            for name in self.suspicious_patterns['file_names']:
                if name in filename:
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Erreur lors de la vérification du fichier: {e}")
            return False
    
    async def _is_suspicious_process(self, process_info: Dict[str, Any]) -> bool:
        """Vérifier si un processus est suspect"""
        try:
            process_name = process_info.get('name', '').lower()
            
            # Vérifier les noms de processus suspects
            for pattern in self.suspicious_patterns['process_names']:
                if pattern in process_name:
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Erreur lors de la vérification du processus: {e}")
            return False
    
    async def _is_suspicious_registry_change(self, registry_info: Dict[str, Any]) -> bool:
        """Vérifier si une modification de registre est suspecte"""
        try:
            key = registry_info.get('key', '').lower()
            value = registry_info.get('value', '').lower()
            
            # Vérifier les clés sensibles
            for pattern in self.suspicious_patterns['registry_keys']:
                if pattern.lower() in key:
                    return True
            
            # Vérifier les valeurs suspectes
            suspicious_values = ['encrypt', 'crypt', 'lock', 'ransom', 'bitcoin']
            for pattern in suspicious_values:
                if pattern in value:
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Erreur lors de la vérification du registre: {e}")
            return False
    
    async def _is_suspicious_connection(self, connection_info: Dict[str, Any]) -> bool:
        """Vérifier si une connexion est suspecte"""
        try:
            remote_ip = connection_info.get('remote_ip', '')
            remote_port = connection_info.get('remote_port', 0)
            
            # Ports suspects
            suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999, 1234, 31337]
            if remote_port in suspicious_ports:
                return True
            
            # IPs suspectes (exemple)
            suspicious_ips = ['192.168.1.100', '10.0.0.1']
            if remote_ip in suspicious_ips:
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Erreur lors de la vérification de connexion: {e}")
            return False
    
    def add_callback(self, event_type: str, callback: Callable):
        """Ajouter un callback pour un type d'événement"""
        if event_type in self.callbacks:
            self.callbacks[event_type].append(callback)
    
    def remove_callback(self, event_type: str, callback: Callable):
        """Supprimer un callback"""
        if event_type in self.callbacks and callback in self.callbacks[event_type]:
            self.callbacks[event_type].remove(callback)

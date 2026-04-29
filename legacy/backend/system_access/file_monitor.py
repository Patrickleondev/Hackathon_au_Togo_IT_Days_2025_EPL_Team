"""
Moniteur de système de fichiers temps réel multi-OS
Surveillance avancée avec accès privilégié
"""

import os
import asyncio
import logging
from typing import Dict, List, Callable, Optional, Set
from datetime import datetime
from pathlib import Path
import hashlib
import json
from collections import defaultdict

from .os_detector import system_access, OSType

logger = logging.getLogger(__name__)

class FileSystemMonitor:
    """Surveillance temps réel du système de fichiers avec détection d'anomalies"""
    
    def __init__(self):
        self.os_type = system_access.os_type
        self.is_monitoring = False
        self.watch_paths: Set[str] = set()
        self.exclude_patterns: Set[str] = set()
        self.file_callbacks: List[Callable] = []
        self.file_hashes: Dict[str, str] = {}
        self.file_history: Dict[str, List[Dict]] = defaultdict(list)
        self.suspicious_extensions = {
            '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar',
            '.scr', '.pif', '.com', '.gadget', '.msi', '.msp', '.hta',
            '.cpl', '.msc', '.jar', '.vb', '.jse', '.ws', '.wsf',
            '.wsc', '.wsh', '.ps1xml', '.ps2', '.ps2xml', '.psc1', '.psc2',
            '.msh', '.msh1', '.msh2', '.mshxml', '.msh1xml', '.msh2xml',
            '.scf', '.lnk', '.inf', '.reg', '.sct', '.shb', '.shs',
            '.url', '.vbe', '.vbs', '.wsf', '.wsh', '.xsl', '.job',
            '.application', '.pif', '.gadget', '.msi', '.msp', '.com',
            '.scr', '.hta', '.cpl', '.msc', '.jar', '.bat', '.cmd'
        }
        self._setup_os_specific_monitoring()
        
    def _setup_os_specific_monitoring(self):
        """Configurer la surveillance spécifique à l'OS"""
        if self.os_type == OSType.WINDOWS:
            self._setup_windows_monitoring()
        elif self.os_type == OSType.LINUX:
            self._setup_linux_monitoring()
        elif self.os_type == OSType.MACOS:
            self._setup_macos_monitoring()
    
    def _setup_windows_monitoring(self):
        """Configuration Windows avec WMI et Win32 API"""
        try:
            import win32file
            import win32con
            import pywintypes
            self.win32_available = True
            
            # Chemins Windows critiques à surveiller
            self.critical_paths = [
                r"C:\Windows\System32",
                r"C:\Windows\SysWOW64",
                r"C:\Program Files",
                r"C:\Program Files (x86)",
                r"C:\ProgramData",
                r"C:\Users\Public",
                os.environ.get('USERPROFILE', ''),
                os.path.join(os.environ.get('USERPROFILE', ''), 'AppData'),
                os.path.join(os.environ.get('USERPROFILE', ''), 'Desktop'),
                os.path.join(os.environ.get('USERPROFILE', ''), 'Documents'),
                os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads')
            ]
            
            # Patterns d'exclusion Windows
            self.exclude_patterns.update({
                r"*.tmp", r"*.temp", r"~$*", r"*.log",
                r"*\System Volume Information\*",
                r"*\$RECYCLE.BIN\*",
                r"*\pagefile.sys",
                r"*\hiberfil.sys",
                r"*\swapfile.sys"
            })
            
        except ImportError:
            logger.warning("win32 API non disponible, utilisation du mode basique")
            self.win32_available = False
    
    def _setup_linux_monitoring(self):
        """Configuration Linux avec inotify"""
        try:
            import inotify.adapters
            self.inotify_available = True
            
            # Chemins Linux critiques
            self.critical_paths = [
                "/etc",
                "/usr/bin",
                "/usr/sbin",
                "/bin",
                "/sbin",
                "/boot",
                "/lib",
                "/lib64",
                "/opt",
                "/home",
                "/root",
                "/var/log",
                "/tmp",
                os.path.expanduser("~"),
                os.path.join(os.path.expanduser("~"), ".ssh"),
                os.path.join(os.path.expanduser("~"), ".config")
            ]
            
            # Patterns d'exclusion Linux
            self.exclude_patterns.update({
                "*.tmp", "*.swp", "*.swo", "*~",
                "/proc/*", "/sys/*", "/dev/*",
                "*.log", "*.pid", "*.lock"
            })
            
        except ImportError:
            logger.warning("inotify non disponible, utilisation du mode polling")
            self.inotify_available = False
    
    def _setup_macos_monitoring(self):
        """Configuration macOS avec FSEvents"""
        try:
            import fsevents
            self.fsevents_available = True
            
            # Chemins macOS critiques
            self.critical_paths = [
                "/System",
                "/Library",
                "/Applications",
                "/usr/local",
                "/private/etc",
                "/private/var",
                os.path.expanduser("~"),
                os.path.join(os.path.expanduser("~"), "Library"),
                os.path.join(os.path.expanduser("~"), "Desktop"),
                os.path.join(os.path.expanduser("~"), "Documents"),
                os.path.join(os.path.expanduser("~"), "Downloads")
            ]
            
            # Patterns d'exclusion macOS
            self.exclude_patterns.update({
                "*.tmp", ".DS_Store", "._*",
                "*/Library/Caches/*",
                "*/Library/Logs/*",
                "*.log"
            })
            
        except ImportError:
            logger.warning("FSEvents non disponible, utilisation du mode polling")
            self.fsevents_available = False
    
    async def start_monitoring(self, paths: Optional[List[str]] = None):
        """Démarrer la surveillance des chemins spécifiés"""
        if self.is_monitoring:
            logger.warning("La surveillance est déjà active")
            return
        
        # Utiliser les chemins critiques par défaut si aucun n'est spécifié
        if not paths:
            paths = [p for p in self.critical_paths if os.path.exists(p)]
        
        self.watch_paths = set(paths)
        self.is_monitoring = True
        
        logger.info(f"🔍 Démarrage de la surveillance sur {len(self.watch_paths)} chemins")
        
        # Lancer la surveillance selon l'OS
        if self.os_type == OSType.WINDOWS and self.win32_available:
            asyncio.create_task(self._windows_file_monitor())
        elif self.os_type == OSType.LINUX and self.inotify_available:
            asyncio.create_task(self._linux_file_monitor())
        elif self.os_type == OSType.MACOS and self.fsevents_available:
            asyncio.create_task(self._macos_file_monitor())
        else:
            # Fallback sur polling
            asyncio.create_task(self._polling_file_monitor())
    
    async def _windows_file_monitor(self):
        """Surveillance Windows avec ReadDirectoryChangesW"""
        import win32file
        import win32con
        import pywintypes
        
        ACTIONS = {
            1: "created",
            2: "deleted",
            3: "modified",
            4: "renamed_from",
            5: "renamed_to"
        }
        
        for path in self.watch_paths:
            if not os.path.exists(path):
                continue
                
            try:
                handle = win32file.CreateFile(
                    path,
                    win32con.GENERIC_READ,
                    win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
                    None,
                    win32con.OPEN_EXISTING,
                    win32con.FILE_FLAG_BACKUP_SEMANTICS,
                    None
                )
                
                asyncio.create_task(self._monitor_windows_directory(handle, path, ACTIONS))
                
            except Exception as e:
                logger.error(f"Erreur surveillance Windows sur {path}: {e}")
    
    async def _monitor_windows_directory(self, handle, path, actions):
        """Surveiller un répertoire Windows"""
        import win32file
        import win32con
        
        while self.is_monitoring:
            try:
                results = win32file.ReadDirectoryChangesW(
                    handle,
                    1024,
                    True,  # Surveiller les sous-répertoires
                    win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                    win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                    win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                    win32con.FILE_NOTIFY_CHANGE_SIZE |
                    win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
                    win32con.FILE_NOTIFY_CHANGE_SECURITY,
                    None,
                    None
                )
                
                for action, file in results:
                    full_path = os.path.join(path, file)
                    
                    if self._should_ignore_file(full_path):
                        continue
                    
                    event = {
                        'timestamp': datetime.now().isoformat(),
                        'action': actions.get(action, 'unknown'),
                        'path': full_path,
                        'suspicious': self._is_suspicious_file(full_path)
                    }
                    
                    await self._handle_file_event(event)
                    
            except Exception as e:
                logger.error(f"Erreur ReadDirectoryChangesW: {e}")
                await asyncio.sleep(1)
    
    async def _linux_file_monitor(self):
        """Surveillance Linux avec inotify"""
        import inotify.adapters
        
        for path in self.watch_paths:
            if not os.path.exists(path):
                continue
                
            asyncio.create_task(self._monitor_linux_directory(path))
    
    async def _monitor_linux_directory(self, path):
        """Surveiller un répertoire Linux"""
        import inotify.adapters
        
        i = inotify.adapters.InotifyTree(path)
        
        while self.is_monitoring:
            try:
                for event in i.event_gen(timeout_s=1):
                    if event is None:
                        continue
                        
                    (header, type_names, watch_path, filename) = event
                    
                    if filename:
                        full_path = os.path.join(watch_path, filename.decode('utf-8', errors='ignore'))
                        
                        if self._should_ignore_file(full_path):
                            continue
                        
                        action = 'unknown'
                        if 'IN_CREATE' in type_names:
                            action = 'created'
                        elif 'IN_DELETE' in type_names:
                            action = 'deleted'
                        elif 'IN_MODIFY' in type_names:
                            action = 'modified'
                        elif 'IN_MOVED_FROM' in type_names:
                            action = 'renamed_from'
                        elif 'IN_MOVED_TO' in type_names:
                            action = 'renamed_to'
                        
                        event_data = {
                            'timestamp': datetime.now().isoformat(),
                            'action': action,
                            'path': full_path,
                            'suspicious': self._is_suspicious_file(full_path)
                        }
                        
                        await self._handle_file_event(event_data)
                        
            except Exception as e:
                logger.error(f"Erreur inotify: {e}")
                await asyncio.sleep(1)
    
    async def _polling_file_monitor(self):
        """Fallback: surveillance par polling pour tous les OS"""
        logger.info("Utilisation du mode polling pour la surveillance")
        
        file_stats = {}
        
        while self.is_monitoring:
            try:
                for watch_path in self.watch_paths:
                    if not os.path.exists(watch_path):
                        continue
                    
                    for root, dirs, files in os.walk(watch_path):
                        # Limiter la profondeur pour les performances
                        depth = root[len(watch_path):].count(os.sep)
                        if depth > 5:
                            dirs.clear()
                            continue
                        
                        for file in files:
                            full_path = os.path.join(root, file)
                            
                            if self._should_ignore_file(full_path):
                                continue
                            
                            try:
                                stat = os.stat(full_path)
                                current_stat = (stat.st_size, stat.st_mtime)
                                
                                if full_path in file_stats:
                                    if file_stats[full_path] != current_stat:
                                        # Fichier modifié
                                        event = {
                                            'timestamp': datetime.now().isoformat(),
                                            'action': 'modified',
                                            'path': full_path,
                                            'suspicious': self._is_suspicious_file(full_path)
                                        }
                                        await self._handle_file_event(event)
                                else:
                                    # Nouveau fichier
                                    event = {
                                        'timestamp': datetime.now().isoformat(),
                                        'action': 'created',
                                        'path': full_path,
                                        'suspicious': self._is_suspicious_file(full_path)
                                    }
                                    await self._handle_file_event(event)
                                
                                file_stats[full_path] = current_stat
                                
                            except (OSError, PermissionError):
                                continue
                
                # Vérifier les fichiers supprimés
                deleted_files = set(file_stats.keys()) - set(
                    full_path for watch_path in self.watch_paths
                    for root, dirs, files in os.walk(watch_path)
                    for file in files
                    for full_path in [os.path.join(root, file)]
                )
                
                for deleted_file in deleted_files:
                    event = {
                        'timestamp': datetime.now().isoformat(),
                        'action': 'deleted',
                        'path': deleted_file,
                        'suspicious': False
                    }
                    await self._handle_file_event(event)
                    del file_stats[deleted_file]
                
                await asyncio.sleep(2)  # Polling toutes les 2 secondes
                
            except Exception as e:
                logger.error(f"Erreur polling: {e}")
                await asyncio.sleep(5)
    
    def _should_ignore_file(self, path: str) -> bool:
        """Vérifier si un fichier doit être ignoré"""
        path_lower = path.lower()
        
        # Ignorer les patterns d'exclusion
        for pattern in self.exclude_patterns:
            if pattern.startswith("*") and path_lower.endswith(pattern[1:]):
                return True
            elif pattern.endswith("*") and path_lower.startswith(pattern[:-1]):
                return True
            elif "*" in pattern:
                import fnmatch
                if fnmatch.fnmatch(path_lower, pattern.lower()):
                    return True
        
        return False
    
    def _is_suspicious_file(self, path: str) -> bool:
        """Détecter si un fichier est suspect"""
        _, ext = os.path.splitext(path.lower())
        
        # Extension suspecte
        if ext in self.suspicious_extensions:
            return True
        
        # Nom de fichier suspect
        filename = os.path.basename(path).lower()
        suspicious_names = [
            'ransomware', 'cryptolocker', 'wannacry', 'petya', 'locky',
            'cerber', 'gandcrab', 'ryuk', 'sodinokibi', 'maze',
            'encrypt', 'decrypt', 'locked', 'pwned', 'readme',
            'howtorecoveryourfiles', 'howtodecrypt', 'readthis'
        ]
        
        if any(name in filename for name in suspicious_names):
            return True
        
        # Vérifier les doubles extensions
        parts = filename.split('.')
        if len(parts) > 2 and parts[-2] in ['jpg', 'doc', 'pdf', 'txt']:
            return True
        
        return False
    
    async def _handle_file_event(self, event: Dict):
        """Traiter un événement fichier"""
        # Ajouter à l'historique
        path = event['path']
        self.file_history[path].append(event)
        
        # Limiter l'historique
        if len(self.file_history[path]) > 100:
            self.file_history[path] = self.file_history[path][-100:]
        
        # Calculer le hash si c'est une création/modification
        if event['action'] in ['created', 'modified'] and os.path.exists(path):
            try:
                event['hash'] = await self._calculate_file_hash(path)
            except:
                event['hash'] = None
        
        # Notifier les callbacks
        for callback in self.file_callbacks:
            try:
                await callback(event)
            except Exception as e:
                logger.error(f"Erreur callback: {e}")
        
        # Logger si suspect
        if event.get('suspicious'):
            logger.warning(f"⚠️ Fichier suspect détecté: {path}")
    
    async def _calculate_file_hash(self, path: str, max_size: int = 50 * 1024 * 1024) -> Optional[str]:
        """Calculer le hash SHA256 d'un fichier"""
        try:
            # Limiter aux fichiers < 50MB pour les performances
            if os.path.getsize(path) > max_size:
                return None
            
            sha256_hash = hashlib.sha256()
            with open(path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            
            return sha256_hash.hexdigest()
            
        except Exception:
            return None
    
    def add_callback(self, callback: Callable):
        """Ajouter un callback pour les événements fichier"""
        self.file_callbacks.append(callback)
    
    def get_file_history(self, path: str) -> List[Dict]:
        """Obtenir l'historique d'un fichier"""
        return self.file_history.get(path, [])
    
    async def stop_monitoring(self):
        """Arrêter la surveillance"""
        self.is_monitoring = False
        logger.info("🛑 Surveillance des fichiers arrêtée")

"""
Moniteur de registre Windows temps réel
Surveillance des clés de persistence et modifications suspectes
"""

import os
import asyncio
import logging
from typing import Dict, List, Set, Optional, Callable, Any
from datetime import datetime
from collections import defaultdict

from .os_detector import system_access, OSType

logger = logging.getLogger(__name__)

class RegistryMonitor:
    """Surveillance du registre Windows pour détecter les modifications suspectes"""
    
    def __init__(self):
        self.os_type = system_access.os_type
        self.is_monitoring = False
        self.registry_callbacks: List[Callable] = []
        self.monitored_keys: Set[str] = set()
        self.registry_history: Dict[str, List[Dict]] = defaultdict(list)
        
        # Clés de registre critiques pour la persistence
        self.critical_keys = [
            # Auto-démarrage utilisateur
            r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices",
            r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
            
            # Auto-démarrage système
            r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices",
            r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
            r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
            
            # Services
            r"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services",
            
            # Winlogon
            r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
            
            # Image File Execution Options (détournement de processus)
            r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
            
            # Browser Helper Objects
            r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
            r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
            
            # Shell Extensions
            r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
            
            # AppInit DLLs
            r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows",
            
            # Scheduled Tasks
            r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache",
            
            # Firewall
            r"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy",
            
            # Windows Defender
            r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Defender",
            r"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender"
        ]
        
        self._setup_monitoring()
    
    def _setup_monitoring(self):
        """Configurer la surveillance du registre"""
        if self.os_type != OSType.WINDOWS:
            logger.info("Surveillance registre non disponible sur cet OS")
            return
            
        try:
            import winreg
            import win32api
            import win32con
            import win32event
            self.winreg = winreg
            self.win32api = win32api
            self.win32con = win32con
            self.win32event = win32event
            self.registry_available = True
        except ImportError:
            logger.warning("Modules Windows non disponibles pour la surveillance registre")
            self.registry_available = False
    
    async def start_monitoring(self, keys: Optional[List[str]] = None):
        """Démarrer la surveillance du registre"""
        if self.os_type != OSType.WINDOWS:
            logger.warning("Surveillance registre disponible uniquement sur Windows")
            return
            
        if not self.registry_available:
            logger.error("Modules Windows requis non installés")
            return
            
        if self.is_monitoring:
            return
            
        self.is_monitoring = True
        
        # Utiliser les clés critiques par défaut
        if not keys:
            keys = self.critical_keys
            
        self.monitored_keys = set(keys)
        
        logger.info(f"🔍 Démarrage surveillance registre sur {len(self.monitored_keys)} clés")
        
        # Lancer la surveillance pour chaque clé
        for key_path in self.monitored_keys:
            asyncio.create_task(self._monitor_registry_key(key_path))
    
    async def _monitor_registry_key(self, key_path: str):
        """Surveiller une clé de registre spécifique"""
        hkey_map = {
            'HKEY_CURRENT_USER': self.winreg.HKEY_CURRENT_USER,
            'HKEY_LOCAL_MACHINE': self.winreg.HKEY_LOCAL_MACHINE,
            'HKEY_CLASSES_ROOT': self.winreg.HKEY_CLASSES_ROOT,
            'HKEY_USERS': self.winreg.HKEY_USERS,
            'HKEY_CURRENT_CONFIG': self.winreg.HKEY_CURRENT_CONFIG
        }
        
        # Parser le chemin
        parts = key_path.split('\\')
        hkey_name = parts[0]
        subkey_path = '\\'.join(parts[1:])
        
        if hkey_name not in hkey_map:
            logger.error(f"Clé racine invalide: {hkey_name}")
            return
            
        hkey = hkey_map[hkey_name]
        
        # Capturer l'état initial
        initial_state = await self._capture_registry_state(hkey, subkey_path)
        
        while self.is_monitoring:
            try:
                # Créer un événement pour la notification
                event = self.win32event.CreateEvent(None, 0, 0, None)
                
                # Ouvrir la clé
                key = self.winreg.OpenKey(hkey, subkey_path, 0, 
                                         self.winreg.KEY_READ | self.winreg.KEY_NOTIFY)
                
                # S'abonner aux changements
                self.win32api.RegNotifyChangeKeyValue(
                    key,
                    True,  # Surveiller les sous-clés
                    self.win32con.REG_NOTIFY_CHANGE_NAME |
                    self.win32con.REG_NOTIFY_CHANGE_ATTRIBUTES |
                    self.win32con.REG_NOTIFY_CHANGE_LAST_SET |
                    self.win32con.REG_NOTIFY_CHANGE_SECURITY,
                    event,
                    True  # Asynchrone
                )
                
                # Attendre le changement
                result = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: self.win32event.WaitForSingleObject(event, 5000)  # 5 secondes timeout
                )
                
                if result == self.win32con.WAIT_OBJECT_0:
                    # Changement détecté
                    current_state = await self._capture_registry_state(hkey, subkey_path)
                    changes = self._compare_registry_states(initial_state, current_state)
                    
                    if changes:
                        await self._handle_registry_changes(key_path, changes)
                        initial_state = current_state
                
                # Fermer les handles
                self.winreg.CloseKey(key)
                self.win32api.CloseHandle(event)
                
            except Exception as e:
                logger.error(f"Erreur surveillance {key_path}: {e}")
                await asyncio.sleep(10)
    
    async def _capture_registry_state(self, hkey, subkey_path: str) -> Dict:
        """Capturer l'état actuel d'une clé de registre"""
        state = {
            'values': {},
            'subkeys': []
        }
        
        try:
            key = self.winreg.OpenKey(hkey, subkey_path, 0, self.winreg.KEY_READ)
            
            # Énumérer les valeurs
            index = 0
            while True:
                try:
                    name, value, reg_type = self.winreg.EnumValue(key, index)
                    state['values'][name] = {
                        'value': value,
                        'type': reg_type
                    }
                    index += 1
                except WindowsError:
                    break
            
            # Énumérer les sous-clés
            index = 0
            while True:
                try:
                    subkey = self.winreg.EnumKey(key, index)
                    state['subkeys'].append(subkey)
                    index += 1
                except WindowsError:
                    break
            
            self.winreg.CloseKey(key)
            
        except Exception as e:
            logger.debug(f"Erreur capture état registre: {e}")
            
        return state
    
    def _compare_registry_states(self, old_state: Dict, new_state: Dict) -> List[Dict]:
        """Comparer deux états de registre et détecter les changements"""
        changes = []
        
        # Valeurs ajoutées
        for name, data in new_state['values'].items():
            if name not in old_state['values']:
                changes.append({
                    'type': 'value_added',
                    'name': name,
                    'value': data['value'],
                    'reg_type': data['type']
                })
        
        # Valeurs modifiées
        for name, data in new_state['values'].items():
            if name in old_state['values']:
                old_data = old_state['values'][name]
                if data['value'] != old_data['value']:
                    changes.append({
                        'type': 'value_modified',
                        'name': name,
                        'old_value': old_data['value'],
                        'new_value': data['value'],
                        'reg_type': data['type']
                    })
        
        # Valeurs supprimées
        for name in old_state['values']:
            if name not in new_state['values']:
                changes.append({
                    'type': 'value_deleted',
                    'name': name,
                    'value': old_state['values'][name]['value']
                })
        
        # Sous-clés ajoutées
        new_subkeys = set(new_state['subkeys']) - set(old_state['subkeys'])
        for subkey in new_subkeys:
            changes.append({
                'type': 'subkey_added',
                'name': subkey
            })
        
        # Sous-clés supprimées
        deleted_subkeys = set(old_state['subkeys']) - set(new_state['subkeys'])
        for subkey in deleted_subkeys:
            changes.append({
                'type': 'subkey_deleted',
                'name': subkey
            })
        
        return changes
    
    async def _handle_registry_changes(self, key_path: str, changes: List[Dict]):
        """Gérer les changements de registre détectés"""
        for change in changes:
            # Créer l'événement
            event = {
                'timestamp': datetime.now().isoformat(),
                'key_path': key_path,
                'change': change,
                'suspicious': self._is_suspicious_change(key_path, change)
            }
            
            # Ajouter à l'historique
            self.registry_history[key_path].append(event)
            
            # Limiter l'historique
            if len(self.registry_history[key_path]) > 100:
                self.registry_history[key_path] = self.registry_history[key_path][-100:]
            
            # Logger si suspect
            if event['suspicious']:
                logger.warning(f"⚠️ Modification registre suspecte: {key_path}")
                logger.warning(f"   Changement: {change}")
            
            # Notifier les callbacks
            for callback in self.registry_callbacks:
                try:
                    await callback(event)
                except Exception as e:
                    logger.error(f"Erreur callback registre: {e}")
    
    def _is_suspicious_change(self, key_path: str, change: Dict) -> bool:
        """Déterminer si un changement est suspect"""
        # Toute modification dans les clés critiques est suspecte
        if any(critical in key_path for critical in [
            'Run', 'RunOnce', 'Services', 'Winlogon', 
            'Image File Execution Options', 'Browser Helper Objects',
            'AppInit', 'Windows Defender'
        ]):
            # Vérifier le contenu
            if change['type'] in ['value_added', 'value_modified']:
                value = change.get('new_value', change.get('value', '')).lower()
                
                # Patterns suspects
                suspicious_patterns = [
                    'powershell', 'cmd', 'wscript', 'cscript', 'mshta',
                    'rundll32', 'regsvr32', 'certutil', 'bitsadmin',
                    'base64', 'downloadstring', 'downloadfile',
                    'invoke-expression', 'iex', 'bypass', 'hidden',
                    '.ps1', '.bat', '.cmd', '.vbs', '.js',
                    'temp\\', 'appdata\\', 'programdata\\',
                    'http://', 'https://', 'ftp://',
                    'disable', 'tamper', 'exclusion'
                ]
                
                if any(pattern in value for pattern in suspicious_patterns):
                    return True
            
            # Toute suppression dans Windows Defender est suspecte
            if 'Windows Defender' in key_path and change['type'] == 'value_deleted':
                return True
        
        return False
    
    def add_callback(self, callback: Callable):
        """Ajouter un callback pour les événements registre"""
        self.registry_callbacks.append(callback)
    
    def add_monitored_key(self, key_path: str):
        """Ajouter une clé à surveiller"""
        if key_path not in self.monitored_keys:
            self.monitored_keys.add(key_path)
            if self.is_monitoring:
                asyncio.create_task(self._monitor_registry_key(key_path))
    
    def get_registry_history(self, key_path: str) -> List[Dict]:
        """Obtenir l'historique d'une clé"""
        return self.registry_history.get(key_path, [])
    
    async def stop_monitoring(self):
        """Arrêter la surveillance"""
        self.is_monitoring = False
        logger.info("🛑 Surveillance registre arrêtée")
    
    def get_monitoring_stats(self) -> Dict[str, Any]:
        """Obtenir les statistiques de surveillance"""
        total_events = sum(len(events) for events in self.registry_history.values())
        suspicious_events = sum(
            len([e for e in events if e.get('suspicious', False)])
            for events in self.registry_history.values()
        )
        
        return {
            'is_monitoring': self.is_monitoring,
            'monitored_keys_count': len(self.monitored_keys),
            'critical_keys_count': len(self.critical_keys),
            'total_events': total_events,
            'suspicious_events': suspicious_events,
            'events_by_key': {
                key: len(events) for key, events in self.registry_history.items()
            },
            'last_events': {
                key: events[-5:] if events else [] 
                for key, events in self.registry_history.items()
            }
        }

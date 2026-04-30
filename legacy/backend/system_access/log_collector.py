"""
Collecteur de logs système multi-OS
Analyse temps réel des événements système
"""

import os
import asyncio
import logging
import json
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime, timedelta
from collections import defaultdict
import subprocess

from .os_detector import system_access, OSType

logger = logging.getLogger(__name__)

class SystemLogCollector:
    """Collecteur et analyseur de logs système"""
    
    def __init__(self):
        self.os_type = system_access.os_type
        self.is_collecting = False
        self.log_callbacks: List[Callable] = []
        self.log_buffer = []
        self.suspicious_patterns = []
        self.event_stats = defaultdict(int)
        
        # Patterns suspects par catégorie
        self.suspicious_patterns = {
            'authentication': [
                'failed login', 'authentication failure', 'invalid user',
                'failed password', 'account locked', 'brute force'
            ],
            'privilege_escalation': [
                'privilege escalation', 'sudo', 'su root', 'runas',
                'sedebugtokenprivilege', 'setcbprivilege'
            ],
            'persistence': [
                'service installed', 'scheduled task created', 'registry modified',
                'startup folder', 'cron job added'
            ],
            'defense_evasion': [
                'log cleared', 'audit disabled', 'firewall disabled',
                'defender disabled', 'antivirus stopped'
            ],
            'lateral_movement': [
                'remote desktop', 'ssh connection', 'smb share', 'wmi',
                'psexec', 'remote shell'
            ],
            'process_injection': [
                'code injection', 'dll injection', 'process hollowing',
                'reflective dll', 'setwindowshook'
            ],
            'data_exfiltration': [
                'large data transfer', 'unusual network', 'archive created',
                'ftp transfer', 'cloud upload'
            ]
        }
        
        self._setup_log_sources()
    
    def _setup_log_sources(self):
        """Configurer les sources de logs selon l'OS"""
        if self.os_type == OSType.WINDOWS:
            self.log_sources = {
                'Security': ['Security'],
                'System': ['System'],
                'Application': ['Application'],
                'PowerShell': ['Microsoft-Windows-PowerShell/Operational'],
                'Sysmon': ['Microsoft-Windows-Sysmon/Operational'],
                'Defender': ['Microsoft-Windows-Windows Defender/Operational'],
                'WMI': ['Microsoft-Windows-WMI-Activity/Operational']
            }
        elif self.os_type == OSType.LINUX:
            self.log_sources = {
                'auth': ['/var/log/auth.log', '/var/log/secure'],
                'syslog': ['/var/log/syslog', '/var/log/messages'],
                'kernel': ['/var/log/kern.log', '/var/log/dmesg'],
                'audit': ['/var/log/audit/audit.log'],
                'apache': ['/var/log/apache2/access.log', '/var/log/httpd/access_log'],
                'nginx': ['/var/log/nginx/access.log']
            }
        elif self.os_type == OSType.MACOS:
            self.log_sources = {
                'system': ['system.log'],
                'security': ['security.log'],
                'install': ['install.log']
            }
    
    async def start_collecting(self):
        """Démarrer la collecte de logs"""
        if self.is_collecting:
            return
            
        self.is_collecting = True
        logger.info("🔍 Démarrage de la collecte de logs système")
        
        if self.os_type == OSType.WINDOWS:
            asyncio.create_task(self._collect_windows_logs())
        elif self.os_type == OSType.LINUX:
            asyncio.create_task(self._collect_linux_logs())
        elif self.os_type == OSType.MACOS:
            asyncio.create_task(self._collect_macos_logs())
        
        # Lancer l'analyse
        asyncio.create_task(self._analyze_logs())
    
    async def _collect_windows_logs(self):
        """Collecter les logs Windows Event Log"""
        try:
            import win32evtlog
            import win32evtlogutil
            import win32con
            self.win32evtlog = win32evtlog
            self.win32evtlogutil = win32evtlogutil
        except ImportError:
            logger.error("pywin32 requis pour la collecte de logs Windows")
            return
        
        while self.is_collecting:
            try:
                for category, sources in self.log_sources.items():
                    for source in sources:
                        try:
                            # Ouvrir le log
                            hand = self.win32evtlog.OpenEventLog(None, source)
                            flags = self.win32evtlog.EVENTLOG_BACKWARDS_READ | \
                                   self.win32evtlog.EVENTLOG_SEQUENTIAL_READ
                            
                            # Lire les événements récents
                            events = self.win32evtlog.ReadEventLog(hand, flags, 0)
                            
                            for event in events:
                                # Filtrer les événements récents (dernières 5 minutes)
                                event_time = datetime.fromtimestamp(event.TimeGenerated)
                                if datetime.now() - event_time < timedelta(minutes=5):
                                    log_entry = {
                                        'timestamp': event_time.isoformat(),
                                        'source': source,
                                        'category': category,
                                        'event_id': event.EventID,
                                        'event_type': event.EventType,
                                        'message': win32evtlogutil.SafeFormatMessage(event, source),
                                        'computer': event.ComputerName,
                                        'user': event.Sid
                                    }
                                    
                                    await self._process_log_entry(log_entry)
                            
                            self.win32evtlog.CloseEventLog(hand)
                            
                        except Exception as e:
                            logger.debug(f"Erreur lecture {source}: {e}")
                
                await asyncio.sleep(10)  # Vérifier toutes les 10 secondes
                
            except Exception as e:
                logger.error(f"Erreur collecte logs Windows: {e}")
                await asyncio.sleep(30)
    
    async def _collect_linux_logs(self):
        """Collecter les logs Linux"""
        # Suivre les fichiers de log
        tail_processes = {}
        
        try:
            for category, paths in self.log_sources.items():
                for path in paths:
                    if os.path.exists(path) and os.access(path, os.R_OK):
                        # Lancer tail -f pour suivre le fichier
                        process = subprocess.Popen(
                            ['tail', '-f', '-n', '0', path],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            universal_newlines=True
                        )
                        tail_processes[path] = (process, category)
            
            # Lire les nouvelles lignes
            while self.is_collecting and tail_processes:
                for path, (process, category) in list(tail_processes.items()):
                    try:
                        # Lire de manière non-bloquante
                        line = process.stdout.readline()
                        if line:
                            log_entry = {
                                'timestamp': datetime.now().isoformat(),
                                'source': path,
                                'category': category,
                                'message': line.strip(),
                                'raw': line
                            }
                            
                            # Parser les formats de log communs
                            parsed = self._parse_linux_log(line, category)
                            if parsed:
                                log_entry.update(parsed)
                            
                            await self._process_log_entry(log_entry)
                        
                        # Vérifier si le processus est toujours actif
                        if process.poll() is not None:
                            logger.warning(f"Tail terminé pour {path}")
                            del tail_processes[path]
                            
                    except Exception as e:
                        logger.error(f"Erreur lecture {path}: {e}")
                
                await asyncio.sleep(0.1)
                
        finally:
            # Terminer tous les processus tail
            for path, (process, _) in tail_processes.items():
                try:
                    process.terminate()
                except:
                    pass
    
    async def _collect_macos_logs(self):
        """Collecter les logs macOS"""
        while self.is_collecting:
            try:
                # Utiliser log show pour les logs récents
                cmd = ['log', 'show', '--last', '5m', '--style', 'json']
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    try:
                        logs = json.loads(result.stdout)
                        for log in logs:
                            log_entry = {
                                'timestamp': log.get('timestamp', ''),
                                'source': log.get('subsystem', ''),
                                'category': log.get('category', ''),
                                'message': log.get('eventMessage', ''),
                                'process': log.get('processImagePath', ''),
                                'pid': log.get('processID', 0)
                            }
                            
                            await self._process_log_entry(log_entry)
                            
                    except json.JSONDecodeError:
                        logger.error("Erreur parsing logs macOS")
                
                await asyncio.sleep(10)
                
            except Exception as e:
                logger.error(f"Erreur collecte logs macOS: {e}")
                await asyncio.sleep(30)
    
    def _parse_linux_log(self, line: str, category: str) -> Optional[Dict]:
        """Parser les formats de log Linux communs"""
        parsed = {}
        
        # Format syslog standard
        if category in ['syslog', 'auth']:
            # Ex: Jan 10 12:34:56 hostname process[pid]: message
            import re
            pattern = r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(\[\d+\])?:\s+(.*)$'
            match = re.match(pattern, line)
            if match:
                parsed['log_time'] = match.group(1)
                parsed['hostname'] = match.group(2)
                parsed['process'] = match.group(3)
                parsed['message'] = match.group(5)
        
        # Format audit
        elif category == 'audit':
            # Parser les événements audit
            if 'type=' in line:
                parts = line.split()
                for part in parts:
                    if '=' in part:
                        key, value = part.split('=', 1)
                        parsed[key] = value.strip('"')
        
        return parsed if parsed else None
    
    async def _process_log_entry(self, log_entry: Dict):
        """Traiter une entrée de log"""
        # Ajouter au buffer
        self.log_buffer.append(log_entry)
        
        # Limiter la taille du buffer
        if len(self.log_buffer) > 10000:
            self.log_buffer = self.log_buffer[-10000:]
        
        # Détecter les patterns suspects
        suspicious = self._detect_suspicious_patterns(log_entry)
        if suspicious:
            log_entry['suspicious'] = True
            log_entry['threat_categories'] = suspicious
            
            logger.warning(f"⚠️ Log suspect détecté: {suspicious}")
            logger.warning(f"   Message: {log_entry.get('message', '')[:100]}...")
        
        # Mettre à jour les statistiques
        self.event_stats[log_entry.get('category', 'unknown')] += 1
        if log_entry.get('event_id'):
            self.event_stats[f"event_{log_entry['event_id']}"] += 1
        
        # Notifier les callbacks
        for callback in self.log_callbacks:
            try:
                await callback(log_entry)
            except Exception as e:
                logger.error(f"Erreur callback log: {e}")
    
    def _detect_suspicious_patterns(self, log_entry: Dict) -> List[str]:
        """Détecter les patterns suspects dans un log"""
        message = log_entry.get('message', '').lower()
        detected_categories = []
        
        for category, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                if pattern in message:
                    detected_categories.append(category)
                    break
        
        # Patterns spécifiques aux event IDs Windows
        if self.os_type == OSType.WINDOWS:
            event_id = log_entry.get('event_id', 0)
            
            # Event IDs suspects connus
            suspicious_events = {
                1102: 'defense_evasion',  # Log cleared
                4624: 'authentication',   # Logon
                4625: 'authentication',   # Failed logon
                4648: 'lateral_movement', # Explicit logon
                4672: 'privilege_escalation', # Special privileges
                4688: 'process_creation', # Process creation
                4697: 'persistence',      # Service installed
                4698: 'persistence',      # Scheduled task created
                4720: 'persistence',      # User account created
                4732: 'persistence',      # User added to group
                5140: 'lateral_movement', # Network share accessed
                5145: 'lateral_movement', # Network share object checked
                7045: 'persistence'       # Service installed
            }
            
            if event_id in suspicious_events:
                detected_categories.append(suspicious_events[event_id])
        
        return list(set(detected_categories))
    
    async def _analyze_logs(self):
        """Analyser les logs collectés"""
        while self.is_collecting:
            try:
                # Analyser les patterns temporels
                await self._analyze_temporal_patterns()
                
                # Détecter les anomalies
                await self._detect_log_anomalies()
                
                await asyncio.sleep(30)  # Analyse toutes les 30 secondes
                
            except Exception as e:
                logger.error(f"Erreur analyse logs: {e}")
                await asyncio.sleep(60)
    
    async def _analyze_temporal_patterns(self):
        """Analyser les patterns temporels dans les logs"""
        # Regrouper les événements par fenêtre temporelle
        time_windows = defaultdict(list)
        
        for log in self.log_buffer[-1000:]:  # Derniers 1000 logs
            timestamp = log.get('timestamp', '')
            if timestamp:
                # Arrondir à la minute
                try:
                    dt = datetime.fromisoformat(timestamp)
                    window = dt.replace(second=0, microsecond=0)
                    time_windows[window].append(log)
                except:
                    pass
        
        # Détecter les rafales d'événements
        for window, logs in time_windows.items():
            if len(logs) > 100:  # Plus de 100 événements par minute
                # Analyser le type d'événements
                event_types = defaultdict(int)
                for log in logs:
                    event_types[log.get('category', 'unknown')] += 1
                
                # Alerte si pattern suspect
                if any(count > 50 for count in event_types.values()):
                    await self._notify_callbacks({
                        'event': 'log_burst_detected',
                        'window': window.isoformat(),
                        'total_events': len(logs),
                        'event_types': dict(event_types),
                        'severity': 'medium'
                    })
    
    async def _detect_log_anomalies(self):
        """Détecter les anomalies dans les logs"""
        # Détecter les tentatives de brute force
        failed_auth = [
            log for log in self.log_buffer[-500:]
            if 'authentication' in log.get('threat_categories', [])
        ]
        
        if len(failed_auth) > 10:
            # Grouper par source
            sources = defaultdict(int)
            for log in failed_auth:
                source = log.get('computer', log.get('hostname', 'unknown'))
                sources[source] += 1
            
            # Alerte si une source a trop d'échecs
            for source, count in sources.items():
                if count > 5:
                    await self._notify_callbacks({
                        'event': 'brute_force_detected',
                        'source': source,
                        'failed_attempts': count,
                        'severity': 'high'
                    })
    
    async def _notify_callbacks(self, event: Dict):
        """Notifier les callbacks"""
        event['timestamp'] = datetime.now().isoformat()
        event['type'] = 'system_log'
        
        for callback in self.log_callbacks:
            try:
                await callback(event)
            except Exception as e:
                logger.error(f"Erreur callback: {e}")
    
    def add_callback(self, callback: Callable):
        """Ajouter un callback pour les événements log"""
        self.log_callbacks.append(callback)
    
    def get_recent_logs(self, count: int = 100, category: Optional[str] = None) -> List[Dict]:
        """Obtenir les logs récents"""
        logs = self.log_buffer[-count:]
        
        if category:
            logs = [log for log in logs if log.get('category') == category]
        
        return logs
    
    def get_statistics(self) -> Dict[str, Any]:
        """Obtenir les statistiques de logs"""
        return {
            'total_logs': len(self.log_buffer),
            'event_stats': dict(self.event_stats),
            'suspicious_count': sum(1 for log in self.log_buffer if log.get('suspicious')),
            'categories': list(set(log.get('category', 'unknown') for log in self.log_buffer))
        }
    
    async def search_logs(self, query: str, limit: int = 100) -> List[Dict]:
        """Rechercher dans les logs"""
        query_lower = query.lower()
        results = []
        
        for log in reversed(self.log_buffer):
            if query_lower in log.get('message', '').lower():
                results.append(log)
                if len(results) >= limit:
                    break
        
        return results
    
    async def stop_collecting(self):
        """Arrêter la collecte"""
        self.is_collecting = False
        logger.info("🛑 Collecte de logs arrêtée")

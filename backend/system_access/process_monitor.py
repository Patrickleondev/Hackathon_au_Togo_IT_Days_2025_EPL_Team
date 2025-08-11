"""
Moniteur de processus temps réel avec détection d'anomalies
Surveillance avancée des processus et injections
"""

import os
import asyncio
import logging
import psutil
import hashlib
from typing import Dict, List, Set, Optional, Callable
from datetime import datetime
from collections import defaultdict
import json

from .os_detector import system_access, OSType

logger = logging.getLogger(__name__)

class ProcessMonitor:
    """Surveillance avancée des processus avec détection de comportements malveillants"""
    
    def __init__(self):
        self.os_type = system_access.os_type
        self.is_monitoring = False
        self.process_callbacks: List[Callable] = []
        self.process_cache: Dict[int, Dict] = {}
        self.process_history: Dict[int, List[Dict]] = defaultdict(list)
        self.suspicious_processes: Set[int] = set()
        self.network_connections: Dict[int, List] = defaultdict(list)
        self.process_relationships: Dict[int, Set[int]] = defaultdict(set)
        
        # Processus légitimes connus
        self.legitimate_processes = {
            'windows': {
                'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
                'services.exe', 'lsass.exe', 'svchost.exe', 'explorer.exe',
                'taskhostw.exe', 'runtime broker.exe', 'searchindexer.exe'
            },
            'linux': {
                'systemd', 'init', 'kernel', 'kthreadd', 'kworker', 'ksoftirqd',
                'migration', 'rcu_', 'systemd-journald', 'systemd-logind',
                'systemd-networkd', 'systemd-resolved', 'sshd', 'cron'
            },
            'macos': {
                'kernel_task', 'launchd', 'UserEventAgent', 'SystemUIServer',
                'WindowServer', 'loginwindow', 'mdworker', 'mds', 'spotlight'
            }
        }
        
        # Comportements suspects
        self.suspicious_behaviors = {
            'process_injection': ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'],
            'privilege_escalation': ['SeDebugPrivilege', 'SeTcbPrivilege', 'SeAssignPrimaryTokenPrivilege'],
            'persistence': ['Registry', 'Startup', 'Schedule', 'Service'],
            'defense_evasion': ['AMSI', 'ETW', 'WMI', 'Defender'],
            'credential_access': ['lsass', 'SAM', 'NTDS', 'Mimikatz'],
            'discovery': ['net', 'whoami', 'ipconfig', 'systeminfo', 'tasklist'],
            'lateral_movement': ['psexec', 'wmic', 'winrm', 'rdp', 'ssh'],
            'command_control': ['powershell', 'cmd', 'wscript', 'cscript', 'mshta'],
            'exfiltration': ['compress', 'archive', 'upload', 'post', 'send'],
            'impact': ['encrypt', 'wipe', 'destroy', 'ransom', 'lock']
        }
        
        self._setup_os_specific()
    
    def _setup_os_specific(self):
        """Configuration spécifique à l'OS"""
        if self.os_type == OSType.WINDOWS:
            try:
                import wmi
                import win32api
                import win32con
                import win32process
                import win32security
                self.wmi_client = wmi.WMI()
                self.win32_available = True
            except ImportError:
                logger.warning("WMI/Win32 non disponible")
                self.win32_available = False
                
        elif self.os_type == OSType.LINUX:
            self.proc_path = "/proc"
            
        elif self.os_type == OSType.MACOS:
            # macOS specific setup
            pass
    
    async def start_monitoring(self):
        """Démarrer la surveillance des processus"""
        if self.is_monitoring:
            return
            
        self.is_monitoring = True
        logger.info("🔍 Démarrage de la surveillance des processus")
        
        # Scanner les processus existants
        await self._initial_process_scan()
        
        # Lancer la surveillance continue
        asyncio.create_task(self._monitor_processes())
        
        if self.os_type == OSType.WINDOWS and self.win32_available:
            asyncio.create_task(self._monitor_wmi_events())
    
    async def _initial_process_scan(self):
        """Scanner tous les processus existants"""
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time']):
            try:
                proc_info = await self._analyze_process(proc)
                self.process_cache[proc.pid] = proc_info
                
                # Détecter les processus suspects
                if self._is_suspicious_process(proc_info):
                    self.suspicious_processes.add(proc.pid)
                    await self._handle_suspicious_process(proc_info)
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    
    async def _monitor_processes(self):
        """Surveillance continue des processus"""
        known_pids = set(self.process_cache.keys())
        
        while self.is_monitoring:
            try:
                current_pids = set()
                
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        pid = proc.pid
                        current_pids.add(pid)
                        
                        # Nouveau processus
                        if pid not in known_pids:
                            proc_info = await self._analyze_process(proc)
                            self.process_cache[pid] = proc_info
                            
                            # Vérifier la légitimité
                            if self._is_suspicious_process(proc_info):
                                self.suspicious_processes.add(pid)
                                await self._handle_suspicious_process(proc_info)
                            
                            # Notifier les callbacks
                            await self._notify_callbacks({
                                'event': 'process_created',
                                'process': proc_info,
                                'timestamp': datetime.now().isoformat()
                            })
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # Processus terminés
                terminated_pids = known_pids - current_pids
                for pid in terminated_pids:
                    if pid in self.process_cache:
                        proc_info = self.process_cache[pid]
                        await self._notify_callbacks({
                            'event': 'process_terminated',
                            'process': proc_info,
                            'timestamp': datetime.now().isoformat()
                        })
                        del self.process_cache[pid]
                
                known_pids = current_pids
                
                # Analyser les comportements
                await self._analyze_process_behaviors()
                
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.error(f"Erreur surveillance processus: {e}")
                await asyncio.sleep(5)
    
    async def _analyze_process(self, proc) -> Dict:
        """Analyser un processus en détail"""
        try:
            with proc.oneshot():
                info = {
                    'pid': proc.pid,
                    'name': proc.name(),
                    'exe': proc.exe() if hasattr(proc, 'exe') else None,
                    'cmdline': proc.cmdline() if hasattr(proc, 'cmdline') else [],
                    'create_time': proc.create_time(),
                    'username': proc.username() if hasattr(proc, 'username') else None,
                    'status': proc.status() if hasattr(proc, 'status') else None,
                    'ppid': proc.ppid() if hasattr(proc, 'ppid') else None,
                    'children': [p.pid for p in proc.children(recursive=True)],
                    'num_threads': proc.num_threads() if hasattr(proc, 'num_threads') else 0,
                    'cpu_percent': proc.cpu_percent(),
                    'memory_info': proc.memory_info()._asdict() if hasattr(proc, 'memory_info') else {},
                    'connections': [],
                    'open_files': [],
                    'suspicious_score': 0,
                    'behaviors': []
                }
                
                # Connexions réseau
                try:
                    connections = proc.connections()
                    info['connections'] = [
                        {
                            'fd': c.fd,
                            'family': c.family,
                            'type': c.type,
                            'laddr': f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                            'raddr': f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                            'status': c.status
                        }
                        for c in connections
                    ]
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                
                # Fichiers ouverts
                try:
                    open_files = proc.open_files()
                    info['open_files'] = [f.path for f in open_files]
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                
                # Hash de l'exécutable
                if info['exe'] and os.path.exists(info['exe']):
                    try:
                        info['exe_hash'] = await self._calculate_file_hash(info['exe'])
                    except:
                        info['exe_hash'] = None
                
                # Analyse spécifique OS
                if self.os_type == OSType.WINDOWS:
                    await self._analyze_windows_process(info, proc)
                elif self.os_type == OSType.LINUX:
                    await self._analyze_linux_process(info, proc)
                
                return info
                
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return {'pid': proc.pid, 'error': str(e)}
    
    async def _analyze_windows_process(self, info: Dict, proc):
        """Analyse spécifique Windows"""
        if not self.win32_available:
            return
            
        try:
            import win32api
            import win32process
            import win32security
            
            # Obtenir le handle du processus
            handle = win32api.OpenProcess(
                win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ,
                False,
                info['pid']
            )
            
            # Privilèges
            token = win32security.OpenProcessToken(handle, win32con.TOKEN_QUERY)
            privileges = win32security.GetTokenInformation(
                token, win32security.TokenPrivileges
            )
            info['privileges'] = [
                win32security.LookupPrivilegeName(None, priv[0])
                for priv in privileges
            ]
            
            # Vérifier les injections
            if self._check_process_injection_windows(info):
                info['behaviors'].append('possible_injection')
                info['suspicious_score'] += 50
                
        except Exception as e:
            logger.debug(f"Erreur analyse Windows: {e}")
    
    async def _analyze_linux_process(self, info: Dict, proc):
        """Analyse spécifique Linux"""
        try:
            proc_path = f"/proc/{info['pid']}"
            
            # Lire les maps pour détecter les injections
            maps_path = f"{proc_path}/maps"
            if os.path.exists(maps_path):
                with open(maps_path, 'r') as f:
                    maps_content = f.read()
                    
                    # Chercher des régions mémoire suspectes
                    if 'rwxp' in maps_content:  # Read-Write-Execute
                        info['behaviors'].append('rwx_memory')
                        info['suspicious_score'] += 30
                    
                    # Chercher des bibliothèques injectées
                    if '/tmp/' in maps_content or '/dev/shm/' in maps_content:
                        info['behaviors'].append('tmp_library')
                        info['suspicious_score'] += 20
            
            # Vérifier les capacités
            status_path = f"{proc_path}/status"
            if os.path.exists(status_path):
                with open(status_path, 'r') as f:
                    for line in f:
                        if line.startswith('CapEff:'):
                            cap_hex = line.split()[1]
                            capabilities = int(cap_hex, 16)
                            if capabilities & 0xFFFFFFFF:  # Capacités élevées
                                info['behaviors'].append('elevated_capabilities')
                                info['suspicious_score'] += 25
                                
        except Exception as e:
            logger.debug(f"Erreur analyse Linux: {e}")
    
    def _is_suspicious_process(self, proc_info: Dict) -> bool:
        """Déterminer si un processus est suspect"""
        if proc_info.get('error'):
            return False
            
        name = proc_info['name'].lower()
        exe = proc_info.get('exe', '').lower()
        cmdline = ' '.join(proc_info.get('cmdline', [])).lower()
        
        # Score de suspicion
        score = proc_info.get('suspicious_score', 0)
        
        # Nom suspect
        suspicious_names = [
            'powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'rundll32',
            'regsvr32', 'certutil', 'bitsadmin', 'psexec', 'wmic',
            'net', 'sc', 'schtasks', 'at', 'bcdedit', 'wevtutil',
            'cipher', 'conhost', 'consent', 'cvtres', 'dllhost',
            'driverquery', 'dsget', 'dsquery', 'forfiles', 'makecab',
            'netsh', 'nltest', 'nslookup', 'ntdsutil', 'pcalua',
            'ping', 'qprocess', 'qwinsta', 'reg', 'regasm', 'regedit',
            'replace', 'rpcping', 'rundll', 'schtask', 'systeminfo',
            'taskkill', 'tasklist', 'tracert', 'vssadmin', 'wbadmin',
            'whoami', 'winrm', 'winrs', 'wusa'
        ]
        
        if any(susp in name for susp in suspicious_names):
            score += 20
        
        # Commande suspecte
        suspicious_commands = [
            '-enc', '-encoded', 'bypass', 'hidden', 'noprofile',
            'invoke-expression', 'iex', 'downloadstring', 'downloadfile',
            'net.webclient', 'bitstransfer', 'curl', 'wget',
            'base64', 'compress', 'decompress', 'encrypt', 'decrypt',
            '/c', '/k', '/r', '/s', '/q', '/v:off', 'echo off'
        ]
        
        if any(cmd in cmdline for cmd in suspicious_commands):
            score += 30
        
        # Processus sans chemin
        if not exe or exe == name:
            score += 15
        
        # Processus dans des emplacements suspects
        suspicious_paths = ['/tmp/', '/var/tmp/', '/dev/shm/', 'temp\\', 'appdata\\local\\temp']
        if any(path in exe for path in suspicious_paths):
            score += 25
        
        # Parent suspect
        if proc_info.get('ppid'):
            parent_name = self.process_cache.get(proc_info['ppid'], {}).get('name', '').lower()
            if parent_name in ['explorer.exe', 'svchost.exe'] and name in suspicious_names:
                score += 20
        
        # Connexions réseau suspectes
        for conn in proc_info.get('connections', []):
            if conn.get('raddr'):
                # Connexion vers des ports suspects
                raddr = conn['raddr']
                if ':' in raddr:
                    port = int(raddr.split(':')[1])
                    if port in [1337, 4444, 8080, 8888, 9999, 31337]:
                        score += 30
        
        # Comportements détectés
        behaviors = proc_info.get('behaviors', [])
        if 'possible_injection' in behaviors:
            score += 50
        if 'rwx_memory' in behaviors:
            score += 30
        if 'elevated_capabilities' in behaviors:
            score += 25
        
        proc_info['suspicious_score'] = score
        
        # Seuil de suspicion
        return score >= 50
    
    def _check_process_injection_windows(self, proc_info: Dict) -> bool:
        """Vérifier les signes d'injection de processus sur Windows"""
        if not self.win32_available:
            return False
            
        try:
            # Vérifier les threads créés à distance
            for child_pid in proc_info.get('children', []):
                child = self.process_cache.get(child_pid, {})
                if child.get('name', '').lower() in ['svchost.exe', 'explorer.exe']:
                    return True
            
            # Vérifier les DLL suspectes
            suspicious_dlls = ['vaultcli.dll', 'samlib.dll', 'wdigest.dll']
            for file in proc_info.get('open_files', []):
                if any(dll in file.lower() for dll in suspicious_dlls):
                    return True
                    
        except Exception:
            pass
            
        return False
    
    async def _analyze_process_behaviors(self):
        """Analyser les comportements des processus"""
        for pid, proc_info in list(self.process_cache.items()):
            if proc_info.get('error'):
                continue
                
            # Analyser les patterns de communication
            connections = proc_info.get('connections', [])
            if connections:
                # Détecter le beaconing C2
                if self._detect_c2_beaconing(pid, connections):
                    proc_info['behaviors'].append('c2_beaconing')
                    proc_info['suspicious_score'] += 40
                    self.suspicious_processes.add(pid)
                
                # Détecter l'exfiltration
                if self._detect_data_exfiltration(pid, connections):
                    proc_info['behaviors'].append('data_exfiltration')
                    proc_info['suspicious_score'] += 35
                    self.suspicious_processes.add(pid)
            
            # Analyser l'arbre de processus
            if self._detect_process_tree_anomaly(pid):
                proc_info['behaviors'].append('anomalous_tree')
                proc_info['suspicious_score'] += 25
                self.suspicious_processes.add(pid)
    
    def _detect_c2_beaconing(self, pid: int, connections: List[Dict]) -> bool:
        """Détecter les patterns de communication C2"""
        # Stocker l'historique des connexions
        current_time = datetime.now()
        self.network_connections[pid].append({
            'time': current_time,
            'connections': connections
        })
        
        # Garder seulement les 5 dernières minutes
        self.network_connections[pid] = [
            c for c in self.network_connections[pid]
            if (current_time - c['time']).seconds < 300
        ]
        
        # Analyser les patterns
        if len(self.network_connections[pid]) < 3:
            return False
        
        # Chercher des intervalles réguliers
        intervals = []
        for i in range(1, len(self.network_connections[pid])):
            delta = (self.network_connections[pid][i]['time'] - 
                    self.network_connections[pid][i-1]['time']).seconds
            intervals.append(delta)
        
        if intervals:
            # Vérifier si les intervalles sont réguliers (variance faible)
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
            
            # Beaconing détecté si variance < 10% de la moyenne
            if variance < (avg_interval * 0.1) ** 2:
                return True
        
        return False
    
    def _detect_data_exfiltration(self, pid: int, connections: List[Dict]) -> bool:
        """Détecter l'exfiltration de données"""
        # Analyser le volume de données sortantes
        try:
            proc = psutil.Process(pid)
            io_counters = proc.io_counters()
            
            # Ratio écriture/lecture élevé
            if io_counters.read_bytes > 0:
                write_read_ratio = io_counters.write_bytes / io_counters.read_bytes
                if write_read_ratio > 10:  # 10x plus d'écriture que de lecture
                    return True
            
            # Beaucoup de données vers l'extérieur
            external_connections = [
                c for c in connections 
                if c.get('raddr') and not self._is_local_address(c['raddr'])
            ]
            
            if len(external_connections) > 0 and io_counters.write_bytes > 100 * 1024 * 1024:  # 100MB
                return True
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        
        return False
    
    def _detect_process_tree_anomaly(self, pid: int) -> bool:
        """Détecter les anomalies dans l'arbre de processus"""
        proc_info = self.process_cache.get(pid, {})
        
        if not proc_info.get('ppid'):
            return False
        
        parent = self.process_cache.get(proc_info['ppid'], {})
        if not parent:
            return False
        
        # Vérifier les relations parent-enfant suspectes
        suspicious_relationships = [
            ('explorer.exe', 'powershell.exe'),
            ('winword.exe', 'cmd.exe'),
            ('excel.exe', 'wscript.exe'),
            ('outlook.exe', 'mshta.exe'),
            ('firefox.exe', 'rundll32.exe'),
            ('chrome.exe', 'regsvr32.exe')
        ]
        
        parent_name = parent.get('name', '').lower()
        child_name = proc_info.get('name', '').lower()
        
        for p, c in suspicious_relationships:
            if p in parent_name and c in child_name:
                return True
        
        return False
    
    def _is_local_address(self, addr: str) -> bool:
        """Vérifier si une adresse est locale"""
        if ':' in addr:
            ip = addr.split(':')[0]
            return ip.startswith('127.') or ip.startswith('192.168.') or \
                   ip.startswith('10.') or ip.startswith('172.')
        return False
    
    async def _calculate_file_hash(self, path: str) -> Optional[str]:
        """Calculer le hash SHA256 d'un fichier"""
        try:
            sha256_hash = hashlib.sha256()
            with open(path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except:
            return None
    
    async def _handle_suspicious_process(self, proc_info: Dict):
        """Gérer un processus suspect"""
        logger.warning(f"⚠️ Processus suspect détecté: {proc_info['name']} (PID: {proc_info['pid']})")
        logger.warning(f"   Score de suspicion: {proc_info['suspicious_score']}")
        logger.warning(f"   Comportements: {proc_info['behaviors']}")
        
        # Notifier via callback
        await self._notify_callbacks({
            'event': 'suspicious_process_detected',
            'process': proc_info,
            'timestamp': datetime.now().isoformat(),
            'severity': 'high' if proc_info['suspicious_score'] > 70 else 'medium'
        })
    
    async def _notify_callbacks(self, event: Dict):
        """Notifier les callbacks"""
        for callback in self.process_callbacks:
            try:
                await callback(event)
            except Exception as e:
                logger.error(f"Erreur callback processus: {e}")
    
    async def _monitor_wmi_events(self):
        """Surveiller les événements WMI sur Windows"""
        if not self.win32_available:
            return
            
        try:
            # Surveiller la création de processus via WMI
            process_watcher = self.wmi_client.Win32_Process.watch_for("creation")
            
            while self.is_monitoring:
                try:
                    new_process = process_watcher(timeout_ms=1000)
                    if new_process:
                        logger.info(f"Nouveau processus WMI: {new_process.Name} (PID: {new_process.ProcessId})")
                except Exception:
                    pass
                    
                await asyncio.sleep(0.1)
                
        except Exception as e:
            logger.error(f"Erreur WMI: {e}")
    
    def add_callback(self, callback: Callable):
        """Ajouter un callback pour les événements processus"""
        self.process_callbacks.append(callback)
    
    def get_suspicious_processes(self) -> List[Dict]:
        """Obtenir la liste des processus suspects"""
        return [
            self.process_cache[pid]
            for pid in self.suspicious_processes
            if pid in self.process_cache
        ]
    
    def get_process_info(self, pid: int) -> Optional[Dict]:
        """Obtenir les informations d'un processus"""
        return self.process_cache.get(pid)
    
    def get_process_tree(self, pid: int) -> Dict:
        """Obtenir l'arbre de processus"""
        tree = {'process': self.process_cache.get(pid, {}), 'children': []}
        
        for child_pid in self.process_cache.get(pid, {}).get('children', []):
            tree['children'].append(self.get_process_tree(child_pid))
        
        return tree
    
    async def kill_process(self, pid: int, force: bool = False) -> bool:
        """Terminer un processus"""
        try:
            proc = psutil.Process(pid)
            
            if force:
                proc.kill()  # SIGKILL
            else:
                proc.terminate()  # SIGTERM
            
            logger.info(f"Processus {pid} terminé")
            
            # Notifier
            await self._notify_callbacks({
                'event': 'process_killed',
                'pid': pid,
                'timestamp': datetime.now().isoformat()
            })
            
            return True
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.error(f"Impossible de terminer le processus {pid}: {e}")
            return False
    
    async def stop_monitoring(self):
        """Arrêter la surveillance"""
        self.is_monitoring = False
        logger.info("🛑 Surveillance des processus arrêtée")

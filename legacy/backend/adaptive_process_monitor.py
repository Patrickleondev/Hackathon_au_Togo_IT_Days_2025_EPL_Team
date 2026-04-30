#!/usr/bin/env python3
"""
Moniteur de processus adaptatif au système hôte
RansomGuard AI - Surveillance intelligente multi-OS
"""

import asyncio
import logging
import platform
import psutil
import os
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, asdict
import json

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ProcessInfo:
    """Informations détaillées sur un processus adaptées à l'OS"""
    pid: int
    name: str
    exe: str
    cmdline: List[str]
    cpu_percent: float
    memory_percent: float
    memory_info: Dict[str, int]
    status: str
    create_time: float
    num_threads: int
    connections: List[Dict[str, Any]]
    open_files: List[str]
    os_specific_info: Dict[str, Any]  # Informations spécifiques à l'OS
    is_suspicious: bool = False
    threat_score: float = 0.0
    last_updated: datetime = None
    
    def __post_init__(self):
        if self.last_updated is None:
            self.last_updated = datetime.now()

class AdaptiveProcessMonitor:
    """
    Moniteur de processus qui s'adapte automatiquement au système hôte
    """
    
    def __init__(self):
        self.os_type = self._detect_os()
        self.os_version = self._get_os_version()
        self.processes: Dict[int, ProcessInfo] = {}
        self.suspicious_processes: List[ProcessInfo] = []
        self.monitoring_active = False
        
        # Patterns suspects adaptés à l'OS
        self.suspicious_patterns = self._get_os_specific_patterns()
        
        # Capacités selon l'OS
        self.capabilities = self._get_os_capabilities()
        
        logger.info(f"🖥️ Système détecté: {self.os_type} {self.os_version}")
        logger.info(f"🔧 Capacités: {list(self.capabilities.keys())}")
        
        # NE PAS démarrer automatiquement la surveillance
    
    def _detect_os(self) -> str:
        """Détecter l'OS de manière robuste"""
        system = platform.system().lower()
        if system == "windows":
            return "windows"
        elif system == "linux":
            return "linux"
        elif system == "darwin":
            return "macos"
        else:
            return "unknown"
    
    def _get_os_version(self) -> str:
        """Obtenir la version de l'OS"""
        try:
            if self.os_type == "windows":
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                   r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
                build = winreg.QueryValueEx(key, "CurrentBuild")[0]
                winreg.CloseKey(key)
                return f"Windows Build {build}"
            elif self.os_type == "linux":
                try:
                    with open("/etc/os-release") as f:
                        for line in f:
                            if line.startswith("PRETTY_NAME="):
                                return line.split("=", 1)[1].strip('"')
                except:
                    return platform.release()
            else:
                return platform.release()
        except:
            return platform.release()
    
    def _get_os_specific_patterns(self) -> Dict[str, List[str]]:
        """Patterns suspects spécifiques à l'OS"""
        base_patterns = ['crypto', 'encrypt', 'decrypt', 'ransom', 'malware']
        
        if self.os_type == "windows":
            return {
                "process_names": base_patterns + ['svchost.exe', 'lsass.exe', 'csrss.exe'],
                "file_extensions": ['.exe', '.dll', '.bat', '.ps1', '.vbs'],
                "registry_keys": ['Run', 'RunOnce', 'Services', 'Startup'],
                "network_ports": [80, 443, 8080, 22, 3389]
            }
        elif self.os_type == "linux":
            return {
                "process_names": base_patterns + ['systemd', 'init', 'kthreadd'],
                "file_extensions": ['.sh', '.py', '.pl', '.rb'],
                "system_paths": ['/etc/init.d', '/etc/systemd', '/var/spool'],
                "network_ports": [22, 80, 443, 8080, 3306]
            }
        elif self.os_type == "macos":
            return {
                "process_names": base_patterns + ['launchd', 'kernel_task', 'WindowServer'],
                "file_extensions": ['.app', '.plist', '.command', '.sh'],
                "system_paths": ['/Library/LaunchDaemons', '/System/Library'],
                "network_ports": [22, 80, 443, 8080, 548]
            }
        else:
            return {"generic": base_patterns}
    
    def _get_os_capabilities(self) -> Dict[str, bool]:
        """Déterminer les capacités disponibles selon l'OS"""
        caps = {
            "process_monitoring": True,
            "memory_analysis": False,
            "kernel_events": False,
            "network_capture": False,
            "file_system_watcher": False
        }
        
        if self.os_type == "windows":
            caps.update({
                "registry_monitoring": True,
                "wmi_access": True,
                "etw_tracing": True,
                "sysmon_events": self._check_sysmon_available()
            })
        elif self.os_type == "linux":
            caps.update({
                "procfs_access": True,
                "sysfs_access": True,
                "ebpf_support": self._check_ebpf_support(),
                "audit_logs": self._check_audit_support()
            })
        elif self.os_type == "macos":
            caps.update({
                "launchd_monitoring": True,
                "kext_analysis": True,
                "system_logs": True,
                "network_extension": self._check_network_extension()
            })
        
        return caps
    
    def _check_sysmon_available(self) -> bool:
        """Vérifier si Sysmon est disponible sur Windows"""
        try:
            if self.os_type == "windows":
                import subprocess
                result = subprocess.run(['sc', 'query', 'SysmonDrv'], 
                                     capture_output=True, text=True)
                return "RUNNING" in result.stdout
        except:
            pass
        return False
    
    def _check_ebpf_support(self) -> bool:
        """Vérifier le support eBPF sur Linux"""
        try:
            if self.os_type == "linux":
                return os.path.exists("/sys/kernel/debug/bpf")
        except:
            pass
        return False
    
    def _check_audit_support(self) -> bool:
        """Vérifier le support audit sur Linux"""
        try:
            if self.os_type == "linux":
                import subprocess
                result = subprocess.run(['systemctl', 'status', 'auditd'], 
                                     capture_output=True, text=True)
                return "active" in result.stdout.lower()
        except:
            pass
        return False
    
    def _check_network_extension(self) -> bool:
        """Vérifier le support Network Extension sur macOS"""
        try:
            if self.os_type == "macos":
                return os.path.exists("/System/Library/Frameworks/NetworkExtension.framework")
        except:
            pass
        return False
    
    async def start_monitoring(self):
        """Démarrer la surveillance adaptée à l'OS"""
        logger.info(f"🚀 Démarrage de la surveillance adaptée à {self.os_type}...")
        self.monitoring_active = True
        
        # Démarrer les moniteurs spécifiques à l'OS
        if self.capabilities.get("sysmon_events", False):
            logger.info("🔍 Monitoring Sysmon activé (Windows)")
        
        if self.capabilities.get("ebpf_support", False):
            logger.info("🔍 Monitoring eBPF activé (Linux)")
        
        while self.monitoring_active:
            try:
                await self.scan_processes()
                await asyncio.sleep(5)  # Scan toutes les 5 secondes
            except Exception as e:
                logger.error(f"Erreur lors du scan: {e}")
                await asyncio.sleep(10)
    
    async def stop_monitoring(self):
        """Arrêter la surveillance"""
        logger.info("🛑 Arrêt de la surveillance des processus...")
        self.monitoring_active = False
    
    async def scan_processes(self):
        """Scanner les processus avec des méthodes adaptées à l'OS"""
        try:
            current_processes = {}
            
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'status', 'create_time', 'num_threads']):
                try:
                    proc_info = proc.info
                    pid = proc_info['pid']
                    
                    # Obtenir des informations supplémentaires selon l'OS
                    os_specific_info = await self._get_os_specific_process_info(proc)
                    
                    with proc.oneshot():
                        cpu_percent = proc.cpu_percent()
                        memory_percent = proc.memory_percent()
                        memory_info = proc.memory_info()._asdict()
                        
                        # Connexions réseau
                        try:
                            connections = [conn._asdict() for conn in proc.connections()]
                        except (psutil.AccessDenied, psutil.ZombieProcess):
                            connections = []
                        
                        # Fichiers ouverts
                        try:
                            open_files = [f.path for f in proc.open_files()]
                        except (psutil.AccessDenied, psutil.ZombieProcess):
                            open_files = []
                    
                    process_info = ProcessInfo(
                        pid=pid,
                        name=proc_info['name'],
                        exe=proc_info['exe'],
                        cmdline=proc_info['cmdline'],
                        cpu_percent=cpu_percent,
                        memory_percent=memory_percent,
                        memory_info=memory_info,
                        status=proc_info['status'],
                        create_time=proc_info['create_time'],
                        num_threads=proc_info['num_threads'],
                        connections=connections,
                        open_files=open_files,
                        os_specific_info=os_specific_info
                    )
                    
                    # Analyser le processus pour détecter les menaces
                    await self._analyze_process_for_threats(process_info)
                    
                    current_processes[pid] = process_info
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            self.processes = current_processes
            
        except Exception as e:
            logger.error(f"Erreur lors du scan des processus: {e}")
    
    async def _get_os_specific_process_info(self, proc) -> Dict[str, Any]:
        """Obtenir des informations spécifiques à l'OS pour un processus"""
        os_info = {}
        
        try:
            if self.os_type == "windows":
                os_info.update(await self._get_windows_process_info(proc))
            elif self.os_type == "linux":
                os_info.update(await self._get_linux_process_info(proc))
            elif self.os_type == "macos":
                os_info.update(await self._get_macos_process_info(proc))
        except Exception as e:
            logger.debug(f"Erreur lors de la récupération d'infos OS: {e}")
        
        return os_info
    
    async def _get_windows_process_info(self, proc) -> Dict[str, Any]:
        """Informations spécifiques Windows"""
        info = {}
        try:
            # Informations WMI si disponible
            if self.capabilities.get("wmi_access", False):
                try:
                    import wmi
                    c = wmi.WMI()
                    for process in c.Win32_Process(ProcessId=proc.pid):
                        info["windows_parent_pid"] = process.ParentProcessId
                        info["windows_priority"] = process.Priority
                        info["windows_working_set"] = process.WorkingSetSize
                except:
                    pass
        except:
            pass
        return info
    
    async def _get_linux_process_info(self, proc) -> Dict[str, Any]:
        """Informations spécifiques Linux"""
        info = {}
        try:
            # Lire /proc/{pid}/status
            proc_status_path = f"/proc/{proc.pid}/status"
            if os.path.exists(proc_status_path):
                with open(proc_status_path, 'r') as f:
                    for line in f:
                        if line.startswith("PPid:"):
                            info["linux_parent_pid"] = int(line.split()[1])
                        elif line.startswith("Uid:"):
                            info["linux_user_id"] = int(line.split()[1])
                        elif line.startswith("Gid:"):
                            info["linux_group_id"] = int(line.split()[1])
        except:
            pass
        return info
    
    async def _get_macos_process_info(self, proc) -> Dict[str, Any]:
        """Informations spécifiques macOS"""
        info = {}
        try:
            # Utiliser ps pour des informations détaillées
            import subprocess
            result = subprocess.run(['ps', '-p', str(proc.pid), '-o', 'ppid,uid,gid,pri'], 
                                 capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:
                    parts = lines[1].split()
                    if len(parts) >= 4:
                        info["macos_parent_pid"] = int(parts[0])
                        info["macos_user_id"] = int(parts[1])
                        info["macos_group_id"] = int(parts[2])
                        info["macos_priority"] = int(parts[3])
        except:
            pass
        return info
    
    async def _analyze_process_for_threats(self, process: ProcessInfo):
        """Analyser un processus pour détecter les menaces selon l'OS"""
        threat_score = 0.0
        suspicious_indicators = []
        
        # Vérifications de base
        if process.cpu_percent > 80:
            threat_score += 0.2
            suspicious_indicators.append("Utilisation CPU élevée")
        
        if process.memory_percent > 50:
            threat_score += 0.2
            suspicious_indicators.append("Utilisation mémoire élevée")
        
        # Vérifications spécifiques à l'OS
        if self.os_type == "windows":
            threat_score += await self._analyze_windows_process(process)
        elif self.os_type == "linux":
            threat_score += await self._analyze_linux_process(process)
        elif self.os_type == "macos":
            threat_score += await self._analyze_macos_process(process)
        
        # Vérifications des patterns suspects
        for pattern in self.suspicious_patterns.get("process_names", []):
            if pattern.lower() in process.name.lower():
                threat_score += 0.3
                suspicious_indicators.append(f"Nom suspect: {pattern}")
        
        # Vérifications des connexions réseau
        if len(process.connections) > 100:
            threat_score += 0.2
            suspicious_indicators.append("Nombre élevé de connexions réseau")
        
        # Vérifications des fichiers ouverts
        if len(process.open_files) > 1000:
            threat_score += 0.2
            suspicious_indicators.append("Nombre élevé de fichiers ouverts")
        
        # Mettre à jour le processus
        process.threat_score = min(threat_score, 1.0)
        process.is_suspicious = threat_score > 0.5
        
        if process.is_suspicious:
            self.suspicious_processes.append(process)
            logger.warning(f"⚠️ Processus suspect détecté: {process.name} (PID: {process.pid}) - Score: {threat_score:.2f}")
            logger.warning(f"   Indicateurs: {', '.join(suspicious_indicators)}")
    
    async def _analyze_windows_process(self, process: ProcessInfo) -> float:
        """Analyse spécifique Windows"""
        threat_score = 0.0
        
        # Vérifier les informations WMI
        if "windows_parent_pid" in process.os_specific_info:
            parent_pid = process.os_specific_info["windows_parent_pid"]
            if parent_pid == 0:  # Processus orphelin
                threat_score += 0.1
        
        # Vérifier les extensions de fichiers suspects
        if process.exe and any(ext in process.exe.lower() for ext in ['.exe', '.dll']):
            if any(pattern in process.exe.lower() for pattern in ['temp', 'downloads', 'desktop']):
                threat_score += 0.2
        
        return threat_score
    
    async def _analyze_linux_process(self, process: ProcessInfo) -> float:
        """Analyse spécifique Linux"""
        threat_score = 0.0
        
        # Vérifier les permissions
        if "linux_user_id" in process.os_specific_info:
            user_id = process.os_specific_info["linux_user_id"]
            if user_id == 0:  # Processus root
                threat_score += 0.1
        
        # Vérifier les chemins suspects
        if process.exe and any(path in process.exe for path in ['/tmp', '/var/tmp', '/dev/shm']):
            threat_score += 0.2
        
        return threat_score
    
    async def _analyze_macos_process(self, process: ProcessInfo) -> float:
        """Analyse spécifique macOS"""
        threat_score = 0.0
        
        # Vérifier les LaunchDaemons
        if process.exe and any(path in process.exe for path in ['/Library/LaunchDaemons', '/System/Library/LaunchDaemons']):
            threat_score += 0.1
        
        return threat_score
    
    async def get_processes_summary(self) -> Dict[str, Any]:
        """Obtenir un résumé des processus avec informations OS"""
        total_processes = len(self.processes)
        suspicious_count = len(self.suspicious_processes)
        
        # Statistiques par OS
        os_stats = {
            "total_processes": total_processes,
            "suspicious_processes": suspicious_count,
            "os_type": self.os_type,
            "os_version": self.os_version,
            "capabilities": self.capabilities,
            "threat_level": self._calculate_threat_level(),
            "monitoring_status": "active" if self.monitoring_active else "inactive"
        }
        
        # Top processus par utilisation
        if self.processes:
            top_cpu = sorted(self.processes.values(), key=lambda x: x.cpu_percent, reverse=True)[:5]
            top_memory = sorted(self.processes.values(), key=lambda x: x.memory_percent, reverse=True)[:5]
            
            os_stats.update({
                "top_cpu_processes": [{"name": p.name, "pid": p.pid, "cpu": p.cpu_percent} for p in top_cpu],
                "top_memory_processes": [{"name": p.name, "pid": p.pid, "memory": p.memory_percent} for p in top_memory]
            })
        
        return os_stats
    
    def _calculate_threat_level(self) -> str:
        """Calculer le niveau de menace global"""
        if not self.suspicious_processes:
            return "Faible"
        
        high_threat_count = sum(1 for p in self.suspicious_processes if p.threat_score > 0.7)
        medium_threat_count = sum(1 for p in self.suspicious_processes if 0.5 < p.threat_score <= 0.7)
        
        if high_threat_count > 0:
            return "Élevé"
        elif medium_threat_count > 0:
            return "Moyen"
        else:
            return "Faible"
    
    async def get_process_details(self, pid: int) -> Optional[ProcessInfo]:
        """Obtenir les détails d'un processus spécifique"""
        return self.processes.get(pid)
    
    async def kill_process(self, pid: int) -> bool:
        """Tuer un processus (avec vérifications de sécurité)"""
        try:
            if pid in self.processes:
                process = self.processes[pid]
                
                # Vérifications de sécurité
                if process.threat_score < 0.7:
                    logger.warning(f"⚠️ Tentative de tuer un processus à faible risque: {process.name}")
                    return False
                
                # Tuer le processus
                proc = psutil.Process(pid)
                proc.terminate()
                
                # Attendre la terminaison
                try:
                    proc.wait(timeout=5)
                    logger.info(f"✅ Processus {process.name} (PID: {pid}) terminé avec succès")
                    return True
                except psutil.TimeoutExpired:
                    proc.kill()
                    logger.info(f"✅ Processus {process.name} (PID: {pid}) tué de force")
                    return True
                    
        except Exception as e:
            logger.error(f"❌ Erreur lors de la terminaison du processus {pid}: {e}")
            return False
        
        return False

async def main():
    """Test du moniteur adaptatif"""
    monitor = AdaptiveProcessMonitor()
    
    logger.info("🧪 Test du moniteur de processus adaptatif...")
    
    # Démarrer la surveillance
    await monitor.start_monitoring()
    
    # Attendre un peu pour collecter des données
    await asyncio.sleep(10)
    
    # Arrêter la surveillance
    await monitor.stop_monitoring()
    
    # Afficher le résumé
    summary = await monitor.get_processes_summary()
    logger.info(f"📊 Résumé: {summary}")
    
    # Afficher les processus suspects détectés
    if monitor.suspicious_processes:
        logger.info("🚨 Processus suspects détectés:")
        for proc in monitor.suspicious_processes:
            logger.info(f"  - {proc.name} (PID: {proc.pid}) - Score: {proc.threat_score:.2f}")
    
    logger.info("✅ Test terminé avec succès!")

if __name__ == "__main__":
    asyncio.run(main())

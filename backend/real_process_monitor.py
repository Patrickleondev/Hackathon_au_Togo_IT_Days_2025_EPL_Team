#!/usr/bin/env python3
"""
Moniteur de processus réel pour RansomGuard AI
Surveillance en temps réel des processus système
"""

import psutil
import asyncio
import logging
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import time

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ProcessInfo:
    """Informations détaillées sur un processus"""
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
    is_suspicious: bool = False
    threat_score: float = 0.0
    last_updated: datetime = None
    
    def __post_init__(self):
        if self.last_updated is None:
            self.last_updated = datetime.now()

class RealProcessMonitor:
    """Moniteur de processus réel avec détection de menaces"""
    
    def __init__(self):
        self.processes: Dict[int, ProcessInfo] = {}
        self.suspicious_processes: List[ProcessInfo] = []
        self.monitoring_active = False
        self.suspicious_patterns = [
            'crypto', 'encrypt', 'decrypt', 'ransom', 'malware',
            'trojan', 'virus', 'spyware', 'keylogger', 'backdoor'
        ]
        
    async def start_monitoring(self):
        """Démarrer la surveillance des processus"""
        logger.info("🚀 Démarrage de la surveillance des processus...")
        self.monitoring_active = True
        
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
        """Scanner tous les processus en cours"""
        try:
            current_processes = {}
            
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'status', 'create_time', 'num_threads']):
                try:
                    proc_info = proc.info
                    pid = proc_info['pid']
                    
                    # Obtenir des informations supplémentaires
                    with proc.oneshot():
                        cpu_percent = proc.cpu_percent()
                        memory_percent = proc.memory_percent()
                        memory_info = proc.memory_info()._asdict()
                        
                        # Obtenir les connexions réseau
                        try:
                            connections = [conn._asdict() for conn in proc.connections()]
                        except (psutil.AccessDenied, psutil.ZombieProcess):
                            connections = []
                        
                        # Obtenir les fichiers ouverts
                        try:
                            open_files = [f.path for f in proc.open_files()]
                        except (psutil.AccessDenied, psutil.ZombieProcess):
                            open_files = []
                    
                    # Créer l'objet ProcessInfo
                    process_info = ProcessInfo(
                        pid=pid,
                        name=proc_info['name'] or 'Unknown',
                        exe=proc_info['exe'] or '',
                        cmdline=proc_info['cmdline'] or [],
                        cpu_percent=cpu_percent,
                        memory_percent=memory_percent,
                        memory_info=memory_info,
                        status=proc_info['status'],
                        create_time=proc_info['create_time'],
                        num_threads=proc_info['num_threads'],
                        connections=connections,
                        open_files=open_files
                    )
                    
                    # Analyser le processus pour détecter les menaces
                    await self.analyze_process(process_info)
                    
                    current_processes[pid] = process_info
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                    continue
            
            # Mettre à jour la liste des processus
            self.processes = current_processes
            
            # Mettre à jour les processus suspects
            self.suspicious_processes = [p for p in self.processes.values() if p.is_suspicious]
            
            logger.info(f"📊 Scan terminé: {len(self.processes)} processus, {len(self.suspicious_processes)} suspects")
            
        except Exception as e:
            logger.error(f"Erreur lors du scan des processus: {e}")
    
    async def analyze_process(self, process: ProcessInfo):
        """Analyser un processus pour détecter les menaces"""
        threat_score = 0.0
        is_suspicious = False
        
        # Vérifier le nom du processus
        process_name_lower = process.name.lower()
        for pattern in self.suspicious_patterns:
            if pattern in process_name_lower:
                threat_score += 0.3
                is_suspicious = True
        
        # Vérifier la ligne de commande
        cmdline_str = ' '.join(process.cmdline).lower()
        for pattern in self.suspicious_patterns:
            if pattern in cmdline_str:
                threat_score += 0.4
                is_suspicious = True
        
        # Vérifier l'utilisation des ressources
        if process.cpu_percent > 80:
            threat_score += 0.2
        if process.memory_percent > 70:
            threat_score += 0.2
        
        # Vérifier les connexions réseau suspectes
        for conn in process.connections:
            if conn.get('status') == 'LISTEN' and conn.get('lport') in [22, 23, 3389, 5900]:
                threat_score += 0.3
                is_suspicious = True
        
        # Vérifier les fichiers ouverts suspects
        for file_path in process.open_files:
            if any(ext in file_path.lower() for ext in ['.exe', '.dll', '.bat', '.ps1']):
                if 'temp' in file_path.lower() or 'downloads' in file_path.lower():
                    threat_score += 0.2
                    is_suspicious = True
        
        # Limiter le score de menace
        threat_score = min(threat_score, 1.0)
        
        # Mettre à jour le processus
        process.threat_score = threat_score
        process.is_suspicious = is_suspicious
        process.last_updated = datetime.now()
    
    def get_processes_summary(self) -> Dict[str, Any]:
        """Obtenir un résumé des processus"""
        total_processes = len(self.processes)
        suspicious_count = len(self.suspicious_processes)
        
        # Top 10 des processus par utilisation CPU
        top_cpu = sorted(
            [p for p in self.processes.values() if p.cpu_percent > 0],
            key=lambda x: x.cpu_percent,
            reverse=True
        )[:10]
        
        # Top 10 des processus par utilisation mémoire
        top_memory = sorted(
            [p for p in self.processes.values() if p.memory_percent > 0],
            key=lambda x: x.memory_percent,
            reverse=True
        )[:10]
        
        # Processus suspects
        suspicious = [
            {
                'pid': p.pid,
                'name': p.name,
                'threat_score': p.threat_score,
                'cpu_percent': p.cpu_percent,
                'memory_percent': p.memory_percent,
                'exe': p.exe,
                'cmdline': p.cmdline[:3]  # Limiter la ligne de commande
            }
            for p in self.suspicious_processes
        ]
        
        return {
            'total_processes': total_processes,
            'suspicious_count': suspicious_count,
            'top_cpu_processes': [
                {
                    'pid': p.pid,
                    'name': p.name,
                    'cpu_percent': round(p.cpu_percent, 2),
                    'memory_percent': round(p.memory_percent, 2)
                }
                for p in top_cpu
            ],
            'top_memory_processes': [
                {
                    'pid': p.pid,
                    'name': p.name,
                    'cpu_percent': round(p.cpu_percent, 2),
                    'memory_percent': round(p.memory_percent, 2)
                }
                for p in top_memory
            ],
            'suspicious_processes': suspicious,
            'last_scan': datetime.now().isoformat()
        }
    
    def get_process_details(self, pid: int) -> Optional[ProcessInfo]:
        """Obtenir les détails d'un processus spécifique"""
        return self.processes.get(pid)
    
    def kill_process(self, pid: int) -> bool:
        """Tuer un processus"""
        try:
            if pid in self.processes:
                proc = psutil.Process(pid)
                proc.terminate()
                logger.info(f"🔄 Processus {pid} ({proc.name()}) terminé")
                return True
        except Exception as e:
            logger.error(f"Erreur lors de la terminaison du processus {pid}: {e}")
        return False

# Instance globale
process_monitor = RealProcessMonitor()

async def main():
    """Fonction principale de test"""
    logger.info("🚀 Test du moniteur de processus réel...")
    
    # Démarrer la surveillance
    monitor_task = asyncio.create_task(process_monitor.start_monitoring())
    
    try:
        # Attendre un peu pour collecter des données
        await asyncio.sleep(10)
        
        # Afficher un résumé
        summary = process_monitor.get_processes_summary()
        logger.info("📊 Résumé des processus:")
        logger.info(f"  Total: {summary['total_processes']}")
        logger.info(f"  Suspects: {summary['suspicious_count']}")
        
        if summary['suspicious_processes']:
            logger.info("🚨 Processus suspects détectés:")
            for proc in summary['suspicious_processes'][:3]:
                logger.info(f"  - {proc['name']} (PID: {proc['pid']}) - Score: {proc['threat_score']}")
        
        # Afficher les top processus
        logger.info("🔥 Top processus CPU:")
        for proc in summary['top_cpu_processes'][:3]:
            logger.info(f"  - {proc['name']}: {proc['cpu_percent']}% CPU, {proc['memory_percent']}% RAM")
        
    except KeyboardInterrupt:
        logger.info("⏹️ Arrêt demandé par l'utilisateur...")
    finally:
        # Arrêter la surveillance
        await process_monitor.stop_monitoring()
        monitor_task.cancel()
        logger.info("✅ Moniteur de processus arrêté")

if __name__ == "__main__":
    asyncio.run(main())

#!/usr/bin/env python3
"""
Système de monitoring unifié pour RansomGuard AI
Intègre la surveillance des processus, fichiers, registre et réseau
"""

import asyncio
import logging
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import os

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import des moniteurs
try:
    from real_process_monitor import RealProcessMonitor, process_monitor
    PROCESS_MONITOR_AVAILABLE = True
    logger.info("✅ Moniteur de processus disponible")
except ImportError as e:
    PROCESS_MONITOR_AVAILABLE = False
    logger.warning(f"⚠️ Moniteur de processus non disponible: {e}")

try:
    from real_file_monitor import RealFileMonitor, file_monitor
    FILE_MONITOR_AVAILABLE = True
    logger.info("✅ Moniteur de fichiers disponible")
except ImportError as e:
    FILE_MONITOR_AVAILABLE = False
    logger.warning(f"⚠️ Moniteur de fichiers non disponible: {e}")

try:
    from real_registry_monitor import RealRegistryMonitor, registry_monitor
    REGISTRY_MONITOR_AVAILABLE = True
    logger.info("✅ Moniteur de registre disponible")
except ImportError as e:
    REGISTRY_MONITOR_AVAILABLE = False
    logger.warning(f"⚠️ Moniteur de registre non disponible: {e}")

try:
    from system_access.network_monitor import NetworkMonitor
    NETWORK_MONITOR_AVAILABLE = True
    logger.info("✅ Moniteur réseau disponible")
except ImportError as e:
    NETWORK_MONITOR_AVAILABLE = False
    logger.warning(f"⚠️ Moniteur réseau non disponible: {e}")

@dataclass
class SystemStatus:
    """Statut global du système"""
    overall_status: str  # "HEALTHY", "WARNING", "CRITICAL"
    total_threats: int
    active_monitors: int
    last_scan: datetime
    system_health_score: float  # 0.0 à 1.0
    recommendations: List[str]

@dataclass
class ThreatSummary:
    """Résumé des menaces détectées"""
    threat_type: str  # "process", "file", "registry", "network"
    count: int
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    description: str
    last_detected: datetime

class UnifiedSystemMonitor:
    """Système de monitoring unifié"""
    
    def __init__(self):
        self.monitors = {}
        self.monitoring_active = False
        self.system_status = SystemStatus(
            overall_status="UNKNOWN",
            total_threats=0,
            active_monitors=0,
            last_scan=datetime.now(),
            system_health_score=1.0,
            recommendations=[]
        )
        
        # Initialiser les moniteurs disponibles
        self.init_monitors()
    
    def init_monitors(self):
        """Initialiser les moniteurs disponibles"""
        if PROCESS_MONITOR_AVAILABLE:
            self.monitors['process'] = process_monitor
            logger.info("✅ Moniteur de processus initialisé")
        
        if FILE_MONITOR_AVAILABLE:
            self.monitors['file'] = file_monitor
            logger.info("✅ Moniteur de fichiers initialisé")
        
        if REGISTRY_MONITOR_AVAILABLE:
            self.monitors['registry'] = registry_monitor
            logger.info("✅ Moniteur de registre initialisé")
        
        if NETWORK_MONITOR_AVAILABLE:
            try:
                self.monitors['network'] = NetworkMonitor()
                logger.info("✅ Moniteur réseau initialisé")
            except Exception as e:
                logger.warning(f"⚠️ Erreur initialisation moniteur réseau: {e}")
        
        logger.info(f"🎯 {len(self.monitors)} moniteurs initialisés")
    
    async def start_all_monitoring(self):
        """Démarrer tous les moniteurs"""
        logger.info("🚀 Démarrage de tous les moniteurs...")
        self.monitoring_active = True
        
        # Démarrer les moniteurs en parallèle
        monitor_tasks = []
        
        for monitor_name, monitor in self.monitors.items():
            try:
                if hasattr(monitor, 'start_monitoring'):
                    task = asyncio.create_task(monitor.start_monitoring())
                    monitor_tasks.append((monitor_name, task))
                    logger.info(f"✅ {monitor_name} démarré")
                else:
                    logger.warning(f"⚠️ {monitor_name} n'a pas de méthode start_monitoring")
            except Exception as e:
                logger.error(f"❌ Erreur lors du démarrage de {monitor_name}: {e}")
        
        # Attendre que tous les moniteurs soient prêts
        await asyncio.sleep(5)
        
        # Démarrer la surveillance globale
        global_monitor_task = asyncio.create_task(self.global_monitoring())
        
        try:
            # Attendre que la surveillance globale se termine
            await global_monitor_task
        except KeyboardInterrupt:
            logger.info("⏹️ Arrêt demandé par l'utilisateur...")
        finally:
            # Arrêter tous les moniteurs
            await self.stop_all_monitoring()
            for monitor_name, task in monitor_tasks:
                task.cancel()
            global_monitor_task.cancel()
            logger.info("✅ Tous les moniteurs arrêtés")
    
    async def stop_all_monitoring(self):
        """Arrêter tous les moniteurs"""
        logger.info("🛑 Arrêt de tous les moniteurs...")
        self.monitoring_active = False
        
        for monitor_name, monitor in self.monitors.items():
            try:
                if hasattr(monitor, 'stop_monitoring'):
                    monitor.stop_monitoring()
                    logger.info(f"✅ {monitor_name} arrêté")
            except Exception as e:
                logger.error(f"❌ Erreur lors de l'arrêt de {monitor_name}: {e}")
    
    async def global_monitoring(self):
        """Surveillance globale du système"""
        logger.info("🌍 Démarrage de la surveillance globale...")
        
        while self.monitoring_active:
            try:
                # Mettre à jour le statut global
                await self.update_system_status()
                
                # Vérifier la santé du système
                await self.check_system_health()
                
                # Générer des recommandations
                await self.generate_recommendations()
                
                # Attendre avant la prochaine vérification
                await asyncio.sleep(10)
                
            except Exception as e:
                logger.error(f"❌ Erreur lors de la surveillance globale: {e}")
                await asyncio.sleep(30)
    
    async def update_system_status(self):
        """Mettre à jour le statut global du système"""
        try:
            total_threats = 0
            active_monitors = 0
            
            # Compter les menaces et moniteurs actifs
            for monitor_name, monitor in self.monitors.items():
                try:
                    if hasattr(monitor, 'monitoring_active') and monitor.monitoring_active:
                        active_monitors += 1
                    
                    # Compter les menaces selon le type de moniteur
                    if monitor_name == 'process' and hasattr(monitor, 'suspicious_processes'):
                        total_threats += len(monitor.suspicious_processes)
                    elif monitor_name == 'file' and hasattr(monitor, 'suspicious_operations'):
                        total_threats += len(monitor.suspicious_operations)
                    elif monitor_name == 'registry' and hasattr(monitor, 'suspicious_operations'):
                        total_threats += len(monitor.suspicious_operations)
                    elif monitor_name == 'network' and hasattr(monitor, 'suspicious_connections'):
                        total_threats += len(monitor.suspicious_connections)
                        
                except Exception as e:
                    logger.warning(f"⚠️ Erreur lors de la vérification de {monitor_name}: {e}")
            
            # Mettre à jour le statut
            self.system_status.total_threats = total_threats
            self.system_status.active_monitors = active_monitors
            self.system_status.last_scan = datetime.now()
            
        except Exception as e:
            logger.error(f"❌ Erreur lors de la mise à jour du statut: {e}")
    
    async def check_system_health(self):
        """Vérifier la santé globale du système"""
        try:
            health_score = 1.0
            issues = []
            
            # Vérifier les moniteurs
            if len(self.monitors) == 0:
                health_score -= 0.5
                issues.append("Aucun moniteur disponible")
            
            # Vérifier les menaces
            if self.system_status.total_threats > 10:
                health_score -= 0.3
                issues.append("Nombre élevé de menaces détectées")
            elif self.system_status.total_threats > 5:
                health_score -= 0.1
                issues.append("Menaces modérées détectées")
            
            # Vérifier les moniteurs actifs
            if self.system_status.active_monitors < len(self.monitors):
                health_score -= 0.2
                issues.append("Certains moniteurs ne sont pas actifs")
            
            # Limiter le score de santé
            health_score = max(0.0, health_score)
            
            # Déterminer le statut global
            if health_score >= 0.8:
                overall_status = "HEALTHY"
            elif health_score >= 0.6:
                overall_status = "WARNING"
            else:
                overall_status = "CRITICAL"
            
            # Mettre à jour le statut
            self.system_status.system_health_score = health_score
            self.system_status.overall_status = overall_status
            
            if issues:
                logger.warning(f"⚠️ Problèmes de santé détectés: {', '.join(issues)}")
            else:
                logger.info(f"✅ Système en bonne santé (Score: {health_score:.2f})")
                
        except Exception as e:
            logger.error(f"❌ Erreur lors de la vérification de la santé: {e}")
    
    async def generate_recommendations(self):
        """Générer des recommandations de sécurité"""
        try:
            recommendations = []
            
            # Recommandations basées sur les menaces
            if self.system_status.total_threats > 5:
                recommendations.append("Effectuer un scan complet du système")
                recommendations.append("Vérifier les processus suspects")
            
            # Recommandations basées sur les moniteurs
            if not PROCESS_MONITOR_AVAILABLE:
                recommendations.append("Installer le moniteur de processus")
            if not FILE_MONITOR_AVAILABLE:
                recommendations.append("Installer le moniteur de fichiers")
            if not REGISTRY_MONITOR_AVAILABLE:
                recommendations.append("Installer le moniteur de registre")
            
            # Recommandations générales
            if self.system_status.system_health_score < 0.8:
                recommendations.append("Mettre à jour les définitions de menaces")
                recommendations.append("Vérifier la configuration de sécurité")
            
            # Ajouter des recommandations spécifiques
            recommendations.extend(await self.get_specific_recommendations())
            
            # Mettre à jour les recommandations
            self.system_status.recommendations = recommendations[:5]  # Limiter à 5
            
        except Exception as e:
            logger.error(f"❌ Erreur lors de la génération des recommandations: {e}")
    
    async def get_specific_recommendations(self) -> List[str]:
        """Obtenir des recommandations spécifiques selon les moniteurs"""
        recommendations = []
        
        try:
            # Recommandations du moniteur de processus
            if 'process' in self.monitors:
                monitor = self.monitors['process']
                if hasattr(monitor, 'suspicious_processes') and monitor.suspicious_processes:
                    recommendations.append("Terminer les processus suspects détectés")
            
            # Recommandations du moniteur de fichiers
            if 'file' in self.monitors:
                monitor = self.monitors['file']
                if hasattr(monitor, 'suspicious_operations') and monitor.suspicious_operations:
                    recommendations.append("Quarantiner les fichiers suspects")
            
            # Recommandations du moniteur de registre
            if 'registry' in self.monitors:
                monitor = self.monitors['registry']
                if hasattr(monitor, 'suspicious_operations') and monitor.suspicious_operations:
                    recommendations.append("Restaurer les clés de registre compromises")
            
        except Exception as e:
            logger.error(f"❌ Erreur lors de l'obtention des recommandations spécifiques: {e}")
        
        return recommendations
    
    def get_system_overview(self) -> Dict[str, Any]:
        """Obtenir une vue d'ensemble du système"""
        try:
            overview = {
                'system_status': {
                    'overall_status': self.system_status.overall_status,
                    'health_score': self.system_status.system_health_score,
                    'total_threats': self.system_status.total_threats,
                    'active_monitors': self.system_status.active_monitors,
                    'last_scan': self.system_status.last_scan.isoformat()
                },
                'monitors': {},
                'threats_summary': [],
                'recommendations': self.system_status.recommendations
            }
            
            # Informations sur chaque moniteur
            for monitor_name, monitor in self.monitors.items():
                try:
                    monitor_info = {
                        'available': True,
                        'active': getattr(monitor, 'monitoring_active', False),
                        'status': 'active' if getattr(monitor, 'monitoring_active', False) else 'inactive'
                    }
                    
                    # Ajouter des informations spécifiques selon le type de moniteur
                    if monitor_name == 'process' and hasattr(monitor, 'get_processes_summary'):
                        summary = monitor.get_processes_summary()
                        monitor_info['processes_count'] = summary.get('total_processes', 0)
                        monitor_info['suspicious_count'] = summary.get('suspicious_count', 0)
                    
                    elif monitor_name == 'file' and hasattr(monitor, 'get_monitoring_summary'):
                        summary = monitor.get_monitoring_summary()
                        monitor_info['directories_count'] = summary.get('total_monitored_directories', 0)
                        monitor_info['operations_count'] = summary.get('total_file_operations', 0)
                    
                    elif monitor_name == 'registry' and hasattr(monitor, 'get_registry_summary'):
                        summary = monitor.get_registry_summary()
                        monitor_info['keys_count'] = summary.get('total_registry_keys', 0)
                        monitor_info['suspicious_keys'] = summary.get('suspicious_keys', 0)
                    
                    overview['monitors'][monitor_name] = monitor_info
                    
                except Exception as e:
                    logger.warning(f"⚠️ Erreur lors de l'obtention des infos de {monitor_name}: {e}")
                    overview['monitors'][monitor_name] = {
                        'available': True,
                        'active': False,
                        'status': 'error',
                        'error': str(e)
                    }
            
            # Résumé des menaces par type
            threat_types = ['process', 'file', 'registry', 'network']
            for threat_type in threat_types:
                if threat_type in self.monitors:
                    monitor = self.monitors[threat_type]
                    threat_count = 0
                    
                    if threat_type == 'process' and hasattr(monitor, 'suspicious_processes'):
                        threat_count = len(monitor.suspicious_processes)
                    elif threat_type == 'file' and hasattr(monitor, 'suspicious_operations'):
                        threat_count = len(monitor.suspicious_operations)
                    elif threat_type == 'registry' and hasattr(monitor, 'suspicious_operations'):
                        threat_count = len(monitor.suspicious_operations)
                    elif threat_type == 'network' and hasattr(monitor, 'suspicious_connections'):
                        threat_count = len(monitor.suspicious_connections)
                    
                    if threat_count > 0:
                        overview['threats_summary'].append({
                            'type': threat_type,
                            'count': threat_count,
                            'severity': 'HIGH' if threat_count > 5 else 'MEDIUM' if threat_count > 2 else 'LOW'
                        })
            
            return overview
            
        except Exception as e:
            logger.error(f"❌ Erreur lors de l'obtention de la vue d'ensemble: {e}")
            return {
                'error': str(e),
                'system_status': {
                    'overall_status': 'ERROR',
                    'health_score': 0.0,
                    'total_threats': 0,
                    'active_monitors': 0,
                    'last_scan': datetime.now().isoformat()
                }
            }
    
    def add_directory_to_monitor(self, directory_path: str) -> bool:
        """Ajouter un répertoire à surveiller"""
        if 'file' in self.monitors:
            return self.monitors['file'].add_directory(directory_path)
        return False
    
    def remove_directory_from_monitor(self, directory_path: str) -> bool:
        """Retirer un répertoire de la surveillance"""
        if 'file' in self.monitors:
            return self.monitors['file'].remove_directory(directory_path)
        return False
    
    def get_monitored_directories(self) -> List[str]:
        """Obtenir la liste des répertoires surveillés"""
        if 'file' in self.monitors:
            return list(self.monitors['file'].monitored_dirs.keys())
        return []

# Instance globale
unified_monitor = UnifiedSystemMonitor()

async def main():
    """Fonction principale de test"""
    logger.info("🚀 Test du système de monitoring unifié...")
    
    # Démarrer la surveillance
    try:
        await unified_monitor.start_all_monitoring()
    except KeyboardInterrupt:
        logger.info("⏹️ Arrêt demandé par l'utilisateur...")
    finally:
        await unified_monitor.stop_all_monitoring()
        logger.info("✅ Système de monitoring arrêté")

if __name__ == "__main__":
    asyncio.run(main())

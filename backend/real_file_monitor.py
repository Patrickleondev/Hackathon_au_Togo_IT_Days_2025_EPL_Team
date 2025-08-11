#!/usr/bin/env python3
"""
Moniteur de fichiers réel pour RansomGuard AI
Surveillance en temps réel des dossiers spécifiés par l'utilisateur
"""

import os
import asyncio
import logging
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, asdict
from pathlib import Path
import time
import psutil

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class FileOperation:
    """Informations sur une opération de fichier"""
    operation_type: str  # 'create', 'modify', 'delete', 'access'
    file_path: str
    timestamp: datetime
    process_name: str
    process_pid: int
    file_size: int
    file_hash: str
    is_suspicious: bool = False
    threat_score: float = 0.0
    ml_detection: Dict[str, Any] = None

@dataclass
class MonitoredDirectory:
    """Informations sur un répertoire surveillé"""
    path: str
    name: str
    total_files: int
    suspicious_files: int
    last_scan: datetime
    file_operations: List[FileOperation]
    threat_level: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL

class RealFileMonitor:
    """Moniteur de fichiers réel avec détection ML"""
    
    def __init__(self):
        self.monitored_dirs: Dict[str, MonitoredDirectory] = {}
        self.monitoring_active = False
        self.file_operations: List[FileOperation] = []
        self.suspicious_operations: List[FileOperation] = []
        self.suspicious_extensions = {'.exe', '.dll', '.bat', '.ps1', '.vbs', '.js', '.jar'}
        self.critical_dirs = {'desktop', 'documents', 'downloads', 'pictures', 'videos'}
        
        # Initialiser les détecteurs ML
        self.ml_detectors = {}
        self.init_ml_detectors()
    
    def init_ml_detectors(self):
        """Initialiser les détecteurs ML"""
        try:
            from ml_engine.hybrid_detector import HybridDetector
            self.ml_detectors['hybrid'] = HybridDetector()
            logger.info("✅ Détecteur hybride initialisé")
        except Exception as e:
            logger.warning(f"⚠️ Détecteur hybride non disponible: {e}")
        
        try:
            from ml_engine.ultra_detector import UltraDetector
            self.ml_detectors['ultra'] = UltraDetector()
            logger.info("✅ Détecteur ultra initialisé")
        except Exception as e:
            logger.warning(f"⚠️ Détecteur ultra non disponible: {e}")
        
        try:
            from ml_engine.ransomware_detector import RansomwareDetector
            self.ml_detectors['ransomware'] = RansomwareDetector()
            logger.info("✅ Détecteur ransomware initialisé")
        except Exception as e:
            logger.warning(f"⚠️ Détecteur ransomware non disponible: {e}")
    
    def add_directory(self, directory_path: str) -> bool:
        """Ajouter un répertoire à surveiller"""
        try:
            path = Path(directory_path).resolve()
            if not path.exists() or not path.is_dir():
                logger.error(f"❌ Le répertoire {directory_path} n'existe pas ou n'est pas un dossier")
                return False
            
            # Vérifier les permissions
            if not os.access(path, os.R_OK):
                logger.error(f"❌ Pas de permission de lecture sur {directory_path}")
                return False
            
            # Créer l'objet MonitoredDirectory
            monitored_dir = MonitoredDirectory(
                path=str(path),
                name=path.name,
                total_files=0,
                suspicious_files=0,
                last_scan=datetime.now(),
                file_operations=[]
            )
            
            # Scanner le répertoire initialement
            self.scan_directory_initial(monitored_dir)
            
            self.monitored_dirs[str(path)] = monitored_dir
            logger.info(f"✅ Répertoire {directory_path} ajouté à la surveillance")
            logger.info(f"   📁 Fichiers trouvés: {monitored_dir.total_files}")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Erreur lors de l'ajout du répertoire {directory_path}: {e}")
            return False
    
    def remove_directory(self, directory_path: str) -> bool:
        """Retirer un répertoire de la surveillance"""
        try:
            path = str(Path(directory_path).resolve())
            if path in self.monitored_dirs:
                del self.monitored_dirs[path]
                logger.info(f"✅ Répertoire {directory_path} retiré de la surveillance")
                return True
            else:
                logger.warning(f"⚠️ Répertoire {directory_path} n'était pas surveillé")
                return False
        except Exception as e:
            logger.error(f"❌ Erreur lors de la suppression du répertoire {directory_path}: {e}")
            return False
    
    def scan_directory_initial(self, monitored_dir: MonitoredDirectory):
        """Scanner un répertoire pour la première fois"""
        try:
            path = Path(monitored_dir.path)
            file_count = 0
            suspicious_count = 0
            
            for file_path in path.rglob('*'):
                if file_path.is_file():
                    file_count += 1
                    
                    # Vérifier si le fichier est suspect
                    if self.is_file_suspicious(file_path):
                        suspicious_count += 1
            
            monitored_dir.total_files = file_count
            monitored_dir.suspicious_files = suspicious_count
            monitored_dir.last_scan = datetime.now()
            
        except Exception as e:
            logger.error(f"❌ Erreur lors du scan initial de {monitored_dir.path}: {e}")
    
    def is_file_suspicious(self, file_path: Path) -> bool:
        """Vérifier si un fichier est suspect"""
        try:
            # Vérifier l'extension
            if file_path.suffix.lower() in self.suspicious_extensions:
                return True
            
            # Vérifier le nom du fichier
            filename_lower = file_path.name.lower()
            suspicious_patterns = [
                'crypto', 'encrypt', 'decrypt', 'ransom', 'malware',
                'trojan', 'virus', 'spyware', 'keylogger', 'backdoor',
                'hack', 'exploit', 'payload', 'shell'
            ]
            
            for pattern in suspicious_patterns:
                if pattern in filename_lower:
                    return True
            
            # Vérifier le répertoire
            dir_parts = [part.lower() for part in file_path.parts]
            for critical_dir in self.critical_dirs:
                if critical_dir in dir_parts:
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"❌ Erreur lors de la vérification du fichier {file_path}: {e}")
            return False
    
    async def analyze_file_with_ml(self, file_path: str) -> Dict[str, Any]:
        """Analyser un fichier avec les modèles ML"""
        try:
            results = {}
            
            # Analyser avec le détecteur hybride
            if 'hybrid' in self.ml_detectors:
                try:
                    hybrid_result = await self.ml_detectors['hybrid'].analyze_file_hybrid(file_path, {})
                    results['hybrid'] = hybrid_result
                except Exception as e:
                    logger.warning(f"⚠️ Erreur détecteur hybride: {e}")
            
            # Analyser avec le détecteur ultra
            if 'ultra' in self.ml_detectors:
                try:
                    ultra_result = await self.ml_detectors['ultra'].analyze_file_ultra(file_path, {})
                    results['ultra'] = ultra_result
                except Exception as e:
                    logger.warning(f"⚠️ Erreur détecteur ultra: {e}")
            
            # Analyser avec le détecteur ransomware
            if 'ransomware' in self.ml_detectors:
                try:
                    ransomware_result = await self.ml_detectors['ransomware'].detect_ransomware(file_path)
                    results['ransomware'] = ransomware_result
                except Exception as e:
                    logger.warning(f"⚠️ Erreur détecteur ransomware: {e}")

            # Threat Intelligence: vérifier le hash contre les IOC (MalwareBazaar, listes locales)
            try:
                from ml_engine.threat_intelligence import ThreatIntelligence
                ti = ThreatIntelligence()
                # Calculer hash si non calculé
                if not results.get('file_hash'):
                    try:
                        file_hash_local = await self.calculate_file_hash(file_path)
                    except Exception:
                        file_hash_local = ''
                else:
                    file_hash_local = results.get('file_hash')
                if file_hash_local:
                    ti_result = await ti.query_hash(file_hash_local)
                    results['threat_intelligence'] = ti_result
            except Exception as e:
                logger.debug(f"ThreatIntelligence indisponible: {e}")
            
            return results
            
        except Exception as e:
            logger.error(f"❌ Erreur lors de l'analyse ML de {file_path}: {e}")
            return {}
    
    async def monitor_file_operations(self):
        """Surveiller les opérations sur les fichiers"""
        logger.info("🔍 Démarrage de la surveillance des opérations de fichiers...")
        
        while self.monitoring_active:
            try:
                # Simuler la détection d'opérations (dans un vrai système, on utiliserait des hooks système)
                await self.detect_file_operations()
                await asyncio.sleep(2)  # Vérifier toutes les 2 secondes
                
            except Exception as e:
                logger.error(f"❌ Erreur lors de la surveillance des fichiers: {e}")
                await asyncio.sleep(5)
    
    async def detect_file_operations(self):
        """Détecter les opérations sur les fichiers (simulation pour l'instant)"""
        try:
            for dir_path, monitored_dir in self.monitored_dirs.items():
                path = Path(dir_path)
                
                # Vérifier les nouveaux fichiers
                for file_path in path.rglob('*'):
                    if file_path.is_file():
                        # Vérifier si c'est un nouveau fichier
                        if not any(op.file_path == str(file_path) for op in monitored_dir.file_operations):
                            await self.handle_file_operation('create', str(file_path))
                
                # Vérifier les fichiers supprimés
                existing_files = set(str(f) for f in path.rglob('*') if f.is_file())
                for op in monitored_dir.file_operations:
                    if op.operation_type == 'create' and op.file_path not in existing_files:
                        await self.handle_file_operation('delete', op.file_path)
                
        except Exception as e:
            logger.error(f"❌ Erreur lors de la détection des opérations: {e}")
    
    async def handle_file_operation(self, operation_type: str, file_path: str):
        """Gérer une opération sur un fichier"""
        try:
            # Obtenir les informations sur le processus qui a effectué l'opération
            process_info = self.get_process_info()
            
            # Obtenir les informations sur le fichier
            file_stat = os.stat(file_path)
            file_size = file_stat.st_size
            
            # Calculer le hash du fichier
            file_hash = await self.calculate_file_hash(file_path)
            
            # Créer l'objet FileOperation
            file_op = FileOperation(
                operation_type=operation_type,
                file_path=file_path,
                timestamp=datetime.now(),
                process_name=process_info.get('name', 'Unknown'),
                process_pid=process_info.get('pid', 0),
                file_size=file_size,
                file_hash=file_hash
            )
            
            # Analyser le fichier avec les modèles ML
            ml_results = await self.analyze_file_with_ml(file_path)
            file_op.ml_detection = ml_results
            
            # Calculer le score de menace
            threat_score = await self.calculate_threat_score(file_op, ml_results)
            file_op.threat_score = threat_score
            file_op.is_suspicious = threat_score > 0.5
            
            # Ajouter l'opération à la liste
            self.file_operations.append(file_op)
            
            # Ajouter au répertoire surveillé et mettre à jour le niveau
            for mdir in self.monitored_dirs.values():
                if file_path.startswith(mdir.path):
                    mdir.file_operations.append(file_op)
                    if file_op.is_suspicious:
                        mdir.suspicious_files += 1
                    await self.update_directory_threat_level(mdir)
                    break

            # Diffuser l'événement via WebSocket si possible
            try:
                from websocket_manager import send_file_event
                await send_file_event(operation_type, file_path, file_op.is_suspicious)
            except Exception as _ws_err:
                logger.debug(f"WS non disponible pour événement fichier: {_ws_err}")
            
            # Logger l'opération
            if file_op.is_suspicious:
                logger.warning(f"🚨 Opération suspecte détectée: {operation_type} sur {file_path}")
                logger.warning(f"   Score de menace: {threat_score:.2f}")
                self.suspicious_operations.append(file_op)
            else:
                logger.info(f"📝 Opération: {operation_type} sur {file_path}")
            
        except Exception as e:
            logger.error(f"❌ Erreur lors du traitement de l'opération {operation_type} sur {file_path}: {e}")
    
    async def calculate_threat_score(self, file_op: FileOperation, ml_results: Dict[str, Any]) -> float:
        """Calculer le score de menace d'un fichier"""
        threat_score = 0.0
        
        try:
            # Score basé sur l'extension
            file_ext = Path(file_op.file_path).suffix.lower()
            if file_ext in self.suspicious_extensions:
                threat_score += 0.3
            
            # Score basé sur le nom du fichier
            filename_lower = Path(file_op.file_path).name.lower()
            suspicious_patterns = ['crypto', 'encrypt', 'decrypt', 'ransom', 'malware']
            for pattern in suspicious_patterns:
                if pattern in filename_lower:
                    threat_score += 0.4
             
            # Score basé sur les résultats ML
            if ml_results:
                # Détecteur hybride
                if 'hybrid' in ml_results:
                    hybrid_score = ml_results['hybrid'].get('confidence', 0.0)
                    if isinstance(hybrid_score, (int, float)):
                        threat_score += hybrid_score * 0.3
                 
                # Détecteur ultra
                if 'ultra' in ml_results:
                    ultra_score = ml_results['ultra'].get('final_score', 0.0)
                    if isinstance(ultra_score, (int, float)):
                        threat_score += ultra_score * 0.3
                 
                # Détecteur ransomware
                if 'ransomware' in ml_results:
                    ransom_score = ml_results['ransomware'].get('threat_score', 0.0)
                    if isinstance(ransom_score, (int, float)):
                        threat_score += ransom_score * 0.4
 
                # Threat Intelligence (hash dans listes)
                ti = ml_results.get('threat_intelligence') or {}
                is_bad_local = bool(ti.get('is_malicious_local'))
                is_bad_remote = bool(ti.get('is_malicious_remote'))
                if is_bad_local:
                    threat_score += 0.5
                if is_bad_remote:
                    threat_score += 0.6

            # Diminuer les faux positifs sur types de fichiers bénins si aucune autre preuve forte
            benign_exts = {'.pdf', '.png', '.jpg', '.jpeg', '.gif', '.txt', '.docx', '.xlsx', '.pptx', '.odt'}
            if file_ext in benign_exts and ml_results:
                hybrid_conf = float(ml_results.get('hybrid', {}).get('confidence', 0.0) or 0.0)
                ransom_conf = float(ml_results.get('ransomware', {}).get('threat_score', 0.0) or 0.0)
                ti_bad = bool((ml_results.get('threat_intelligence') or {}).get('is_malicious_local') or (ml_results.get('threat_intelligence') or {}).get('is_malicious_remote'))
                if not ti_bad and hybrid_conf < 0.5 and ransom_conf < 0.5:
                    threat_score *= 0.5
             
            # Limiter le score
            threat_score = min(threat_score, 1.0)
             
        except Exception as e:
            logger.error(f"❌ Erreur lors du calcul du score de menace: {e}")
         
        return threat_score
    
    async def update_directory_threat_level(self, monitored_dir: MonitoredDirectory):
        """Mettre à jour le niveau de menace d'un répertoire"""
        try:
            suspicious_count = len([op for op in monitored_dir.file_operations if op.is_suspicious])
            total_operations = len(monitored_dir.file_operations)
            
            if total_operations == 0:
                monitored_dir.threat_level = "LOW"
            else:
                suspicious_ratio = suspicious_count / total_operations
                
                if suspicious_ratio >= 0.7:
                    monitored_dir.threat_level = "CRITICAL"
                elif suspicious_ratio >= 0.5:
                    monitored_dir.threat_level = "HIGH"
                elif suspicious_ratio >= 0.2:
                    monitored_dir.threat_level = "MEDIUM"
                else:
                    monitored_dir.threat_level = "LOW"
                    
        except Exception as e:
            logger.error(f"❌ Erreur lors de la mise à jour du niveau de menace: {e}")
    
    def get_process_info(self) -> Dict[str, Any]:
        """Obtenir les informations sur le processus actuel"""
        try:
            current_pid = os.getpid()
            process = psutil.Process(current_pid)
            return {
                'pid': current_pid,
                'name': process.name(),
                'exe': process.exe()
            }
        except Exception as e:
            logger.error(f"❌ Erreur lors de l'obtention des infos processus: {e}")
            return {'pid': 0, 'name': 'Unknown', 'exe': ''}
    
    async def calculate_file_hash(self, file_path: str) -> str:
        """Calculer le hash SHA-256 d'un fichier"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            logger.error(f"❌ Erreur lors du calcul du hash de {file_path}: {e}")
            return ""
    
    def get_monitoring_summary(self) -> Dict[str, Any]:
        """Obtenir un résumé de la surveillance"""
        total_dirs = len(self.monitored_dirs)
        total_operations = len(self.file_operations)
        suspicious_operations = len(self.suspicious_operations)
        
        # Statistiques par répertoire
        dir_stats = []
        for dir_path, monitored_dir in self.monitored_dirs.items():
            dir_stats.append({
                'path': dir_path,
                'name': monitored_dir.name,
                'total_files': monitored_dir.total_files,
                'suspicious_files': monitored_dir.suspicious_files,
                'threat_level': monitored_dir.threat_level,
                'last_scan': monitored_dir.last_scan.isoformat(),
                'operations_count': len(monitored_dir.file_operations)
            })
        
        # Opérations récentes
        recent_operations = []
        for op in sorted(self.file_operations, key=lambda x: x.timestamp, reverse=True)[:10]:
            recent_operations.append({
                'operation_type': op.operation_type,
                'file_path': op.file_path,
                'timestamp': op.timestamp.isoformat(),
                'process_name': op.process_name,
                'threat_score': op.threat_score,
                'is_suspicious': op.is_suspicious
            })
        
        return {
            'total_monitored_directories': total_dirs,
            'total_file_operations': total_operations,
            'suspicious_operations': suspicious_operations,
            'directories': dir_stats,
            'recent_operations': recent_operations,
            'last_update': datetime.now().isoformat()
        }
    
    async def start_monitoring(self):
        """Démarrer la surveillance"""
        logger.info("🚀 Démarrage de la surveillance des fichiers...")
        self.monitoring_active = True
        
        # Démarrer la surveillance des opérations
        monitor_task = asyncio.create_task(self.monitor_file_operations())
        
        try:
            while self.monitoring_active:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            logger.info("⏹️ Arrêt demandé par l'utilisateur...")
        finally:
            self.monitoring_active = False
            monitor_task.cancel()
            logger.info("✅ Surveillance des fichiers arrêtée")
    
    def stop_monitoring(self):
        """Arrêter la surveillance"""
        self.monitoring_active = False

# Instance globale
file_monitor = RealFileMonitor()

async def main():
    """Fonction principale de test"""
    logger.info("🚀 Test du moniteur de fichiers réel...")
    
    # Ajouter des répertoires de test
    test_dirs = [
        os.path.expanduser("~/Desktop"),
        os.path.expanduser("~/Documents"),
        os.path.expanduser("~/Downloads")
    ]
    
    for test_dir in test_dirs:
        if os.path.exists(test_dir):
            file_monitor.add_directory(test_dir)
    
    # Démarrer la surveillance
    monitor_task = asyncio.create_task(file_monitor.start_monitoring())
    
    try:
        # Attendre un peu pour collecter des données
        await asyncio.sleep(15)
        
        # Afficher un résumé
        summary = file_monitor.get_monitoring_summary()
        logger.info("📊 Résumé de la surveillance des fichiers:")
        logger.info(f"  Répertoires surveillés: {summary['total_monitored_directories']}")
        logger.info(f"  Opérations totales: {summary['total_file_operations']}")
        logger.info(f"  Opérations suspectes: {summary['suspicious_operations']}")
        
        if summary['directories']:
            logger.info("📁 Répertoires surveillés:")
            for dir_info in summary['directories']:
                logger.info(f"  - {dir_info['name']}: {dir_info['total_files']} fichiers, "
                          f"Niveau: {dir_info['threat_level']}")
        
        if summary['recent_operations']:
            logger.info("📝 Opérations récentes:")
            for op in summary['recent_operations'][:5]:
                status = "🚨" if op['is_suspicious'] else "✅"
                logger.info(f"  {status} {op['operation_type']} sur {op['file_path']}")
        
    except KeyboardInterrupt:
        logger.info("⏹️ Arrêt demandé par l'utilisateur...")
    finally:
        # Arrêter la surveillance
        file_monitor.stop_monitoring()
        monitor_task.cancel()
        logger.info("✅ Moniteur de fichiers arrêté")

if __name__ == "__main__":
    asyncio.run(main())

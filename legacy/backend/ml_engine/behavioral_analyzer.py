#!/usr/bin/env python3
"""
Analyseur comportemental avancé pour RansomGuard AI
Détection des ransomwares basée sur l'analyse comportementale
Hackathon Togo IT Days 2025
"""

import os
import sys
import time
import json
import logging
import asyncio
import psutil
import threading
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
import winreg
import subprocess

logger = logging.getLogger(__name__)

@dataclass
class BehavioralPattern:
    """Pattern comportemental détecté"""
    pattern_type: str
    confidence: float
    description: str
    indicators: List[str]
    severity: str
    timestamp: float

@dataclass
class ProcessBehavior:
    """Comportement d'un processus"""
    pid: int
    name: str
    command_line: str
    file_operations: List[str]
    network_connections: List[str]
    registry_operations: List[str]
    suspicious_activities: List[str]
    risk_score: float

class BehavioralAnalyzer:
    """Analyseur comportemental avancé pour détecter les ransomwares"""
    
    def __init__(self):
        self.suspicious_patterns = {
            'file_encryption': [
                '*.encrypted', '*.locked', '*.crypto', '*.ransom',
                '*.cryptolocker', '*.wannacry', '*.petya'
            ],
            'suspicious_commands': [
                'cipher', 'certutil', 'powershell -enc', 'wmic',
                'vssadmin delete shadows', 'bcdedit', 'fsutil'
            ],
            'suspicious_processes': [
                'cryptolocker.exe', 'wannacry.exe', 'petya.exe',
                'locky.exe', 'cerber.exe', 'spora.exe'
            ],
            'suspicious_extensions': [
                '.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js'
            ]
        }
        
        self.monitoring_active = False
        self.processes_monitored = {}
        self.behavioral_log = []
        
    async def start_behavioral_monitoring(self) -> bool:
        """Démarrer la surveillance comportementale"""
        try:
            logger.info("🔍 Démarrage de la surveillance comportementale...")
            
            # Démarrer la surveillance des processus
            self.monitoring_active = True
            monitoring_thread = threading.Thread(
                target=self._monitor_processes,
                daemon=True
            )
            monitoring_thread.start()
            
            # Démarrer la surveillance des fichiers
            file_monitoring_thread = threading.Thread(
                target=self._monitor_file_system,
                daemon=True
            )
            file_monitoring_thread.start()
            
            # Démarrer la surveillance du registre
            registry_monitoring_thread = threading.Thread(
                target=self._monitor_registry,
                daemon=True
            )
            registry_monitoring_thread.start()
            
            logger.info("✅ Surveillance comportementale démarrée")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erreur démarrage surveillance: {e}")
            return False
    
    def stop_behavioral_monitoring(self):
        """Arrêter la surveillance comportementale"""
        logger.info("⏹️ Arrêt de la surveillance comportementale...")
        self.monitoring_active = False
    
    def _monitor_processes(self):
        """Surveiller les processus en arrière-plan"""
        while self.monitoring_active:
            try:
                current_processes = {}
                
                for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
                    try:
                        proc_info = proc.info
                        pid = proc_info['pid']
                        
                        # Analyser le comportement du processus
                        behavior = self._analyze_process_behavior(proc)
                        current_processes[pid] = behavior
                        
                        # Détecter les nouveaux processus suspects
                        if pid not in self.processes_monitored:
                            if behavior.risk_score > 0.3:
                                logger.warning(f"⚠️ Nouveau processus suspect: {behavior.name} (PID: {pid}, Score: {behavior.risk_score:.2f})")
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                self.processes_monitored = current_processes
                time.sleep(2)  # Vérifier toutes les 2 secondes
                
            except Exception as e:
                logger.error(f"❌ Erreur surveillance processus: {e}")
                time.sleep(5)
    
    def _monitor_file_system(self):
        """Surveiller le système de fichiers"""
        while self.monitoring_active:
            try:
                # Vérifier les dossiers sensibles
                sensitive_dirs = [
                    os.path.expanduser("~/Desktop"),
                    os.path.expanduser("~/Documents"),
                    os.path.expanduser("~/Downloads"),
                    "C:/Users"
                ]
                
                for directory in sensitive_dirs:
                    if os.path.exists(directory):
                        self._check_directory_for_encryption(directory)
                
                time.sleep(5)  # Vérifier toutes les 5 secondes
                
            except Exception as e:
                logger.error(f"❌ Erreur surveillance fichiers: {e}")
                time.sleep(10)
    
    def _monitor_registry(self):
        """Surveiller le registre Windows"""
        while self.monitoring_active:
            try:
                # Vérifier les clés de registre sensibles
                sensitive_keys = [
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce")
                ]
                
                for hkey, subkey in sensitive_keys:
                    try:
                        self._check_registry_key(hkey, subkey)
                    except Exception as e:
                        logger.debug(f"Impossible d'accéder à {subkey}: {e}")
                
                time.sleep(10)  # Vérifier toutes les 10 secondes
                
            except Exception as e:
                logger.error(f"❌ Erreur surveillance registre: {e}")
                time.sleep(15)
    
    def _analyze_process_behavior(self, proc: psutil.Process) -> ProcessBehavior:
        """Analyser le comportement d'un processus"""
        try:
            # Informations de base
            name = proc.name()
            cmdline = ' '.join(proc.cmdline()) if proc.cmdline() else ''
            
            # Analyser les opérations de fichiers
            file_ops = self._get_file_operations(proc)
            
            # Analyser les connexions réseau
            network_conns = self._get_network_connections(proc)
            
            # Analyser les opérations de registre
            registry_ops = self._get_registry_operations(proc)
            
            # Calculer le score de risque
            risk_score = self._calculate_risk_score(
                name, cmdline, file_ops, network_conns, registry_ops
            )
            
            # Détecter les activités suspectes
            suspicious_activities = self._detect_suspicious_activities(
                name, cmdline, file_ops, network_conns, registry_ops
            )
            
            return ProcessBehavior(
                pid=proc.pid,
                name=name,
                command_line=cmdline,
                file_operations=file_ops,
                network_connections=network_conns,
                registry_operations=registry_ops,
                suspicious_activities=suspicious_activities,
                risk_score=risk_score
            )
            
        except Exception as e:
            logger.error(f"❌ Erreur analyse comportement processus {proc.pid}: {e}")
            return ProcessBehavior(
                pid=proc.pid,
                name="unknown",
                command_line="",
                file_operations=[],
                network_connections=[],
                registry_operations=[],
                suspicious_activities=[],
                risk_score=0.0
            )
    
    def _get_file_operations(self, proc: psutil.Process) -> List[str]:
        """Obtenir les opérations de fichiers d'un processus"""
        try:
            # Utiliser handle.exe pour lister les handles de fichiers
            result = subprocess.run(
                ['handle.exe', '-p', str(proc.pid)],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                return result.stdout.split('\n')
            else:
                return []
                
        except Exception:
            return []
    
    def _get_network_connections(self, proc: psutil.Process) -> List[str]:
        """Obtenir les connexions réseau d'un processus"""
        try:
            connections = proc.connections()
            return [f"{conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port}" 
                   for conn in connections if conn.raddr]
        except Exception:
            return []
    
    def _get_registry_operations(self, proc: psutil.Process) -> List[str]:
        """Obtenir les opérations de registre d'un processus"""
        # Cette fonction nécessiterait des outils avancés comme Process Monitor
        # Pour l'instant, retourner une liste vide
        return []
    
    def _calculate_risk_score(self, name: str, cmdline: str, 
                            file_ops: List[str], network_conns: List[str], 
                            registry_ops: List[str]) -> float:
        """Calculer le score de risque d'un processus"""
        score = 0.0
        
        # Vérifier le nom du processus
        if any(susp in name.lower() for susp in self.suspicious_patterns['suspicious_processes']):
            score += 0.4
        
        # Vérifier la ligne de commande
        if any(susp in cmdline.lower() for susp in self.suspicious_patterns['suspicious_commands']):
            score += 0.3
        
        # Vérifier les opérations de fichiers
        if len(file_ops) > 100:  # Beaucoup d'opérations de fichiers
            score += 0.2
        
        # Vérifier les connexions réseau
        if len(network_conns) > 10:  # Beaucoup de connexions
            score += 0.1
        
        return min(score, 1.0)
    
    def _detect_suspicious_activities(self, name: str, cmdline: str,
                                    file_ops: List[str], network_conns: List[str],
                                    registry_ops: List[str]) -> List[str]:
        """Détecter les activités suspectes"""
        activities = []
        
        # Vérifier les commandes suspectes
        for cmd in self.suspicious_patterns['suspicious_commands']:
            if cmd in cmdline.lower():
                activities.append(f"Commande suspecte: {cmd}")
        
        # Vérifier les processus suspects
        for proc in self.suspicious_patterns['suspicious_processes']:
            if proc in name.lower():
                activities.append(f"Processus suspect: {proc}")
        
        # Vérifier les opérations de fichiers massives
        if len(file_ops) > 200:
            activities.append("Opérations de fichiers massives")
        
        # Vérifier les connexions réseau suspectes
        if len(network_conns) > 20:
            activities.append("Connexions réseau nombreuses")
        
        return activities
    
    def _check_directory_for_encryption(self, directory: str):
        """Vérifier un répertoire pour détecter l'encryption"""
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    # Vérifier les extensions suspectes
                    if any(ext in file.lower() for ext in self.suspicious_patterns['file_encryption']):
                        logger.warning(f"⚠️ Fichier encrypté détecté: {os.path.join(root, file)}")
                        
                        # Analyser le processus qui a créé ce fichier
                        self._investigate_file_creation(os.path.join(root, file))
                        
        except Exception as e:
            logger.debug(f"Impossible d'accéder au répertoire {directory}: {e}")
    
    def _check_registry_key(self, hkey, subkey: str):
        """Vérifier une clé de registre pour des modifications suspectes"""
        try:
            with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        
                        # Vérifier les valeurs suspectes
                        if any(susp in str(value).lower() for susp in self.suspicious_patterns['suspicious_processes']):
                            logger.warning(f"⚠️ Valeur de registre suspecte dans {subkey}: {name} = {value}")
                        
                        i += 1
                    except WindowsError:
                        break
                        
        except Exception as e:
            logger.debug(f"Impossible d'accéder à la clé de registre {subkey}: {e}")
    
    def _investigate_file_creation(self, file_path: str):
        """Enquêter sur la création d'un fichier suspect"""
        try:
            # Obtenir les informations du fichier
            stat = os.stat(file_path)
            creation_time = stat.st_ctime
            
            # Chercher les processus qui ont accédé à ce fichier récemment
            for proc in psutil.process_iter(['pid', 'name', 'create_time']):
                try:
                    if abs(proc.info['create_time'] - creation_time) < 60:  # Dans la minute
                        logger.info(f"🔍 Processus suspect pour {file_path}: {proc.info['name']} (PID: {proc.info['pid']})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            logger.error(f"❌ Erreur investigation fichier {file_path}: {e}")
    
    async def analyze_behavioral_threats(self) -> Dict[str, Any]:
        """Analyser les menaces comportementales détectées"""
        try:
            logger.info("🔍 Analyse des menaces comportementales...")
            
            threats = []
            high_risk_processes = []
            
            # Analyser les processus à haut risque
            for pid, behavior in self.processes_monitored.items():
                if behavior.risk_score > 0.5:
                    high_risk_processes.append({
                        'pid': pid,
                        'name': behavior.name,
                        'risk_score': behavior.risk_score,
                        'suspicious_activities': behavior.suspicious_activities
                    })
                    
                    if behavior.risk_score > 0.7:
                        threats.append({
                            'type': 'high_risk_process',
                            'severity': 'high',
                            'description': f"Processus à haut risque: {behavior.name}",
                            'indicators': behavior.suspicious_activities,
                            'confidence': behavior.risk_score
                        })
            
            # Analyser les patterns comportementaux
            behavioral_patterns = self._analyze_behavioral_patterns()
            
            # Résumé des menaces
            threat_summary = {
                'total_threats': len(threats),
                'high_risk_processes': len(high_risk_processes),
                'behavioral_patterns': len(behavioral_patterns),
                'threats': threats,
                'high_risk_processes_details': high_risk_processes,
                'behavioral_patterns_details': behavioral_patterns,
                'monitoring_status': {
                    'active': self.monitoring_active,
                    'processes_monitored': len(self.processes_monitored),
                    'last_analysis': time.time()
                }
            }
            
            logger.info(f"✅ Analyse comportementale terminée: {len(threats)} menaces détectées")
            return threat_summary
            
        except Exception as e:
            logger.error(f"❌ Erreur analyse comportementale: {e}")
            return {
                'error': str(e),
                'total_threats': 0,
                'high_risk_processes': 0,
                'behavioral_patterns': 0
            }
    
    def _analyze_behavioral_patterns(self) -> List[BehavioralPattern]:
        """Analyser les patterns comportementaux détectés"""
        patterns = []
        
        # Pattern: Opérations de fichiers massives
        if any(len(proc.file_operations) > 200 for proc in self.processes_monitored.values()):
            patterns.append(BehavioralPattern(
                pattern_type="mass_file_operations",
                confidence=0.7,
                description="Opérations de fichiers massives détectées",
                indicators=["Plus de 200 opérations de fichiers par processus"],
                severity="medium",
                timestamp=time.time()
            ))
        
        # Pattern: Connexions réseau nombreuses
        if any(len(proc.network_connections) > 20 for proc in self.processes_monitored.values()):
            patterns.append(BehavioralPattern(
                pattern_type="mass_network_connections",
                confidence=0.6,
                description="Connexions réseau nombreuses détectées",
                indicators=["Plus de 20 connexions réseau par processus"],
                severity="medium",
                timestamp=time.time()
            ))
        
        # Pattern: Processus suspects multiples
        suspicious_count = sum(1 for proc in self.processes_monitored.values() if proc.risk_score > 0.5)
        if suspicious_count > 3:
            patterns.append(BehavioralPattern(
                pattern_type="multiple_suspicious_processes",
                confidence=0.8,
                description="Plusieurs processus suspects détectés",
                indicators=[f"{suspicious_count} processus avec score de risque > 0.5"],
                severity="high",
                timestamp=time.time()
            ))
        
        return patterns
    
    def get_behavioral_log(self) -> List[Dict[str, Any]]:
        """Obtenir le journal comportemental"""
        return self.behavioral_log
    
    def export_behavioral_data(self, filepath: str) -> bool:
        """Exporter les données comportementales"""
        try:
            export_data = {
                'timestamp': time.time(),
                'monitoring_status': {
                    'active': self.monitoring_active,
                    'processes_monitored': len(self.processes_monitored)
                },
                'processes': {
                    str(pid): {
                        'name': behavior.name,
                        'risk_score': behavior.risk_score,
                        'suspicious_activities': behavior.suspicious_activities
                    }
                    for pid, behavior in self.processes_monitored.items()
                },
                'behavioral_log': self.behavioral_log
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"✅ Données comportementales exportées vers {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erreur export données comportementales: {e}")
            return False

# Instance globale
behavioral_analyzer = BehavioralAnalyzer()

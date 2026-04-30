#!/usr/bin/env python3
"""
Système de réponse automatique aux menaces pour RansomGuard AI
Actions automatiques de protection et de neutralisation
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
import subprocess
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
import winreg
import shutil

logger = logging.getLogger(__name__)

@dataclass
class ThreatResponse:
    """Réponse à une menace détectée"""
    threat_id: str
    response_type: str
    action_taken: str
    target: str
    success: bool
    timestamp: float
    details: Dict[str, Any]

@dataclass
class ResponseRule:
    """Règle de réponse automatique"""
    rule_id: str
    threat_type: str
    severity_threshold: float
    actions: List[str]
    enabled: bool
    description: str

class AutoResponseSystem:
    """Système de réponse automatique aux menaces"""

    def __init__(self):
        self.response_rules = self._load_default_rules()
        self.active_responses = {}
        self.response_history = []
        self.auto_response_enabled = True
        self.quarantine_directory = Path("quarantine")
        self.quarantine_directory.mkdir(exist_ok=True)
        
        # Actions disponibles
        self.available_actions = {
            'isolate_process': self._isolate_process,
            'kill_process': self._kill_process,
            'block_network': self._block_network,
            'quarantine_file': self._quarantine_file,
            'disable_user': self._disable_user,
            'lock_system': self._lock_system,
            'backup_files': self._backup_files,
            'notify_admin': self._notify_admin
        }

    def _load_default_rules(self) -> Dict[str, ResponseRule]:
        """Charger les règles de réponse par défaut"""
        rules = {
            'high_risk_process': ResponseRule(
                rule_id='high_risk_process',
                threat_type='malicious_process',
                severity_threshold=0.8,
                actions=['isolate_process', 'quarantine_file', 'notify_admin'],
                enabled=True,
                description='Isoler les processus à haut risque'
            ),
            'network_attack': ResponseRule(
                rule_id='network_attack',
                threat_type='network_threat',
                severity_threshold=0.7,
                actions=['block_network', 'isolate_process', 'notify_admin'],
                enabled=True,
                description='Bloquer les attaques réseau'
            ),
            'file_encryption': ResponseRule(
                rule_id='file_encryption',
                threat_type='ransomware',
                severity_threshold=0.6,
                actions=['quarantine_file', 'backup_files', 'isolate_process', 'lock_system'],
                enabled=True,
                description='Réponse immédiate aux ransomwares'
            ),
            'system_compromise': ResponseRule(
                rule_id='system_compromise',
                threat_type='system_threat',
                severity_threshold=0.9,
                actions=['lock_system', 'disable_user', 'notify_admin'],
                enabled=True,
                description='Verrouiller le système en cas de compromission'
            )
        }
        return rules

    async def auto_respond_to_threat(self, threat_data: Dict[str, Any]) -> ThreatResponse:
        """Répondre automatiquement à une menace détectée"""
        try:
            if not self.auto_response_enabled:
                logger.info("⚠️ Réponse automatique désactivée")
                return ThreatResponse(
                    threat_id=threat_data.get('id', 'unknown'),
                    response_type='none',
                    action_taken='Réponse automatique désactivée',
                    target='system',
                    success=False,
                    timestamp=time.time(),
                    details={'reason': 'auto_response_disabled'}
                )

            logger.info(f"🚨 Réponse automatique à la menace: {threat_data.get('type', 'unknown')}")

            # Déterminer le type de menace et la sévérité
            threat_type = threat_data.get('type', 'unknown')
            severity = threat_data.get('severity', 0.0)
            confidence = threat_data.get('confidence', 0.0)

            # Trouver la règle applicable
            applicable_rule = self._find_applicable_rule(threat_type, severity, confidence)
            
            if not applicable_rule:
                logger.info(f"ℹ️ Aucune règle applicable pour {threat_type} (sévérité: {severity})")
                return ThreatResponse(
                    threat_id=threat_data.get('id', 'unknown'),
                    response_type='none',
                    action_taken='Aucune règle applicable',
                    target='system',
                    success=False,
                    timestamp=time.time(),
                    details={'reason': 'no_applicable_rule'}
                )

            # Exécuter les actions de réponse
            actions_executed = []
            actions_success = []

            for action_name in applicable_rule.actions:
                if action_name in self.available_actions:
                    try:
                        action_result = await self.available_actions[action_name](threat_data)
                        actions_executed.append(action_name)
                        if action_result:
                            actions_success.append(action_name)
                        logger.info(f"✅ Action {action_name} exécutée: {action_result}")
                    except Exception as e:
                        logger.error(f"❌ Erreur action {action_name}: {e}")
                        actions_executed.append(f"{action_name}_failed")

            # Créer la réponse
            response = ThreatResponse(
                threat_id=threat_data.get('id', 'unknown'),
                response_type=applicable_rule.rule_id,
                action_taken=f"Actions: {', '.join(actions_executed)}",
                target=threat_data.get('target', 'unknown'),
                success=len(actions_success) > 0,
                timestamp=time.time(),
                details={
                    'rule_applied': applicable_rule.rule_id,
                    'actions_executed': actions_executed,
                    'actions_success': actions_success,
                    'threat_data': threat_data
                }
            )

            # Enregistrer la réponse
            self.response_history.append(response)
            self.active_responses[response.threat_id] = response

            logger.info(f"✅ Réponse automatique terminée: {len(actions_success)}/{len(actions_executed)} actions réussies")
            return response

        except Exception as e:
            logger.error(f"❌ Erreur réponse automatique: {e}")
            return ThreatResponse(
                threat_id=threat_data.get('id', 'unknown'),
                response_type='error',
                action_taken='Erreur lors de la réponse',
                target='system',
                success=False,
                timestamp=time.time(),
                details={'error': str(e)}
            )

    def _find_applicable_rule(self, threat_type: str, severity: float, confidence: float) -> Optional[ResponseRule]:
        """Trouver la règle applicable pour une menace"""
        best_rule = None
        best_score = 0.0

        for rule in self.response_rules.values():
            if not rule.enabled:
                continue

            # Calculer un score de correspondance
            type_match = 1.0 if rule.threat_type == threat_type else 0.5
            severity_match = min(severity / rule.severity_threshold, 1.0) if rule.severity_threshold > 0 else 1.0
            confidence_match = confidence

            score = (type_match + severity_match + confidence_match) / 3

            if score > best_score and score > 0.6:  # Seuil minimum
                best_score = score
                best_rule = rule

        return best_rule

    async def _isolate_process(self, threat_data: Dict[str, Any]) -> bool:
        """Isoler un processus suspect"""
        try:
            process_id = threat_data.get('process_id')
            if not process_id:
                logger.warning("⚠️ Pas d'ID de processus pour l'isolation")
                return False

            # Créer un dossier d'isolation
            isolation_dir = Path(f"isolated_processes/{process_id}")
            isolation_dir.mkdir(parents=True, exist_ok=True)

            # Copier les fichiers du processus
            try:
                proc = psutil.Process(process_id)
                exe_path = proc.exe()
                if exe_path and os.path.exists(exe_path):
                    isolation_path = isolation_dir / Path(exe_path).name
                    shutil.copy2(exe_path, isolation_path)
                    logger.info(f"✅ Processus {process_id} isolé dans {isolation_path}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                logger.warning(f"⚠️ Impossible d'accéder au processus {process_id}")

            # Marquer le processus comme isolé
            threat_data['isolated'] = True
            threat_data['isolation_path'] = str(isolation_dir)

            return True

        except Exception as e:
            logger.error(f"❌ Erreur isolation processus: {e}")
            return False

    async def _kill_process(self, threat_data: Dict[str, Any]) -> bool:
        """Tuer un processus malveillant"""
        try:
            process_id = threat_data.get('process_id')
            if not process_id:
                logger.warning("⚠️ Pas d'ID de processus pour la terminaison")
                return False

            try:
                proc = psutil.Process(process_id)
                proc.terminate()
                
                # Attendre la terminaison
                try:
                    proc.wait(timeout=5)
                    logger.info(f"✅ Processus {process_id} terminé avec succès")
                    return True
                except psutil.TimeoutExpired:
                    # Forcer la terminaison
                    proc.kill()
                    logger.info(f"✅ Processus {process_id} tué de force")
                    return True

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                logger.warning(f"⚠️ Impossible de terminer le processus {process_id}")
                return False

        except Exception as e:
            logger.error(f"❌ Erreur terminaison processus: {e}")
            return False

    async def _block_network(self, threat_data: Dict[str, Any]) -> bool:
        """Bloquer les connexions réseau suspectes"""
        try:
            # Utiliser netsh pour bloquer les connexions
            target_ip = threat_data.get('target_ip')
            target_port = threat_data.get('target_port')

            if target_ip:
                # Bloquer l'IP avec Windows Firewall
                try:
                    cmd = f'netsh advfirewall firewall add rule name="RansomGuard_Block_{target_ip}" dir=out action=block remoteip={target_ip}'
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        logger.info(f"✅ IP {target_ip} bloquée dans le pare-feu")
                        return True
                    else:
                        logger.warning(f"⚠️ Impossible de bloquer l'IP {target_ip}: {result.stderr}")
                        return False

                except Exception as e:
                    logger.error(f"❌ Erreur blocage IP {target_ip}: {e}")
                    return False

            return True

        except Exception as e:
            logger.error(f"❌ Erreur blocage réseau: {e}")
            return False

    async def _quarantine_file(self, threat_data: Dict[str, Any]) -> bool:
        """Mettre en quarantaine un fichier suspect"""
        try:
            file_path = threat_data.get('file_path')
            if not file_path or not os.path.exists(file_path):
                logger.warning("⚠️ Fichier non trouvé pour la quarantaine")
                return False

            # Créer un nom unique pour la quarantaine
            file_name = Path(file_path).name
            quarantine_name = f"{int(time.time())}_{file_name}"
            quarantine_path = self.quarantine_directory / quarantine_name

            # Déplacer le fichier en quarantaine
            try:
                shutil.move(file_path, quarantine_path)
                logger.info(f"✅ Fichier {file_path} mis en quarantaine: {quarantine_path}")
                
                # Créer un fichier de métadonnées
                metadata = {
                    'original_path': file_path,
                    'quarantine_time': time.time(),
                    'threat_data': threat_data,
                    'file_size': os.path.getsize(quarantine_path),
                    'file_hash': self._calculate_file_hash(quarantine_path)
                }
                
                metadata_path = quarantine_path.with_suffix('.metadata.json')
                with open(metadata_path, 'w', encoding='utf-8') as f:
                    json.dump(metadata, f, indent=2, ensure_ascii=False)

                return True

            except Exception as e:
                logger.error(f"❌ Erreur déplacement fichier: {e}")
                return False

        except Exception as e:
            logger.error(f"❌ Erreur quarantaine fichier: {e}")
            return False

    async def _disable_user(self, threat_data: Dict[str, Any]) -> bool:
        """Désactiver un utilisateur suspect"""
        try:
            username = threat_data.get('username')
            if not username:
                logger.warning("⚠️ Pas de nom d'utilisateur pour la désactivation")
                return False

            # Utiliser net user pour désactiver l'utilisateur
            try:
                cmd = f'net user {username} /active:no'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    logger.info(f"✅ Utilisateur {username} désactivé")
                    return True
                else:
                    logger.warning(f"⚠️ Impossible de désactiver l'utilisateur {username}: {result.stderr}")
                    return False

            except Exception as e:
                logger.error(f"❌ Erreur désactivation utilisateur {username}: {e}")
                return False

        except Exception as e:
            logger.error(f"❌ Erreur désactivation utilisateur: {e}")
            return False

    async def _lock_system(self, threat_data: Dict[str, Any]) -> bool:
        """Verrouiller le système"""
        try:
            logger.warning("🚨 VERROUILLAGE DU SYSTÈME ACTIVÉ!")
            
            # Verrouiller la station de travail
            try:
                subprocess.run(['rundll32.exe', 'user32.dll,LockWorkStation'], shell=True)
                logger.info("✅ Système verrouillé")
                return True
            except Exception as e:
                logger.error(f"❌ Erreur verrouillage système: {e}")
                return False

        except Exception as e:
            logger.error(f"❌ Erreur verrouillage système: {e}")
            return False

    async def _backup_files(self, threat_data: Dict[str, Any]) -> bool:
        """Sauvegarder les fichiers importants"""
        try:
            # Créer un dossier de sauvegarde
            backup_dir = Path(f"backups/emergency_{int(time.time())}")
            backup_dir.mkdir(parents=True, exist_ok=True)

            # Dossiers à sauvegarder
            critical_dirs = [
                os.path.expanduser("~/Desktop"),
                os.path.expanduser("~/Documents"),
                os.path.expanduser("~/Downloads")
            ]

            files_backed_up = 0
            for directory in critical_dirs:
                if os.path.exists(directory):
                    try:
                        # Copier les fichiers récents (dernières 24h)
                        current_time = time.time()
                        for root, dirs, files in os.walk(directory):
                            for file in files:
                                file_path = os.path.join(root, file)
                                try:
                                    file_time = os.path.getmtime(file_path)
                                    if current_time - file_time < 86400:  # 24h
                                        relative_path = os.path.relpath(file_path, directory)
                                        backup_path = backup_dir / relative_path
                                        backup_path.parent.mkdir(parents=True, exist_ok=True)
                                        shutil.copy2(file_path, backup_path)
                                        files_backed_up += 1
                                except Exception:
                                    continue
                    except Exception as e:
                        logger.warning(f"⚠️ Erreur sauvegarde dossier {directory}: {e}")

            logger.info(f"✅ {files_backed_up} fichiers sauvegardés dans {backup_dir}")
            return files_backed_up > 0

        except Exception as e:
            logger.error(f"❌ Erreur sauvegarde fichiers: {e}")
            return False

    async def _notify_admin(self, threat_data: Dict[str, Any]) -> bool:
        """Notifier l'administrateur"""
        try:
            # Créer un fichier de notification
            notification = {
                'timestamp': time.time(),
                'threat_data': threat_data,
                'response_taken': 'Auto-response system activated',
                'priority': 'HIGH'
            }

            notification_file = Path(f"notifications/threat_{int(time.time())}.json")
            notification_file.parent.mkdir(exist_ok=True)
            
            with open(notification_file, 'w', encoding='utf-8') as f:
                json.dump(notification, f, indent=2, ensure_ascii=False)

            logger.info(f"✅ Notification admin créée: {notification_file}")
            return True

        except Exception as e:
            logger.error(f"❌ Erreur notification admin: {e}")
            return False

    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculer le hash d'un fichier"""
        try:
            import hashlib
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception:
            return "unknown"

    def get_response_history(self) -> List[ThreatResponse]:
        """Obtenir l'historique des réponses"""
        return self.response_history

    def get_active_responses(self) -> Dict[str, ThreatResponse]:
        """Obtenir les réponses actives"""
        return self.active_responses

    def enable_auto_response(self):
        """Activer la réponse automatique"""
        self.auto_response_enabled = True
        logger.info("✅ Réponse automatique activée")

    def disable_auto_response(self):
        """Désactiver la réponse automatique"""
        self.auto_response_enabled = False
        logger.info("⚠️ Réponse automatique désactivée")

    def add_response_rule(self, rule: ResponseRule):
        """Ajouter une règle de réponse personnalisée"""
        self.response_rules[rule.rule_id] = rule
        logger.info(f"✅ Règle de réponse ajoutée: {rule.rule_id}")

    def remove_response_rule(self, rule_id: str):
        """Supprimer une règle de réponse"""
        if rule_id in self.response_rules:
            del self.response_rules[rule_id]
            logger.info(f"✅ Règle de réponse supprimée: {rule_id}")

    def export_response_data(self, filepath: str) -> bool:
        """Exporter les données de réponse"""
        try:
            export_data = {
                'timestamp': time.time(),
                'auto_response_enabled': self.auto_response_enabled,
                'response_rules': {
                    rule_id: {
                        'threat_type': rule.threat_type,
                        'severity_threshold': rule.severity_threshold,
                        'actions': rule.actions,
                        'enabled': rule.enabled,
                        'description': rule.description
                    }
                    for rule_id, rule in self.response_rules.items()
                },
                'response_history': [
                    {
                        'threat_id': resp.threat_id,
                        'response_type': resp.response_type,
                        'action_taken': resp.action_taken,
                        'target': resp.target,
                        'success': resp.success,
                        'timestamp': resp.timestamp,
                        'details': resp.details
                    }
                    for resp in self.response_history
                ],
                'active_responses': {
                    threat_id: {
                        'response_type': resp.response_type,
                        'action_taken': resp.action_taken,
                        'target': resp.target,
                        'success': resp.success,
                        'timestamp': resp.timestamp
                    }
                    for threat_id, resp in self.active_responses.items()
                }
            }

            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)

            logger.info(f"✅ Données de réponse exportées vers {filepath}")
            return True

        except Exception as e:
            logger.error(f"❌ Erreur export données de réponse: {e}")
            return False

# Instance globale
auto_response_system = AutoResponseSystem()

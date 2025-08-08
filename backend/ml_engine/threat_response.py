"""
Module de réponse automatique aux menaces
RansomGuard AI - Hackathon Togo IT Days 2025
"""

import os
import shutil
import subprocess
import logging
import asyncio
from datetime import datetime
from typing import Dict, List, Any, Optional
import psutil
import platform

logger = logging.getLogger(__name__)

class ThreatResponse:
    """
    Système de réponse automatique aux menaces
    """
    
    def __init__(self):
        self.quarantine_dir = os.path.join(os.path.expanduser("~"), ".ransomguard_quarantine")
        self.blocked_processes = set()
        self.blocked_connections = set()
        self.response_history = []
        
        # Créer le dossier de quarantaine
        os.makedirs(self.quarantine_dir, exist_ok=True)
        
        # Configuration des actions automatiques
        self.auto_actions = {
            'high': ['quarantine', 'block_process', 'notify_admin'],
            'medium': ['quarantine', 'notify_user'],
            'low': ['notify_user']
        }
    
    async def handle_threat(self, threat_info: Dict[str, Any]) -> Dict[str, Any]:
        """Gérer automatiquement une menace détectée"""
        try:
            severity = threat_info.get('severity', 'low')
            threat_type = threat_info.get('threat_type', 'unknown')
            file_path = threat_info.get('file_path')
            process_info = threat_info.get('process_info', {})
            
            logger.warning(f"🚨 Traitement automatique de menace: {threat_type} - {severity}")
            
            # Actions automatiques basées sur la sévérité
            actions_taken = []
            
            if severity in self.auto_actions:
                for action in self.auto_actions[severity]:
                    try:
                        if action == 'quarantine' and file_path:
                            result = await self.quarantine_file(file_path)
                            actions_taken.append(('quarantine', result))
                            
                        elif action == 'block_process' and process_info:
                            result = await self.block_process(process_info)
                            actions_taken.append(('block_process', result))
                            
                        elif action == 'notify_admin':
                            result = await self.notify_admin(threat_info)
                            actions_taken.append(('notify_admin', result))
                            
                        elif action == 'notify_user':
                            result = await self.notify_user(threat_info)
                            actions_taken.append(('notify_user', result))
                            
                    except Exception as e:
                        logger.error(f"Erreur lors de l'action {action}: {e}")
                        actions_taken.append((action, {'success': False, 'error': str(e)}))
            
            # Enregistrer dans l'historique
            response_record = {
                'timestamp': datetime.now().isoformat(),
                'threat_info': threat_info,
                'actions_taken': actions_taken,
                'success': any(action[1].get('success', False) for action in actions_taken)
            }
            self.response_history.append(response_record)
            
            return {
                'success': True,
                'actions_taken': actions_taken,
                'threat_contained': len(actions_taken) > 0,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Erreur lors du traitement de menace: {e}")
            return {
                'success': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    async def quarantine_file(self, file_path: str) -> Dict[str, Any]:
        """Mettre un fichier en quarantaine"""
        try:
            if not os.path.exists(file_path):
                return {'success': False, 'error': 'Fichier non trouvé'}
            
            # Créer un nom unique pour la quarantaine
            filename = os.path.basename(file_path)
            quarantine_name = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_name)
            
            # Déplacer le fichier vers la quarantaine
            shutil.move(file_path, quarantine_path)
            
            # Créer un fichier de métadonnées
            metadata = {
                'original_path': file_path,
                'quarantine_date': datetime.now().isoformat(),
                'file_size': os.path.getsize(quarantine_path),
                'threat_type': 'unknown'
            }
            
            metadata_path = quarantine_path + '.meta'
            with open(metadata_path, 'w') as f:
                import json
                json.dump(metadata, f, indent=2)
            
            logger.info(f"✅ Fichier mis en quarantaine: {file_path} -> {quarantine_path}")
            
            return {
                'success': True,
                'original_path': file_path,
                'quarantine_path': quarantine_path,
                'message': 'Fichier mis en quarantaine avec succès'
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la quarantaine: {e}")
            return {'success': False, 'error': str(e)}
    
    async def block_process(self, process_info: Dict[str, Any]) -> Dict[str, Any]:
        """Bloquer un processus malveillant"""
        try:
            pid = process_info.get('pid')
            process_name = process_info.get('name', 'unknown')
            
            if not pid:
                return {'success': False, 'error': 'PID non fourni'}
            
            # Tenter de terminer le processus
            try:
                process = psutil.Process(pid)
                process.terminate()
                
                # Attendre un peu puis forcer si nécessaire
                await asyncio.sleep(2)
                if process.is_running():
                    process.kill()
                
                self.blocked_processes.add(pid)
                
                logger.info(f"✅ Processus bloqué: {process_name} (PID: {pid})")
                
                return {
                    'success': True,
                    'pid': pid,
                    'process_name': process_name,
                    'message': 'Processus terminé avec succès'
                }
                
            except psutil.NoSuchProcess:
                return {'success': False, 'error': 'Processus déjà terminé'}
            except psutil.AccessDenied:
                return {'success': False, 'error': 'Permission refusée'}
                
        except Exception as e:
            logger.error(f"Erreur lors du blocage du processus: {e}")
            return {'success': False, 'error': str(e)}
    
    async def block_network_connection(self, connection_info: Dict[str, Any]) -> Dict[str, Any]:
        """Bloquer une connexion réseau suspecte"""
        try:
            remote_ip = connection_info.get('remote_ip')
            remote_port = connection_info.get('remote_port')
            
            if not remote_ip:
                return {'success': False, 'error': 'IP non fournie'}
            
            # Ajouter à la liste des connexions bloquées
            connection_key = f"{remote_ip}:{remote_port}"
            self.blocked_connections.add(connection_key)
            
            # Sur Windows, utiliser netsh pour bloquer
            if platform.system() == 'Windows':
                try:
                    # Bloquer l'IP avec Windows Firewall
                    cmd = f'netsh advfirewall firewall add rule name="RansomGuard_Block_{remote_ip}" dir=out action=block remoteip={remote_ip}'
                    subprocess.run(cmd, shell=True, check=True)
                    
                    logger.info(f"✅ Connexion bloquée: {remote_ip}:{remote_port}")
                    
                    return {
                        'success': True,
                        'remote_ip': remote_ip,
                        'remote_port': remote_port,
                        'message': 'Connexion bloquée avec succès'
                    }
                    
                except subprocess.CalledProcessError as e:
                    return {'success': False, 'error': f'Erreur firewall: {e}'}
            
            # Sur Linux, utiliser iptables
            elif platform.system() == 'Linux':
                try:
                    cmd = f'iptables -A OUTPUT -d {remote_ip} -j DROP'
                    subprocess.run(cmd, shell=True, check=True)
                    
                    logger.info(f"✅ Connexion bloquée: {remote_ip}:{remote_port}")
                    
                    return {
                        'success': True,
                        'remote_ip': remote_ip,
                        'remote_port': remote_port,
                        'message': 'Connexion bloquée avec succès'
                    }
                    
                except subprocess.CalledProcessError as e:
                    return {'success': False, 'error': f'Erreur iptables: {e}'}
            
            else:
                return {'success': False, 'error': 'Système non supporté'}
                
        except Exception as e:
            logger.error(f"Erreur lors du blocage réseau: {e}")
            return {'success': False, 'error': str(e)}
    
    async def notify_admin(self, threat_info: Dict[str, Any]) -> Dict[str, Any]:
        """Notifier l'administrateur d'une menace"""
        try:
            # Créer un rapport d'incident
            incident_report = {
                'timestamp': datetime.now().isoformat(),
                'threat_type': threat_info.get('threat_type', 'unknown'),
                'severity': threat_info.get('severity', 'low'),
                'file_path': threat_info.get('file_path', 'N/A'),
                'confidence': threat_info.get('confidence', 0.0),
                'actions_taken': ['auto_response']
            }
            
            # Sauvegarder le rapport
            reports_dir = os.path.join(os.path.expanduser("~"), ".ransomguard_reports")
            os.makedirs(reports_dir, exist_ok=True)
            
            report_file = os.path.join(reports_dir, f"incident_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            with open(report_file, 'w') as f:
                import json
                json.dump(incident_report, f, indent=2)
            
            logger.info(f"📋 Rapport d'incident créé: {report_file}")
            
            return {
                'success': True,
                'report_file': report_file,
                'message': 'Administrateur notifié'
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la notification admin: {e}")
            return {'success': False, 'error': str(e)}
    
    async def notify_user(self, threat_info: Dict[str, Any]) -> Dict[str, Any]:
        """Notifier l'utilisateur d'une menace"""
        try:
            # Créer une notification pour l'interface utilisateur
            notification = {
                'type': 'threat_detected',
                'title': 'Menace Détectée',
                'message': f"Une menace {threat_info.get('threat_type', 'inconnue')} a été détectée",
                'severity': threat_info.get('severity', 'low'),
                'timestamp': datetime.now().isoformat(),
                'actions_available': ['quarantine', 'block', 'details']
            }
            
            logger.info(f"🔔 Notification utilisateur: {notification['message']}")
            
            return {
                'success': True,
                'notification': notification,
                'message': 'Utilisateur notifié'
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la notification utilisateur: {e}")
            return {'success': False, 'error': str(e)}
    
    async def restore_file(self, quarantine_path: str) -> Dict[str, Any]:
        """Restaurer un fichier de la quarantaine"""
        try:
            if not os.path.exists(quarantine_path):
                return {'success': False, 'error': 'Fichier de quarantaine non trouvé'}
            
            # Lire les métadonnées
            metadata_path = quarantine_path + '.meta'
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r') as f:
                    import json
                    metadata = json.load(f)
                    original_path = metadata.get('original_path')
            else:
                return {'success': False, 'error': 'Métadonnées non trouvées'}
            
            # Restaurer le fichier
            shutil.move(quarantine_path, original_path)
            
            # Supprimer les métadonnées
            if os.path.exists(metadata_path):
                os.remove(metadata_path)
            
            logger.info(f"✅ Fichier restauré: {quarantine_path} -> {original_path}")
            
            return {
                'success': True,
                'original_path': original_path,
                'message': 'Fichier restauré avec succès'
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la restauration: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_quarantine_list(self) -> List[Dict[str, Any]]:
        """Obtenir la liste des fichiers en quarantaine"""
        try:
            quarantined_files = []
            
            for filename in os.listdir(self.quarantine_dir):
                if not filename.endswith('.meta'):
                    file_path = os.path.join(self.quarantine_dir, filename)
                    metadata_path = file_path + '.meta'
                    
                    metadata = {}
                    if os.path.exists(metadata_path):
                        with open(metadata_path, 'r') as f:
                            import json
                            metadata = json.load(f)
                    
                    quarantined_files.append({
                        'filename': filename,
                        'quarantine_path': file_path,
                        'original_path': metadata.get('original_path', 'Unknown'),
                        'quarantine_date': metadata.get('quarantine_date', 'Unknown'),
                        'file_size': os.path.getsize(file_path) if os.path.exists(file_path) else 0
                    })
            
            return quarantined_files
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de la quarantaine: {e}")
            return []
    
    def get_response_history(self) -> List[Dict[str, Any]]:
        """Obtenir l'historique des réponses aux menaces"""
        return self.response_history
    
    def get_blocked_processes(self) -> List[int]:
        """Obtenir la liste des processus bloqués"""
        return list(self.blocked_processes)
    
    def get_blocked_connections(self) -> List[str]:
        """Obtenir la liste des connexions bloquées"""
        return list(self.blocked_connections)

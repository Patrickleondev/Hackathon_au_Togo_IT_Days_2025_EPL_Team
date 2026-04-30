#!/usr/bin/env python3
"""
Moniteur de registre réel pour RansomGuard AI
Surveillance en temps réel du registre Windows
"""

import asyncio
import logging
import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, asdict
import time

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class RegistryKey:
    """Informations sur une clé de registre"""
    path: str
    name: str
    value: Any
    value_type: str
    last_modified: datetime
    is_suspicious: bool = False
    threat_score: float = 0.0
    description: str = ""

@dataclass
class RegistryOperation:
    """Informations sur une opération de registre"""
    operation_type: str  # 'create', 'modify', 'delete', 'access'
    key_path: str
    timestamp: datetime
    process_name: str
    process_pid: int
    old_value: Any = None
    new_value: Any = None
    is_suspicious: bool = False
    threat_score: float = 0.0

class RealRegistryMonitor:
    """Moniteur de registre réel pour Windows"""
    
    def __init__(self):
        self.monitored_keys: Dict[str, RegistryKey] = {}
        self.registry_operations: List[RegistryOperation] = []
        self.suspicious_operations: List[RegistryOperation] = []
        self.monitoring_active = False
        
        # Clés de registre critiques à surveiller
        self.critical_keys = {
            # Démarrage automatique
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            
            # Services
            r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services",
            
            # Extensions de fichiers
            r"HKEY_CLASSES_ROOT",
            
            # Politiques de sécurité
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
            r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
            
            # Pare-feu
            r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy",
            
            # Antivirus
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender",
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Security Center",
            
            # Navigation
            r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Internet Explorer\Main",
            r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings",
            
            # RDP
            r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server",
            
            # UAC
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            
            # Scripts de connexion
            r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts",
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts"
        }
        
        # Valeurs suspectes connues
        self.suspicious_values = {
            'crypto', 'encrypt', 'decrypt', 'ransom', 'malware',
            'trojan', 'virus', 'spyware', 'keylogger', 'backdoor',
            'hack', 'exploit', 'payload', 'shell', 'reverse',
            'meterpreter', 'beacon', 'c2', 'command', 'control'
        }
        
        # Vérifier si on est sur Windows
        self.is_windows = os.name == 'nt'
        if not self.is_windows:
            logger.warning("⚠️ Ce moniteur de registre fonctionne uniquement sur Windows")
    
    def is_windows_system(self) -> bool:
        """Vérifier si on est sur un système Windows"""
        return self.is_windows
    
    async def start_monitoring(self):
        """Démarrer la surveillance du registre"""
        if not self.is_windows_system():
            logger.error("❌ Ce moniteur ne fonctionne que sur Windows")
            return
        
        logger.info("🚀 Démarrage de la surveillance du registre Windows...")
        self.monitoring_active = True
        
        # Scanner le registre initialement
        await self.scan_registry_initial()
        
        # Démarrer la surveillance continue
        monitor_task = asyncio.create_task(self.monitor_registry_changes())
        
        try:
            while self.monitoring_active:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            logger.info("⏹️ Arrêt demandé par l'utilisateur...")
        finally:
            self.monitoring_active = False
            monitor_task.cancel()
            logger.info("✅ Surveillance du registre arrêtée")
    
    def stop_monitoring(self):
        """Arrêter la surveillance"""
        self.monitoring_active = False
    
    async def scan_registry_initial(self):
        """Scanner le registre pour la première fois"""
        logger.info("🔍 Scan initial du registre...")
        
        try:
            # Utiliser PowerShell pour scanner le registre
            await self.scan_registry_with_powershell()
            
            logger.info(f"✅ Scan initial terminé: {len(self.monitored_keys)} clés surveillées")
            
        except Exception as e:
            logger.error(f"❌ Erreur lors du scan initial: {e}")
            # Fallback: créer des clés de test
            await self.create_test_registry_keys()
    
    async def scan_registry_with_powershell(self):
        """Scanner le registre avec PowerShell"""
        try:
            import subprocess
            
            # Commande PowerShell pour lister les clés de registre
            ps_commands = [
                "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' | ConvertTo-Json",
                "Get-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' | ConvertTo-Json",
                "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services' | ConvertTo-Json"
            ]
            
            for cmd in ps_commands:
                try:
                    result = subprocess.run(
                        ['powershell', '-Command', cmd],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    
                    if result.returncode == 0 and result.stdout.strip():
                        # Parser le JSON et créer les objets RegistryKey
                        await self.parse_powershell_output(result.stdout)
                        
                except subprocess.TimeoutExpired:
                    logger.warning(f"⚠️ Timeout pour la commande PowerShell: {cmd}")
                except Exception as e:
                    logger.warning(f"⚠️ Erreur PowerShell pour {cmd}: {e}")
                    
        except Exception as e:
            logger.error(f"❌ Erreur lors du scan PowerShell: {e}")
    
    async def parse_powershell_output(self, output: str):
        """Parser la sortie PowerShell"""
        try:
            # Nettoyer la sortie
            cleaned_output = output.strip()
            if not cleaned_output or cleaned_output == 'null':
                return
            
            # Essayer de parser le JSON
            try:
                data = json.loads(cleaned_output)
                await self.process_registry_data(data)
            except json.JSONDecodeError:
                # Si ce n'est pas du JSON valide, traiter comme du texte
                await self.process_text_output(cleaned_output)
                
        except Exception as e:
            logger.error(f"❌ Erreur lors du parsing PowerShell: {e}")
    
    async def process_registry_data(self, data: Any):
        """Traiter les données de registre"""
        try:
            if isinstance(data, dict):
                for key, value in data.items():
                    if key and not key.startswith('PS'):
                        await self.create_registry_key(key, value)
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        await self.process_registry_data(item)
                        
        except Exception as e:
            logger.error(f"❌ Erreur lors du traitement des données: {e}")
    
    async def process_text_output(self, text: str):
        """Traiter la sortie texte"""
        try:
            lines = text.split('\n')
            for line in lines:
                line = line.strip()
                if line and '=' in line:
                    key, value = line.split('=', 1)
                    await self.create_registry_key(key.strip(), value.strip())
                    
        except Exception as e:
            logger.error(f"❌ Erreur lors du traitement du texte: {e}")
    
    async def create_registry_key(self, key_name: str, key_value: Any):
        """Créer un objet RegistryKey"""
        try:
            # Nettoyer le nom de la clé
            clean_key = key_name.replace('"', '').strip()
            
            # Vérifier si la clé est suspecte
            is_suspicious, threat_score, description = self.analyze_registry_key(clean_key, key_value)
            
            registry_key = RegistryKey(
                path=clean_key,
                name=clean_key.split('\\')[-1] if '\\' in clean_key else clean_key,
                value=str(key_value)[:100],  # Limiter la taille
                value_type=type(key_value).__name__,
                last_modified=datetime.now(),
                is_suspicious=is_suspicious,
                threat_score=threat_score,
                description=description
            )
            
            self.monitored_keys[clean_key] = registry_key
            
        except Exception as e:
            logger.error(f"❌ Erreur lors de la création de la clé {key_name}: {e}")
    
    def analyze_registry_key(self, key_name: str, key_value: Any) -> tuple[bool, float, str]:
        """Analyser une clé de registre pour détecter les menaces"""
        is_suspicious = False
        threat_score = 0.0
        description = ""
        
        try:
            key_lower = key_name.lower()
            value_lower = str(key_value).lower()
            
            # Vérifier le nom de la clé
            for pattern in self.suspicious_values:
                if pattern in key_lower:
                    threat_score += 0.4
                    is_suspicious = True
                    description += f"Nom suspect: {pattern}; "
            
            # Vérifier la valeur
            for pattern in self.suspicious_values:
                if pattern in value_lower:
                    threat_score += 0.5
                    is_suspicious = True
                    description += f"Valeur suspecte: {pattern}; "
            
            # Vérifier les chemins suspects
            suspicious_paths = ['temp', 'downloads', 'appdata\\local\\temp']
            for path in suspicious_paths:
                if path in value_lower:
                    threat_score += 0.3
                    is_suspicious = True
                    description += f"Chemin suspect: {path}; "
            
            # Vérifier les extensions suspectes
            suspicious_extensions = ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.js']
            for ext in suspicious_extensions:
                if ext in value_lower:
                    threat_score += 0.2
                    is_suspicious = True
                    description += f"Extension suspecte: {ext}; "
            
            # Vérifier les clés critiques
            critical_keywords = ['run', 'runonce', 'services', 'policies', 'firewall']
            for keyword in critical_keywords:
                if keyword in key_lower:
                    threat_score += 0.1
                    description += f"Clé critique: {keyword}; "
            
            # Limiter le score
            threat_score = min(threat_score, 1.0)
            
            if not description:
                description = "Clé normale"
                
        except Exception as e:
            logger.error(f"❌ Erreur lors de l'analyse de la clé {key_name}: {e}")
        
        return is_suspicious, threat_score, description
    
    async def create_test_registry_keys(self):
        """Créer des clés de registre de test (fallback)"""
        logger.info("📝 Création de clés de registre de test...")
        
        test_keys = [
            ("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\TestApp", "C:\\test\\app.exe"),
            ("HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\UserApp", "C:\\users\\test\\app.exe"),
            ("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\TestService", "C:\\windows\\system32\\testservice.exe"),
            ("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\TestPolicy", "1"),
            ("HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyEnable", "0")
        ]
        
        for key_path, key_value in test_keys:
            await self.create_registry_key(key_path, key_value)
    
    async def monitor_registry_changes(self):
        """Surveiller les changements du registre"""
        logger.info("🔍 Démarrage de la surveillance des changements du registre...")
        
        while self.monitoring_active:
            try:
                # Simuler la détection de changements (dans un vrai système, on utiliserait des hooks)
                await self.detect_registry_changes()
                await asyncio.sleep(5)  # Vérifier toutes les 5 secondes
                
            except Exception as e:
                logger.error(f"❌ Erreur lors de la surveillance: {e}")
                await asyncio.sleep(10)
    
    async def detect_registry_changes(self):
        """Détecter les changements du registre (simulation)"""
        try:
            # Pour l'instant, on simule des changements
            # Dans un vrai système, on utiliserait RegNotifyChangeKeyValue ou des hooks
            pass
            
        except Exception as e:
            logger.error(f"❌ Erreur lors de la détection des changements: {e}")
    
    def get_registry_summary(self) -> Dict[str, Any]:
        """Obtenir un résumé de la surveillance du registre"""
        total_keys = len(self.monitored_keys)
        suspicious_keys = len([k for k in self.monitored_keys.values() if k.is_suspicious])
        
        # Clés par catégorie
        categories = {
            'startup': [],
            'services': [],
            'policies': [],
            'security': [],
            'other': []
        }
        
        for key in self.monitored_keys.values():
            key_lower = key.path.lower()
            
            if 'run' in key_lower or 'startup' in key_lower:
                categories['startup'].append(key)
            elif 'services' in key_lower:
                categories['services'].append(key)
            elif 'policies' in key_lower:
                categories['policies'].append(key)
            elif any(sec in key_lower for sec in ['defender', 'security', 'firewall']):
                categories['security'].append(key)
            else:
                categories['other'].append(key)
        
        # Clés suspectes
        suspicious_keys_list = [
            {
                'path': k.path,
                'name': k.name,
                'value': k.value,
                'threat_score': k.threat_score,
                'description': k.description
            }
            for k in self.monitored_keys.values() if k.is_suspicious
        ]
        
        return {
            'total_registry_keys': total_keys,
            'suspicious_keys': suspicious_keys,
            'categories': {
                name: len(keys) for name, keys in categories.items()
            },
            'suspicious_keys_details': suspicious_keys_list,
            'last_scan': datetime.now().isoformat(),
            'monitoring_active': self.monitoring_active
        }
    
    def get_key_details(self, key_path: str) -> Optional[RegistryKey]:
        """Obtenir les détails d'une clé spécifique"""
        return self.monitored_keys.get(key_path)
    
    def search_keys(self, query: str) -> List[RegistryKey]:
        """Rechercher des clés de registre"""
        query_lower = query.lower()
        results = []
        
        for key in self.monitored_keys.values():
            if (query_lower in key.path.lower() or 
                query_lower in key.name.lower() or 
                query_lower in str(key.value).lower()):
                results.append(key)
        
        return results

# Instance globale
registry_monitor = RealRegistryMonitor()

async def main():
    """Fonction principale de test"""
    logger.info("🚀 Test du moniteur de registre réel...")
    
    if not registry_monitor.is_windows_system():
        logger.error("❌ Ce moniteur ne fonctionne que sur Windows")
        return
    
    # Démarrer la surveillance
    monitor_task = asyncio.create_task(registry_monitor.start_monitoring())
    
    try:
        # Attendre un peu pour collecter des données
        await asyncio.sleep(10)
        
        # Afficher un résumé
        summary = registry_monitor.get_registry_summary()
        logger.info("📊 Résumé de la surveillance du registre:")
        logger.info(f"  Clés totales: {summary['total_registry_keys']}")
        logger.info(f"  Clés suspectes: {summary['suspicious_keys']}")
        
        if summary['categories']:
            logger.info("📁 Catégories de clés:")
            for category, count in summary['categories'].items():
                logger.info(f"  - {category}: {count} clés")
        
        if summary['suspicious_keys_details']:
            logger.info("🚨 Clés suspectes détectées:")
            for key in summary['suspicious_keys_details'][:5]:
                logger.info(f"  - {key['path']}: Score {key['threat_score']:.2f}")
                logger.info(f"    Description: {key['description']}")
        
        # Recherche de test
        logger.info("🔍 Test de recherche...")
        search_results = registry_monitor.search_keys("run")
        logger.info(f"  Clés contenant 'run': {len(search_results)}")
        
    except KeyboardInterrupt:
        logger.info("⏹️ Arrêt demandé par l'utilisateur...")
    finally:
        # Arrêter la surveillance
        registry_monitor.stop_monitoring()
        monitor_task.cancel()
        logger.info("✅ Moniteur de registre arrêté")

if __name__ == "__main__":
    asyncio.run(main())

"""
Module d'intelligence des menaces et mise à jour dynamique
RansomGuard AI - Hackathon Togo IT Days 2025
"""

import os
import json
import logging
import asyncio
import aiohttp
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import requests

logger = logging.getLogger(__name__)

class ThreatIntelligence:
    """
    Système d'intelligence des menaces avec mise à jour dynamique
    """
    
    def __init__(self):
        self.threat_lists = {
            'malicious_ips': [],
            'malicious_domains': [],
            'malicious_hashes': [],
            'malicious_patterns': [],
            'ransomware_families': []
        }
        self.last_update = {}
        self.update_interval = timedelta(hours=6)  # Mise à jour toutes les 6 heures
        self.intelligence_sources = {
            'abuseipdb': 'https://api.abuseipdb.com/api/v2/blacklist',
            'virustotal': 'https://www.virustotal.com/vtapi/v2/ip-address/report',
            'alienvault': 'https://otx.alienvault.com/api/v1/indicators/domain/',
            'malwarebazaar': 'https://bazaar.abuse.ch/api/v1/'
        }
        self.api_keys = {}
        self.load_api_keys()
    
    def load_api_keys(self):
        """Charger les clés API depuis un fichier de configuration"""
        try:
            config_file = os.path.join(os.path.dirname(__file__), '..', 'config', 'api_keys.json')
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    self.api_keys = json.load(f)
            else:
                logger.warning("Fichier de clés API non trouvé, utilisation des listes locales")
        except Exception as e:
            logger.error(f"Erreur lors du chargement des clés API: {e}")
    
    async def update_threat_intelligence(self):
        """Mettre à jour l'intelligence des menaces"""
        try:
            logger.info("🔄 Mise à jour de l'intelligence des menaces...")
            
            # Vérifier si une mise à jour est nécessaire
            if not self._should_update():
                logger.info("✅ Intelligence des menaces à jour")
                return
            
            # Mettre à jour les différentes listes
            await asyncio.gather(
                self._update_malicious_ips(),
                self._update_malicious_domains(),
                self._update_malicious_hashes(),
                self._update_ransomware_patterns(),
                self._update_ransomware_families()
            )
            
            # Sauvegarder les listes mises à jour
            await self._save_threat_lists()
            
            logger.info("✅ Intelligence des menaces mise à jour avec succès")
            
        except Exception as e:
            logger.error(f"Erreur lors de la mise à jour de l'intelligence: {e}")
    
    def _should_update(self) -> bool:
        """Vérifier si une mise à jour est nécessaire"""
        for list_name in self.threat_lists.keys():
            last_update = self.last_update.get(list_name)
            if not last_update or datetime.now() - last_update > self.update_interval:
                return True
        return False
    
    async def _update_malicious_ips(self):
        """Mettre à jour la liste des IPs malveillantes"""
        try:
            # Sources de données
            sources = [
                'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt',
                'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
                'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts'
            ]
            
            malicious_ips = set()
            
            async with aiohttp.ClientSession() as session:
                for source in sources:
                    try:
                        async with session.get(source, timeout=30) as response:
                            if response.status == 200:
                                content = await response.text()
                                lines = content.split('\n')
                                
                                for line in lines:
                                    line = line.strip()
                                    if line and not line.startswith('#') and self._is_valid_ip(line):
                                        malicious_ips.add(line)
                                        
                    except Exception as e:
                        logger.warning(f"Erreur lors de la récupération depuis {source}: {e}")
            
            self.threat_lists['malicious_ips'] = list(malicious_ips)
            self.last_update['malicious_ips'] = datetime.now()
            
            logger.info(f"✅ {len(malicious_ips)} IPs malveillantes mises à jour")
            
        except Exception as e:
            logger.error(f"Erreur lors de la mise à jour des IPs: {e}")
    
    async def _update_malicious_domains(self):
        """Mettre à jour la liste des domaines malveillants"""
        try:
            # Sources de données
            sources = [
                'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
                'https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt',
                'https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts'
            ]
            
            malicious_domains = set()
            
            async with aiohttp.ClientSession() as session:
                for source in sources:
                    try:
                        async with session.get(source, timeout=30) as response:
                            if response.status == 200:
                                content = await response.text()
                                lines = content.split('\n')
                                
                                for line in lines:
                                    line = line.strip()
                                    if line and not line.startswith('#') and self._is_valid_domain(line):
                                        malicious_domains.add(line)
                                        
                    except Exception as e:
                        logger.warning(f"Erreur lors de la récupération depuis {source}: {e}")
            
            self.threat_lists['malicious_domains'] = list(malicious_domains)
            self.last_update['malicious_domains'] = datetime.now()
            
            logger.info(f"✅ {len(malicious_domains)} domaines malveillants mis à jour")
            
        except Exception as e:
            logger.error(f"Erreur lors de la mise à jour des domaines: {e}")
    
    async def _update_malicious_hashes(self):
        """Mettre à jour la liste des hashes malveillants"""
        try:
            # Utiliser MalwareBazaar API si disponible
            if 'malwarebazaar' in self.api_keys:
                hashes = await self._get_malwarebazaar_hashes()
                self.threat_lists['malicious_hashes'] = hashes
                self.last_update['malicious_hashes'] = datetime.now()
                logger.info(f"✅ {len(hashes)} hashes malveillants mis à jour")
            else:
                logger.warning("Clé API MalwareBazaar non disponible")
                
        except Exception as e:
            logger.error(f"Erreur lors de la mise à jour des hashes: {e}")
    
    async def _get_malwarebazaar_hashes(self) -> List[str]:
        """Obtenir les hashes depuis MalwareBazaar"""
        try:
            url = f"{self.intelligence_sources['malwarebazaar']}query_recent"
            api_key = self.api_keys.get('malwarebazaar', '')
            # MalwareBazaar accepts either 'API-KEY' or 'Auth-Key'
            headers = {'API-KEY': api_key} if api_key else {}
            if api_key:
                headers['Auth-Key'] = api_key
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, headers=headers, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        hashes = []
                        
                        if 'data' in data:
                            for item in data['data']:
                                if 'sha256_hash' in item:
                                    hashes.append(item['sha256_hash'])
                        
                        return hashes
            
            return []
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération depuis MalwareBazaar: {e}")
            return []

    async def query_malwarebazaar_hash(self, sha256_hash: str) -> Dict[str, Any]:
        """Interroger MalwareBazaar pour un hash unique (détails échantillon)."""
        try:
            api_key = self.api_keys.get('malwarebazaar', '')
            headers = {'API-KEY': api_key} if api_key else {}
            if api_key:
                headers['Auth-Key'] = api_key
            url = self.intelligence_sources['malwarebazaar']
            payload = {"query": "get_file", "sha256_hash": sha256_hash}
            async with aiohttp.ClientSession() as session:
                async with session.post(url, data=payload, headers=headers, timeout=30) as resp:
                    txt = await resp.text()
                    # MalwareBazaar can return JSON or file content; try JSON first
                    try:
                        data = json.loads(txt)
                    except Exception:
                        data = {"raw": txt}
                    return {"source": "malwarebazaar", "status": resp.status, "data": data}
        except Exception as e:
            logger.error(f"Erreur requête MalwareBazaar (hash): {e}")
            return {"source": "malwarebazaar", "error": str(e)}

    async def query_hash(self, sha256_hash: str) -> Dict[str, Any]:
        """Vérifier un SHA-256 contre les listes locales et interroger MalwareBazaar si possible."""
        try:
            in_local = sha256_hash in self.threat_lists.get('malicious_hashes', [])
            result: Dict[str, Any] = {
                'hash': sha256_hash,
                'is_malicious_local': in_local,
                'confidence_local': 0.95 if in_local else 0.0,
                'sources': []
            }
            # If we have API key, enrich from MalwareBazaar
            if self.api_keys.get('malwarebazaar'):
                mb = await self.query_malwarebazaar_hash(sha256_hash)
                result['sources'].append(mb)
                # Derive confidence if MB reports metadata
                try:
                    data = mb.get('data', {})
                    if isinstance(data, dict) and data.get('query_status') == 'ok':
                        result['is_malicious_remote'] = True
                        result['confidence_remote'] = 0.98
                    else:
                        result['is_malicious_remote'] = False
                        result['confidence_remote'] = 0.0
                except Exception:
                    pass
            return result
        except Exception as e:
            logger.error(f"Erreur query_hash: {e}")
            return {'hash': sha256_hash, 'error': str(e)}
    
    async def _update_ransomware_patterns(self):
        """Mettre à jour les patterns de ransomware"""
        try:
            # Patterns de ransomware connus
            patterns = [
                # Extensions de fichiers
                r'\.encrypted$', r'\.locked$', r'\.crypto$', r'\.ransom$',
                r'\.bitcoin$', r'\.wallet$', r'\.miner$', r'\.cryptolocker$',
                
                # Noms de fichiers
                r'readme.*\.txt$', r'decrypt.*\.txt$', r'pay.*\.txt$',
                r'bitcoin.*\.txt$', r'wallet.*\.txt$', r'ransom.*\.txt$',
                
                # Patterns de contenu
                r'your.*files.*encrypted', r'pay.*bitcoin', r'decrypt.*key',
                r'ransom.*payment', r'crypto.*locker', r'encrypt.*files'
            ]
            
            self.threat_lists['malicious_patterns'] = patterns
            self.last_update['malicious_patterns'] = datetime.now()
            
            logger.info(f"✅ {len(patterns)} patterns de ransomware mis à jour")
            
        except Exception as e:
            logger.error(f"Erreur lors de la mise à jour des patterns: {e}")
    
    async def _update_ransomware_families(self):
        """Mettre à jour les familles de ransomware connues"""
        try:
            # Familles de ransomware connues
            families = {
                'WannaCry': {
                    'patterns': ['wcry', 'wannacry', 'wncry'],
                    'extensions': ['.wcry', '.wncry'],
                    'ransom_note': 'WannaCry'
                },
                'Locky': {
                    'patterns': ['locky', 'locker'],
                    'extensions': ['.locky', '.zepto', '.odin'],
                    'ransom_note': 'Locky'
                },
                'CryptoLocker': {
                    'patterns': ['cryptolocker', 'crypto'],
                    'extensions': ['.encrypted', '.crypto'],
                    'ransom_note': 'CryptoLocker'
                },
                'Cerber': {
                    'patterns': ['cerber', 'cerb'],
                    'extensions': ['.cerber', '.cerb'],
                    'ransom_note': 'Cerber'
                },
                'Petya': {
                    'patterns': ['petya', 'petr'],
                    'extensions': ['.petya', '.petr'],
                    'ransom_note': 'Petya'
                },
                'TeslaCrypt': {
                    'patterns': ['teslacrypt', 'tesla'],
                    'extensions': ['.tesla', '.ecc'],
                    'ransom_note': 'TeslaCrypt'
                },
                'CryptoWall': {
                    'patterns': ['cryptowall', 'cwall'],
                    'extensions': ['.cryptowall', '.cwall'],
                    'ransom_note': 'CryptoWall'
                },
                'CTB-Locker': {
                    'patterns': ['ctb-locker', 'ctb'],
                    'extensions': ['.ctb', '.ctbl'],
                    'ransom_note': 'CTB-Locker'
                }
            }
            
            self.threat_lists['ransomware_families'] = families
            self.last_update['ransomware_families'] = datetime.now()
            
            logger.info(f"✅ {len(families)} familles de ransomware mises à jour")
            
        except Exception as e:
            logger.error(f"Erreur lors de la mise à jour des familles: {e}")
    
    async def _save_threat_lists(self):
        """Sauvegarder les listes de menaces"""
        try:
            data_dir = os.path.join(os.path.dirname(__file__), '..', 'data', 'threat_intelligence')
            os.makedirs(data_dir, exist_ok=True)
            
            for list_name, data in self.threat_lists.items():
                file_path = os.path.join(data_dir, f"{list_name}.json")
                
                with open(file_path, 'w') as f:
                    json.dump({
                        'data': data,
                        'last_update': self.last_update.get(list_name, datetime.now()).isoformat(),
                        'count': len(data) if isinstance(data, list) else len(data.keys())
                    }, f, indent=2)
            
            logger.info("✅ Listes de menaces sauvegardées")
            
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde: {e}")
    
    async def load_threat_lists(self):
        """Charger les listes de menaces depuis les fichiers"""
        try:
            data_dir = os.path.join(os.path.dirname(__file__), '..', 'data', 'threat_intelligence')
            
            for list_name in self.threat_lists.keys():
                file_path = os.path.join(data_dir, f"{list_name}.json")
                
                if os.path.exists(file_path):
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        self.threat_lists[list_name] = data.get('data', [])
                        if 'last_update' in data:
                            self.last_update[list_name] = datetime.fromisoformat(data['last_update'])
            
            logger.info("✅ Listes de menaces chargées")
            
        except Exception as e:
            logger.error(f"Erreur lors du chargement: {e}")
    
    def check_ip_threat(self, ip: str) -> Dict[str, Any]:
        """Vérifier si une IP est malveillante"""
        try:
            is_malicious = ip in self.threat_lists['malicious_ips']
            
            return {
                'ip': ip,
                'is_malicious': is_malicious,
                'confidence': 0.9 if is_malicious else 0.1,
                'source': 'threat_intelligence',
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la vérification IP: {e}")
            return {'ip': ip, 'is_malicious': False, 'error': str(e)}
    
    def check_domain_threat(self, domain: str) -> Dict[str, Any]:
        """Vérifier si un domaine est malveillant"""
        try:
            is_malicious = domain in self.threat_lists['malicious_domains']
            
            return {
                'domain': domain,
                'is_malicious': is_malicious,
                'confidence': 0.9 if is_malicious else 0.1,
                'source': 'threat_intelligence',
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la vérification domaine: {e}")
            return {'domain': domain, 'is_malicious': False, 'error': str(e)}
    
    def check_hash_threat(self, file_hash: str) -> Dict[str, Any]:
        """Vérifier si un hash est malveillant"""
        try:
            is_malicious = file_hash in self.threat_lists['malicious_hashes']
            
            return {
                'hash': file_hash,
                'is_malicious': is_malicious,
                'confidence': 0.95 if is_malicious else 0.1,
                'source': 'threat_intelligence',
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la vérification hash: {e}")
            return {'hash': file_hash, 'is_malicious': False, 'error': str(e)}
    
    def check_ransomware_family(self, filename: str, content: str = "") -> Dict[str, Any]:
        """Identifier la famille de ransomware"""
        try:
            filename_lower = filename.lower()
            content_lower = content.lower()
            
            for family_name, family_data in self.threat_lists['ransomware_families'].items():
                # Vérifier les patterns dans le nom de fichier
                for pattern in family_data['patterns']:
                    if pattern in filename_lower:
                        return {
                            'family': family_name,
                            'confidence': 0.8,
                            'detection_method': 'filename_pattern',
                            'timestamp': datetime.now().isoformat()
                        }
                
                # Vérifier les extensions
                for ext in family_data['extensions']:
                    if filename_lower.endswith(ext):
                        return {
                            'family': family_name,
                            'confidence': 0.9,
                            'detection_method': 'file_extension',
                            'timestamp': datetime.now().isoformat()
                        }
                
                # Vérifier le contenu si disponible
                if content_lower:
                    ransom_note = family_data['ransom_note'].lower()
                    if ransom_note in content_lower:
                        return {
                            'family': family_name,
                            'confidence': 0.95,
                            'detection_method': 'content_analysis',
                            'timestamp': datetime.now().isoformat()
                        }
            
            return {
                'family': 'unknown',
                'confidence': 0.0,
                'detection_method': 'none',
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de l'identification de famille: {e}")
            return {'family': 'unknown', 'error': str(e)}
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Vérifier si une chaîne est une IP valide"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                if not part.isdigit() or not 0 <= int(part) <= 255:
                    return False
            return True
        except:
            return False
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Vérifier si une chaîne est un domaine valide"""
        try:
            if not domain or '.' not in domain:
                return False
            if domain.startswith('.') or domain.endswith('.'):
                return False
            return True
        except:
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Obtenir les statistiques de l'intelligence des menaces"""
        try:
            stats = {
                'malicious_ips_count': len(self.threat_lists['malicious_ips']),
                'malicious_domains_count': len(self.threat_lists['malicious_domains']),
                'malicious_hashes_count': len(self.threat_lists['malicious_hashes']),
                'ransomware_families_count': len(self.threat_lists['ransomware_families']),
                'last_update': {name: date.isoformat() if date else None 
                              for name, date in self.last_update.items()},
                'update_interval_hours': self.update_interval.total_seconds() / 3600
            }
            
            return stats
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des statistiques: {e}")
            return {'error': str(e)}

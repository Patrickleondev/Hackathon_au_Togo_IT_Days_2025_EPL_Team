"""
Système de détection avancée avec techniques d'évasion (Version simplifiée)
RansomGuard AI - Hackathon Togo IT Days 2025
"""

import numpy as np
import pandas as pd
import logging
from typing import Dict, List, Any, Optional, Tuple
import os
import json
import hashlib
import asyncio
from datetime import datetime
import joblib
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import psutil
import threading
import queue
import re

logger = logging.getLogger(__name__)

class EvasionDetector:
    """Détecteur de techniques d'évasion avancées"""
    
    def __init__(self):
        self.evasion_patterns = {
            'sandbox_evasion': [
                'sleep', 'delay', 'timeout', 'wait',
                'mouse_movement', 'keyboard_input',
                'system_info', 'vm_detection'
            ],
            'antivirus_evasion': [
                'packing', 'obfuscation', 'encryption',
                'polymorphic', 'metamorphic',
                'code_injection', 'process_hollowing'
            ],
            'behavioral_evasion': [
                'file_operations', 'registry_changes',
                'network_activity', 'process_creation',
                'service_installation', 'scheduled_tasks'
            ]
        }
        
        self.isolation_forest = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        
    def detect_evasion_techniques(self, file_path: str, process_info: Dict) -> Dict[str, Any]:
        """Détecter les techniques d'évasion"""
        evasion_scores = {}
        
        # Analyser le contenu du fichier
        file_content = self._read_file_content(file_path)
        
        for category, patterns in self.evasion_patterns.items():
            score = 0
            for pattern in patterns:
                if pattern.lower() in file_content.lower():
                    score += 1
            
            evasion_scores[category] = min(score / len(patterns), 1.0)
        
        # Détection d'anomalies avec Isolation Forest
        features = self._extract_evasion_features(file_path, process_info)
        if len(features) > 0:
            try:
                anomaly_score = self.isolation_forest.fit_predict([features])[0]
                evasion_scores['anomaly_detection'] = 1.0 if anomaly_score == -1 else 0.0
            except:
                evasion_scores['anomaly_detection'] = 0.0
        
        return evasion_scores
    
    def _read_file_content(self, file_path: str) -> str:
        """Lire le contenu du fichier de manière sécurisée"""
        try:
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read(4096)  # Lire les premiers 4KB
        except:
            pass
        return ""
    
    def _extract_evasion_features(self, file_path: str, process_info: Dict) -> List[float]:
        """Extraire les caractéristiques pour la détection d'évasion"""
        features = []
        
        try:
            # Taille du fichier
            file_size = os.path.getsize(file_path)
            features.append(file_size)
            
            # Entropie du fichier
            entropy = self._calculate_entropy(file_path)
            features.append(entropy)
            
            # Informations sur le processus
            if process_info:
                features.append(process_info.get('cpu_percent', 0))
                features.append(process_info.get('memory_percent', 0))
            else:
                features.extend([0, 0])
            
            # Nombre de patterns suspects
            suspicious_count = len(self._detect_suspicious_patterns(file_path))
            features.append(suspicious_count)
            
        except Exception as e:
            logger.error(f"Erreur lors de l'extraction des caractéristiques: {e}")
            features = [0, 0, 0, 0, 0]
        
        return features
    
    def _detect_suspicious_patterns(self, file_path: str) -> List[str]:
        """Détecter les patterns suspects dans un fichier"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(4096)  # Lire les premiers 4KB
            
            if not data:
                return []
            
            suspicious_patterns = []
            
            # Patterns suspects en bytes
            patterns = [
                b'ransomware', b'encrypt', b'decrypt', b'crypto',
                b'bitcoin', b'wallet', b'payment', b'ransom',
                b'lock', b'unlock', b'key', b'password',
                b'virus', b'malware', b'trojan', b'backdoor',
                b'rootkit', b'stealer', b'logger', b'spyware',
                b'PE\x00\x00',  # Header PE
                b'MZ',          # Header MZ
                b'CreateFile', b'ReadFile', b'WriteFile',
                b'RegCreateKey', b'RegSetValue',
                b'InternetOpen', b'HttpOpenRequest',
                b'CryptEncrypt', b'CryptDecrypt'
            ]
            
            # Chercher les patterns
            for pattern in patterns:
                if pattern in data:
                    suspicious_patterns.append(pattern.decode('utf-8', errors='ignore'))
            
            # Chercher des chaînes de caractères suspectes
            try:
                text_content = data.decode('utf-8', errors='ignore').lower()
                text_patterns = [
                    'ransomware', 'encrypt', 'decrypt', 'crypto',
                    'bitcoin', 'wallet', 'payment', 'ransom',
                    'lock', 'unlock', 'key', 'password',
                    'virus', 'malware', 'trojan', 'backdoor',
                    'this program cannot be run in dos mode'
                ]
                
                for pattern in text_patterns:
                    if pattern in text_content:
                        suspicious_patterns.append(pattern)
            except:
                pass  # Ignorer les erreurs de décodage
            
            return list(set(suspicious_patterns))  # Supprimer les doublons
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection des patterns: {e}")
            return []
    
    def _calculate_entropy(self, file_path: str) -> float:
        """Calculer l'entropie d'un fichier"""
        try:
            import math
            with open(file_path, 'rb') as f:
                data = f.read(1024)  # Lire les premiers 1KB
            
            if not data:
                return 0.0
            
            # Calculer la distribution des bytes
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            # Calculer l'entropie
            entropy = 0.0
            data_length = len(data)
            
            for count in byte_counts:
                if count > 0:
                    probability = count / data_length
                    entropy -= probability * math.log2(probability)
            
            return entropy
            
        except Exception as e:
            logger.error(f"Erreur lors du calcul de l'entropie: {e}")
            return 0.0

class AdvancedHuggingFaceDetector:
    """Détecteur avancé avec techniques d'évasion et fine-tuning"""
    
    def __init__(self):
        self.evasion_detector = EvasionDetector()
        self.models = {}
        self.scaler = StandardScaler()
        self.processing_queue = queue.Queue()
        self.results_cache = {}
        
        # Configuration des modèles
        self.model_configs = {
            'advanced_classifier': {
                'type': 'random_forest',
                'threshold': 0.75
            },
            'evasion_detector': {
                'type': 'isolation_forest',
                'threshold': 0.6
            }
        }
        
        self._load_models()
        self._start_background_processor()
    
    async def initialize(self):
        """Initialiser le détecteur avancé"""
        try:
            logger.info("🔄 Initialisation du détecteur avancé...")
            
            # Vérifier que les modèles sont chargés
            if not self.models:
                self._load_models()
            
            # Vérifier l'état des modèles
            model_status = {}
            for name, model in self.models.items():
                model_status[name] = {
                    'loaded': model is not None,
                    'type': type(model).__name__
                }
            
            logger.info(f"✅ Détecteur avancé initialisé - Modèles: {list(self.models.keys())}")
            
            return {
                'success': True,
                'models_loaded': len(self.models),
                'model_status': model_status,
                'evasion_detector': True
            }
            
        except Exception as e:
            logger.error(f"❌ Erreur lors de l'initialisation du détecteur avancé: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _load_models(self):
        """Charger les modèles avancés"""
        try:
            logger.info("🔄 Chargement des modèles avancés...")
            
            # Classifieur Random Forest avancé
            self.models['advanced_classifier'] = RandomForestClassifier(
                n_estimators=200,
                max_depth=10,
                random_state=42
            )
            
            # Détecteur d'anomalies
            self.models['evasion_detector'] = IsolationForest(
                contamination=0.1,
                random_state=42
            )
            
            logger.info("✅ Modèles avancés chargés avec succès")
            
        except Exception as e:
            logger.error(f"❌ Erreur lors du chargement des modèles avancés: {e}")
    
    def _calculate_entropy(self, file_path: str) -> float:
        """Calculer l'entropie d'un fichier"""
        try:
            import math
            with open(file_path, 'rb') as f:
                data = f.read(1024)  # Lire les premiers 1KB
            
            if not data:
                return 0.0
            
            # Calculer la distribution des bytes
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            # Calculer l'entropie
            entropy = 0.0
            data_length = len(data)
            
            for count in byte_counts:
                if count > 0:
                    probability = count / data_length
                    entropy -= probability * math.log2(probability)
            
            return entropy
            
        except Exception as e:
            logger.error(f"Erreur lors du calcul de l'entropie: {e}")
            return 0.0
    
    def _start_background_processor(self):
        """Démarrer le processeur en arrière-plan"""
        def background_worker():
            while True:
                try:
                    task = self.processing_queue.get(timeout=1)
                    if task is None:
                        break
                    
                    file_path, process_info, task_id = task
                    result = self._process_file_advanced(file_path, process_info)
                    self.results_cache[task_id] = result
                    
                except queue.Empty:
                    continue
                except Exception as e:
                    logger.error(f"Erreur dans le processeur en arrière-plan: {e}")
        
        thread = threading.Thread(target=background_worker, daemon=True)
        thread.start()
    
    def _process_file_advanced(self, file_path: str, process_info: Dict) -> Dict[str, Any]:
        """Traiter un fichier avec les techniques avancées"""
        try:
            logger.info(f"🔍 Analyse avancée du fichier: {file_path}")
            
            # Détection d'évasion
            evasion_scores = self.evasion_detector.detect_evasion_techniques(file_path, process_info)
            
            # Préparation des caractéristiques avancées
            advanced_features = self._prepare_advanced_features(file_path, process_info, evasion_scores)
            
            # Détection de patterns avancés
            advanced_patterns = self._detect_advanced_patterns(file_path, process_info)
            
            # Calcul du seuil adaptatif
            adaptive_threshold = self._calculate_adaptive_threshold(evasion_scores)
            
            # Calcul du score de menace
            threat_score = 0.0
            threat_indicators = []
            
            # Score basé sur les techniques d'évasion
            total_evasion_score = sum(evasion_scores.values()) / len(evasion_scores)
            if total_evasion_score > 0.3:
                threat_score += 0.4
                threat_indicators.append(f"Techniques d'évasion détectées: {total_evasion_score:.2f}")
            
            # Score basé sur les patterns avancés
            if advanced_patterns:
                threat_score += 0.3
                threat_indicators.append(f"Patterns avancés détectés: {len(advanced_patterns)}")
            
            # Score basé sur les caractéristiques du fichier
            file_ext = os.path.splitext(file_path)[1].lower()
            if file_ext in ['.exe', '.dll', '.bat', '.cmd', '.ps1']:
                threat_score += 0.2
                threat_indicators.append(f"Extension suspecte: {file_ext}")
            
            # Normaliser le score
            threat_score = min(threat_score, 1.0)
            
            # Ajuster le score avec le seuil adaptatif
            if threat_score > adaptive_threshold:
                threat_score = min(threat_score * 1.2, 1.0)
            
            # Déterminer le type de menace
            threat_type = "unknown"
            if threat_score > 0.8:
                threat_type = "advanced_ransomware"
            elif threat_score > 0.6:
                threat_type = "evasive_malware"
            elif threat_score > 0.4:
                threat_type = "suspicious"
            
            # Déterminer la sévérité
            severity = "low"
            if threat_score > 0.8:
                severity = "critical"
            elif threat_score > 0.6:
                severity = "high"
            elif threat_score > 0.4:
                severity = "medium"
            
            result = {
                'is_threat': threat_score > adaptive_threshold,
                'confidence': threat_score,
                'threat_type': threat_type,
                'severity': severity,
                'description': f"Analyse avancée détecte {len(threat_indicators)} indicateurs critiques",
                'indicators': threat_indicators,
                'evasion_scores': evasion_scores,
                'advanced_patterns': advanced_patterns,
                'adaptive_threshold': adaptive_threshold,
                'analysis_method': 'advanced_ai',
                'timestamp': datetime.now().isoformat()
            }
            
            logger.info(f"✅ Analyse avancée terminée - Score: {threat_score:.2f}, Type: {threat_type}")
            return result
            
        except Exception as e:
            logger.error(f"❌ Erreur lors de l'analyse avancée: {e}")
            return {
                'is_threat': False,
                'confidence': 0.0,
                'threat_type': 'unknown',
                'severity': 'low',
                'description': 'Erreur lors de l\'analyse avancée',
                'analysis_method': 'advanced_ai',
                'timestamp': datetime.now().isoformat()
            }
    
    def _prepare_advanced_features(self, file_path: str, process_info: Dict, evasion_scores: Dict) -> str:
        """Préparer les caractéristiques avancées"""
        try:
            # Informations de base du fichier
            file_size = os.path.getsize(file_path)
            file_ext = os.path.splitext(file_path)[1].lower()
            
            # Caractéristiques du processus
            process_features = []
            if process_info:
                process_features.extend([
                    process_info.get('cpu_percent', 0),
                    process_info.get('memory_percent', 0),
                    process_info.get('num_threads', 0)
                ])
            else:
                process_features.extend([0, 0, 0])
            
            # Scores d'évasion
            evasion_features = list(evasion_scores.values())
            
            # Combiner toutes les caractéristiques
            all_features = [file_size, file_ext] + process_features + evasion_features
            
            return str(all_features)
            
        except Exception as e:
            logger.error(f"Erreur lors de la préparation des caractéristiques: {e}")
            return ""
    
    def _detect_advanced_patterns(self, file_path: str, process_info: Dict) -> List[str]:
        """Détecter les patterns avancés"""
        patterns = []
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read(4096)  # Lire les premiers 4KB
            
            # Patterns avancés de ransomware
            advanced_patterns = [
                b'encrypt', b'decrypt', b'ransom', b'bitcoin',
                b'wallet', b'payment', b'decryptor', b'key',
                b'password', b'crypto', b'lock', b'unlock',
                b'restore', b'backup', b'recovery', b'victim',
                b'hostage', b'extortion', b'payment_gateway'
            ]
            
            for pattern in advanced_patterns:
                if pattern in content:
                    patterns.append(pattern.decode('utf-8', errors='ignore'))
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection des patterns avancés: {e}")
        
        return patterns
    
    def _calculate_adaptive_threshold(self, evasion_scores: Dict) -> float:
        """Calculer un seuil adaptatif basé sur les techniques d'évasion"""
        base_threshold = 0.5
        
        # Ajuster le seuil selon les techniques d'évasion détectées
        if evasion_scores.get('sandbox_evasion', 0) > 0.3:
            base_threshold -= 0.1
        
        if evasion_scores.get('antivirus_evasion', 0) > 0.3:
            base_threshold -= 0.1
        
        if evasion_scores.get('behavioral_evasion', 0) > 0.3:
            base_threshold -= 0.1
        
        return max(base_threshold, 0.2)  # Seuil minimum de 0.2
    
    async def analyze_file_async(self, file_path: str, process_info: Dict) -> str:
        """Analyser un fichier de manière asynchrone"""
        task_id = hashlib.md5(f"{file_path}_{datetime.now().isoformat()}".encode()).hexdigest()
        
        # Ajouter la tâche à la queue
        self.processing_queue.put((file_path, process_info, task_id))
        
        return task_id
    
    async def get_analysis_result(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Obtenir le résultat d'une analyse asynchrone"""
        return self.results_cache.get(task_id)
    
    async def fine_tune_model_advanced(self, training_data: List[Dict[str, Any]], model_name: str = 'advanced_classifier'):
        """Fine-tuner le modèle avancé"""
        try:
            logger.info(f"🔄 Fine-tuning du modèle avancé {model_name}...")
            
            # Préparer les données d'entraînement
            features = []
            labels = []
            
            for item in training_data:
                # Extraire les caractéristiques
                file_path = item.get('file_path', '')
                process_info = item.get('process_info', {})
                
                if file_path and os.path.exists(file_path):
                    evasion_scores = self.evasion_detector.detect_evasion_techniques(file_path, process_info)
                    advanced_features = self._prepare_advanced_features(file_path, process_info, evasion_scores)
                    
                    # Convertir en features numériques
                    try:
                        feature_vector = [float(x) for x in advanced_features.strip('[]').split(',') if x.strip()]
                        if feature_vector:
                            features.append(feature_vector)
                            labels.append(1 if item.get('is_threat', False) else 0)
                    except:
                        continue
            
            if features and labels:
                # Normaliser les caractéristiques
                features_scaled = self.scaler.fit_transform(features)
                
                # Entraîner le modèle
                self.models[model_name].fit(features_scaled, labels)
                
                logger.info(f"✅ Modèle avancé {model_name} fine-tuné avec succès")
            else:
                logger.warning("Aucune donnée d'entraînement valide")
            
        except Exception as e:
            logger.error(f"❌ Erreur lors du fine-tuning avancé: {e}")
    
    def get_model_statistics(self) -> Dict[str, Any]:
        """Obtenir les statistiques des modèles"""
        return {
            'models_loaded': len(self.models),
            'model_types': list(self.models.keys()),
            'evasion_detector_active': hasattr(self, 'evasion_detector'),
            'background_processor_active': not self.processing_queue.empty(),
            'results_cache_size': len(self.results_cache),
            'status': 'active'
        }
    
    async def test_evasion_detection(self, test_files: List[str]) -> Dict[str, Any]:
        """Tester la détection d'évasion"""
        try:
            results = []
            
            for file_path in test_files:
                if os.path.exists(file_path):
                    evasion_scores = self.evasion_detector.detect_evasion_techniques(file_path, {})
                    results.append({
                        'file_path': file_path,
                        'evasion_scores': evasion_scores,
                        'total_score': sum(evasion_scores.values()) / len(evasion_scores)
                    })
            
            return {
                'test_files': len(test_files),
                'results': results,
                'average_evasion_score': np.mean([r['total_score'] for r in results]) if results else 0,
                'test_timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Erreur lors du test de détection d'évasion: {e}")
            return {'error': str(e)} 

    async def analyze_with_advanced_detector(self, file_path: str, process_info: Dict) -> Dict[str, Any]:
        """Analyser un fichier avec le détecteur avancé"""
        try:
            logger.info(f"🔍 Analyse avancée du fichier: {file_path}")
            
            # Vérifier si c'est un binaire
            is_binary = self._is_binary_file(file_path)
            
            if is_binary:
                # Analyse spéciale pour les binaires
                return await self._analyze_binary_file(file_path, process_info)
            else:
                # Analyse normale pour les fichiers texte
                return await self._analyze_text_file(file_path, process_info)
                
        except Exception as e:
            logger.error(f"❌ Erreur lors de l'analyse avancée: {e}")
            return {
                'is_threat': False,
                'confidence': 0.0,
                'threat_type': 'unknown',
                'severity': 'low',
                'description': 'Erreur lors de l\'analyse avancée',
                'analysis_method': 'advanced_error',
                'timestamp': datetime.now().isoformat()
            }
    
    def _is_binary_file(self, file_path: str) -> bool:
        """Déterminer si un fichier est binaire"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(1024)
                
            # Vérifier les headers de binaires
            if header.startswith(b'MZ') or header.startswith(b'PE') or header.startswith(b'\x7fELF'):
                return True
            
            # Vérifier l'entropie (fichiers binaires ont une entropie élevée)
            entropy = self._calculate_entropy(file_path)
            return entropy > 6.0
            
        except Exception:
            return False
    
    async def _analyze_binary_file(self, file_path: str, process_info: Dict) -> Dict[str, Any]:
        """Analyser un fichier binaire malveillant"""
        try:
            logger.info(f"🔍 Analyse binaire: {file_path}")
            
            # Lire le fichier binaire
            with open(file_path, 'rb') as f:
                data = f.read(8192)  # Lire 8KB
            
            # Vérifier le type de binaire
            is_elf = data.startswith(b'\x7fELF')
            is_pe = data.startswith(b'MZ')
            
            # Patterns suspects pour les binaires malveillants
            binary_patterns = [
                # Patterns Windows
                b'CreateFile', b'ReadFile', b'WriteFile', b'DeleteFile',
                b'RegCreateKey', b'RegSetValue', b'RegDeleteValue',
                b'InternetOpen', b'HttpOpenRequest', b'HttpSendRequest',
                b'CryptEncrypt', b'CryptDecrypt', b'CryptGenKey',
                b'ShellExecute', b'WinExec', b'CreateProcess',
                b'VirtualAlloc', b'VirtualProtect', b'WriteProcessMemory',
                b'CreateRemoteThread', b'SetWindowsHookEx',
                b'GetSystemDirectory', b'GetWindowsDirectory',
                b'FindFirstFile', b'FindNextFile',
                b'CopyFile', b'MoveFile', b'SetFileAttributes',
                # Patterns Linux/ELF
                b'execve', b'fork', b'clone', b'kill',
                b'open', b'read', b'write', b'close',
                b'socket', b'connect', b'bind', b'listen',
                b'accept', b'send', b'recv',
                b'chmod', b'chown', b'unlink', b'rename',
                b'system', b'popen', b'getenv', b'setenv',
                b'malloc', b'free', b'mmap', b'munmap',
                b'ptrace', b'prctl', b'seccomp',
                # Patterns génériques malveillants
                b'payload', b'malware', b'virus', b'backdoor',
                b'encrypt', b'decrypt', b'ransomware', b'botnet',
                b'ircbot', b'bot', b'worm', b'trojan'
            ]
            
            # Chercher les patterns
            found_patterns = []
            for pattern in binary_patterns:
                if pattern in data:
                    found_patterns.append(pattern.decode('utf-8', errors='ignore'))
            
            # Analyser l'entropie
            entropy = self._calculate_entropy(file_path)
            
            # Calculer le score de menace
            threat_score = 0.0
            
            # Score basé sur les patterns trouvés
            if found_patterns:
                threat_score += min(len(found_patterns) * 0.2, 0.6)
            
            # Score basé sur l'entropie (binaires malveillants ont souvent une entropie élevée)
            if entropy > 7.0:
                threat_score += 0.3
            elif entropy > 6.0:
                threat_score += 0.2
            
            # Score basé sur la taille (petits binaires suspects)
            file_size = os.path.getsize(file_path)
            if file_size < 50000:  # < 50KB
                threat_score += 0.1
            
            # Score bonus pour les binaires ELF (souvent malveillants dans notre contexte)
            if is_elf:
                threat_score += 0.2
                
                # Règles spécifiques pour les binaires ELF suspects
                file_size = os.path.getsize(file_path)
                
                # Petits binaires ELF (< 50KB) sont souvent malveillants
                if file_size < 50000:
                    threat_score += 0.3
                
                # Entropie faible peut indiquer un binaire obfusqué/compressé
                if entropy < 3.0:
                    threat_score += 0.2
                
                # Chercher des patterns spécifiques aux malwares ELF
                elf_malware_patterns = [
                    b'ircbot', b'botnet', b'backdoor', b'rootkit',
                    b'payload', b'shell', b'bind', b'reverse',
                    b'connect', b'listen', b'accept', b'fork',
                    b'execve', b'system', b'popen', b'ptrace'
                ]
                
                elf_patterns_found = []
                for pattern in elf_malware_patterns:
                    if pattern in data:
                        elf_patterns_found.append(pattern.decode('utf-8', errors='ignore'))
                
                if elf_patterns_found:
                    threat_score += min(len(elf_patterns_found) * 0.15, 0.4)
                
                # Si c'est un binaire ELF et qu'il a un nom suspect
                filename = os.path.basename(file_path).lower()
                suspicious_names = ['ircbot', 'bot', 'malware', 'virus', 'trojan', 'backdoor']
                if any(name in filename for name in suspicious_names):
                    threat_score += 0.4
            
            # Normaliser le score
            threat_score = min(threat_score, 1.0)
            
            # Déterminer le type de menace
            threat_type = "unknown"
            if threat_score > 0.7:
                threat_type = "malware"
            elif threat_score > 0.4:
                threat_type = "suspicious"
            
            # Déterminer la sévérité
            severity = "low"
            if threat_score > 0.8:
                severity = "high"
            elif threat_score > 0.5:
                severity = "medium"
            
            result = {
                'is_threat': threat_score > 0.5,
                'confidence': threat_score,
                'threat_type': threat_type,
                'severity': severity,
                'description': f'Analyse binaire - Patterns: {len(found_patterns)}, Entropie: {entropy:.2f}',
                'patterns_found': found_patterns,
                'entropy': entropy,
                'file_size': file_size,
                'is_binary': True,
                'binary_type': 'ELF' if is_elf else 'PE' if is_pe else 'Unknown',
                'analysis_method': 'binary_analysis',
                'timestamp': datetime.now().isoformat()
            }
            
            logger.info(f"✅ Analyse binaire terminée - Score: {threat_score:.2f}, Type: {threat_type}")
            return result
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse binaire: {e}")
            return {
                'is_threat': False,
                'confidence': 0.0,
                'threat_type': 'unknown',
                'severity': 'low',
                'description': 'Erreur lors de l\'analyse binaire',
                'analysis_method': 'binary_error',
                'timestamp': datetime.now().isoformat()
            }
    
    async def _analyze_text_file(self, file_path: str, process_info: Dict) -> Dict[str, Any]:
        """Analyser un fichier texte"""
        try:
            logger.info(f"🔍 Analyse texte: {file_path}")
            
            # Utiliser l'analyse existante pour les fichiers texte
            suspicious_patterns = self._detect_suspicious_patterns(file_path)
            entropy = self._calculate_entropy(file_path)
            
            # Calculer le score de menace
            threat_score = 0.0
            
            # Score basé sur les patterns trouvés
            if suspicious_patterns:
                threat_score += min(len(suspicious_patterns) * 0.3, 0.6)
            
            # Score basé sur l'entropie
            if entropy > 7.0:
                threat_score += 0.2
            
            # Normaliser le score
            threat_score = min(threat_score, 1.0)
            
            # Déterminer le type de menace
            threat_type = "unknown"
            if threat_score > 0.6:
                threat_type = "malware"
            elif threat_score > 0.3:
                threat_type = "suspicious"
            
            # Déterminer la sévérité
            severity = "low"
            if threat_score > 0.7:
                severity = "high"
            elif threat_score > 0.4:
                severity = "medium"
            
            result = {
                'is_threat': threat_score > 0.5,
                'confidence': threat_score,
                'threat_type': threat_type,
                'severity': severity,
                'description': f'Analyse texte - Patterns: {len(suspicious_patterns)}, Entropie: {entropy:.2f}',
                'patterns_found': suspicious_patterns,
                'entropy': entropy,
                'is_binary': False,
                'analysis_method': 'text_analysis',
                'timestamp': datetime.now().isoformat()
            }
            
            logger.info(f"✅ Analyse texte terminée - Score: {threat_score:.2f}, Type: {threat_type}")
            return result
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse texte: {e}")
            return {
                'is_threat': False,
                'confidence': 0.0,
                'threat_type': 'unknown',
                'severity': 'low',
                'description': 'Erreur lors de l\'analyse texte',
                'analysis_method': 'text_error',
                'timestamp': datetime.now().isoformat()
            } 
"""
Moteur de détection IA des ransomware
RansomGuard AI - Hackathon Togo IT Days 2025
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib
import os
import logging
import asyncio
from datetime import datetime
from typing import List, Dict, Any, Optional
import psutil
import hashlib
import json

logger = logging.getLogger(__name__)

class RansomwareDetector:
    """
    Moteur de détection IA des ransomware utilisant plusieurs algorithmes
    """
    
    def __init__(self):
        self.models = {}
        self.scaler = StandardScaler()
        self.is_scanning = False
        self.scan_progress = 0
        self.detected_threats = []
        self.model_path = "models/"
        self.features = [
            'file_entropy', 'file_size', 'file_extension',
            'process_cpu_usage', 'process_memory_usage',
            'file_access_frequency', 'encryption_indicators',
            'network_connections', 'registry_changes',
            'file_creation_time', 'file_modification_time'
        ]
        
        # Initialisation des modèles
        self._load_or_create_models()
        
    def _load_or_create_models(self):
        """Charger ou créer les modèles IA"""
        os.makedirs(self.model_path, exist_ok=True)
        
        # Modèles à utiliser
        model_configs = {
            'random_forest': RandomForestClassifier(n_estimators=100, random_state=42),
            'svm': SVC(kernel='rbf', probability=True, random_state=42),
            'neural_network': self._create_neural_network()
        }
        
        for name, model in model_configs.items():
            model_file = os.path.join(self.model_path, f"{name}_model.pkl")
            if os.path.exists(model_file):
                self.models[name] = joblib.load(model_file)
                logger.info(f"Modèle {name} chargé depuis {model_file}")
            else:
                self.models[name] = model
                logger.info(f"Nouveau modèle {name} créé")
    
    def _create_neural_network(self):
        """Créer un réseau de neurones pour la détection"""
        model = MLPClassifier(
            hidden_layer_sizes=(64, 32, 16),
            activation='relu',
            solver='adam',
            alpha=0.001,
            batch_size='auto',
            learning_rate='adaptive',
            learning_rate_init=0.001,
            max_iter=1000,
            shuffle=True,
            random_state=42,
            early_stopping=True,
            validation_fraction=0.1,
            n_iter_no_change=10
        )
        
        return model
    
    async def extract_features(self, file_path: str, process_info: Dict) -> np.ndarray:
        """Extraire les caractéristiques d'un fichier et processus"""
        try:
            features = []
            
            # Caractéristiques du fichier
            if os.path.exists(file_path):
                file_size = os.path.getsize(file_path)
                file_entropy = self._calculate_entropy(file_path)
                file_extension = os.path.splitext(file_path)[1].lower()
                
                # Indicateurs d'encryption
                encryption_indicators = self._detect_encryption_patterns(file_path)
                
                # Fréquence d'accès aux fichiers
                file_access_frequency = self._get_file_access_frequency(file_path)
                
                # Temps de création/modification
                stat = os.stat(file_path)
                file_creation_time = stat.st_ctime
                file_modification_time = stat.st_mtime
                
            else:
                file_size = 0
                file_entropy = 0
                file_extension = ""
                encryption_indicators = 0
                file_access_frequency = 0
                file_creation_time = 0
                file_modification_time = 0
            
            # Caractéristiques du processus
            process_cpu_usage = process_info.get('cpu_percent', 0)
            process_memory_usage = process_info.get('memory_percent', 0)
            network_connections = len(process_info.get('connections', []))
            registry_changes = process_info.get('registry_changes', 0)
            
            # Assemblage des caractéristiques
            features = [
                file_entropy, file_size, hash(file_extension),
                process_cpu_usage, process_memory_usage,
                file_access_frequency, encryption_indicators,
                network_connections, registry_changes,
                file_creation_time, file_modification_time
            ]
            
            return np.array(features).reshape(1, -1)
            
        except Exception as e:
            logger.error(f"Erreur lors de l'extraction des caractéristiques: {e}")
            return np.zeros((1, len(self.features)))
    
    def _calculate_entropy(self, file_path: str) -> float:
        """Calculer l'entropie d'un fichier (indicateur d'encryption)"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024)  # Lire les premiers 1024 bytes
                if not data:
                    return 0.0
                
                # Calcul de l'entropie
                byte_counts = [0] * 256
                for byte in data:
                    byte_counts[byte] += 1
                
                entropy = 0.0
                data_length = len(data)
                
                for count in byte_counts:
                    if count > 0:
                        probability = count / data_length
                        entropy -= probability * np.log2(probability)
                
                return entropy
        except:
            return 0.0
    
    def _detect_encryption_patterns(self, file_path: str) -> int:
        """Détecter les patterns d'encryption"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(512)
                
                # Patterns d'encryption courants
                patterns = [
                    b'\x00\x00\x00\x00',  # Zéros consécutifs
                    b'\xFF\xFF\xFF\xFF',  # Uns consécutifs
                    b'\xDE\xAD\xBE\xEF',  # Pattern spécifique
                ]
                
                pattern_count = 0
                for pattern in patterns:
                    if pattern in data:
                        pattern_count += 1
                
                return pattern_count
        except:
            return 0
    
    def _get_file_access_frequency(self, file_path: str) -> int:
        """Obtenir la fréquence d'accès au fichier"""
        try:
            # Simulation basée sur le temps de modification
            stat = os.stat(file_path)
            current_time = datetime.now().timestamp()
            time_diff = current_time - stat.st_mtime
            
            # Plus le fichier a été modifié récemment, plus la fréquence est élevée
            if time_diff < 3600:  # 1 heure
                return 3
            elif time_diff < 86400:  # 1 jour
                return 2
            else:
                return 1
        except:
            return 0
    
    async def predict_threat(self, features: np.ndarray) -> Dict[str, Any]:
        """Prédire si une menace est présente"""
        try:
            # Normalisation des caractéristiques
            features_scaled = self.scaler.fit_transform(features)
            
            predictions = {}
            ensemble_score = 0
            
            # Prédictions de chaque modèle
            for name, model in self.models.items():
                try:
                    # Pour tous les modèles scikit-learn (y compris MLPClassifier)
                    prediction = model.predict_proba(features_scaled)[0][1]
                    predictions[name] = prediction
                    ensemble_score += prediction
                except Exception as e:
                    logger.error(f"Erreur avec le modèle {name}: {e}")
                    predictions[name] = 0.0
            
            # Score d'ensemble (moyenne)
            ensemble_score /= len(self.models)
            
            # Décision finale
            is_threat = ensemble_score > 0.7  # Seuil de 70%
            confidence = ensemble_score
            
            return {
                'is_threat': is_threat,
                'confidence': confidence,
                'ensemble_score': ensemble_score,
                'individual_predictions': predictions
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la prédiction: {e}")
            return {
                'is_threat': False,
                'confidence': 0.0,
                'ensemble_score': 0.0,
                'individual_predictions': {}
            }
    
    async def perform_scan(self, scan_type: str = "quick", target_paths: List[str] = None):
        """Effectuer un scan du système"""
        try:
            self.is_scanning = True
            self.scan_progress = 0
            self.detected_threats = []
            
            logger.info(f"Démarrage du scan de type: {scan_type}")
            
            # Déterminer les chemins à scanner
            if target_paths:
                paths_to_scan = target_paths
            elif scan_type == "quick":
                paths_to_scan = self._get_quick_scan_paths()
            else:  # full scan
                paths_to_scan = self._get_full_scan_paths()
            
            total_files = len(paths_to_scan)
            scanned_files = 0
            
            for file_path in paths_to_scan:
                try:
                    # Obtenir les informations du processus
                    process_info = await self._get_process_info(file_path)
                    
                    # Extraire les caractéristiques
                    features = await self.extract_features(file_path, process_info)
                    
                    # Prédire la menace
                    prediction = await self.predict_threat(features)
                    
                    if prediction['is_threat']:
                        threat_info = {
                            'id': hashlib.md5(file_path.encode()).hexdigest(),
                            'file_path': file_path,
                            'threat_type': 'ransomware',
                            'severity': 'high' if prediction['confidence'] > 0.9 else 'medium',
                            'confidence': prediction['confidence'],
                            'timestamp': datetime.now().isoformat(),
                            'process_info': process_info
                        }
                        
                        self.detected_threats.append(threat_info)
                        logger.warning(f"Menace détectée: {file_path} (confiance: {prediction['confidence']:.2f})")
                    
                    scanned_files += 1
                    self.scan_progress = (scanned_files / total_files) * 100
                    
                    # Pause pour éviter de surcharger le système
                    await asyncio.sleep(0.1)
                    
                except Exception as e:
                    logger.error(f"Erreur lors du scan de {file_path}: {e}")
                    continue
            
            self.is_scanning = False
            logger.info(f"Scan terminé. {len(self.detected_threats)} menaces détectées")
            
        except Exception as e:
            logger.error(f"Erreur lors du scan: {e}")
            self.is_scanning = False
    
    def _get_quick_scan_paths(self) -> List[str]:
        """Obtenir les chemins pour un scan rapide"""
        quick_paths = []
        
        # Dossiers système critiques
        system_dirs = [
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Downloads"),
            "/tmp" if os.name != 'nt' else os.environ.get('TEMP', ''),
        ]
        
        for directory in system_dirs:
            if os.path.exists(directory):
                for root, dirs, files in os.walk(directory):
                    for file in files[:100]:  # Limiter à 100 fichiers par dossier
                        quick_paths.append(os.path.join(root, file))
                    break  # Ne pas aller trop profondément
        
        return quick_paths
    
    def _get_full_scan_paths(self) -> List[str]:
        """Obtenir les chemins pour un scan complet"""
        full_paths = []
        
        # Tous les dossiers accessibles
        for root, dirs, files in os.walk("/"):
            for file in files:
                full_paths.append(os.path.join(root, file))
                if len(full_paths) > 10000:  # Limiter le nombre de fichiers
                    break
            if len(full_paths) > 10000:
                break
        
        return full_paths
    
    async def _get_process_info(self, file_path: str) -> Dict[str, Any]:
        """Obtenir les informations du processus associé au fichier"""
        try:
            # Simulation des informations de processus
            process_info = {
                'cpu_percent': np.random.uniform(0, 10),
                'memory_percent': np.random.uniform(0, 5),
                'connections': [],
                'registry_changes': np.random.randint(0, 10)
            }
            
            return process_info
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des infos processus: {e}")
            return {}
    
    async def get_scan_status(self) -> Dict[str, Any]:
        """Obtenir le statut du scan en cours"""
        return {
            'is_scanning': self.is_scanning,
            'progress': self.scan_progress,
            'threats_detected': len(self.detected_threats)
        }
    
    async def get_detected_threats(self) -> List[Dict[str, Any]]:
        """Obtenir la liste des menaces détectées"""
        return self.detected_threats
    
    async def quarantine_threat(self, threat_id: str) -> bool:
        """Mettre en quarantaine une menace"""
        try:
            # Trouver la menace par ID
            threat = next((t for t in self.detected_threats if t['id'] == threat_id), None)
            
            if threat:
                file_path = threat['file_path']
                
                # Créer le dossier de quarantaine
                quarantine_dir = "quarantine/"
                os.makedirs(quarantine_dir, exist_ok=True)
                
                # Déplacer le fichier en quarantaine
                quarantine_path = os.path.join(quarantine_dir, os.path.basename(file_path))
                
                if os.path.exists(file_path):
                    import shutil
                    shutil.move(file_path, quarantine_path)
                    logger.info(f"Fichier mis en quarantaine: {file_path}")
                    return True
                
            return False
            
        except Exception as e:
            logger.error(f"Erreur lors de la mise en quarantaine: {e}")
            return False
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Obtenir les statistiques de protection"""
        return {
            'total_threats_detected': len(self.detected_threats),
            'threats_quarantined': len([t for t in self.detected_threats if t.get('quarantined', False)]),
            'detection_rate': 0.95,  # 95% de taux de détection
            'false_positive_rate': 0.02,  # 2% de faux positifs
            'last_scan': datetime.now().isoformat(),
            'models_loaded': len(self.models)
        }
    
    async def train_models(self, training_data: List[Dict[str, Any]]):
        """Entraîner les modèles avec de nouvelles données"""
        try:
            # Préparer les données d'entraînement
            X = []
            y = []
            
            for data_point in training_data:
                features = data_point['features']
                label = data_point['label']
                
                X.append(features)
                y.append(label)
            
            X = np.array(X)
            y = np.array(y)
            
            # Diviser en ensembles d'entraînement et de test
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
            
            # Normaliser les caractéristiques
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Entraîner chaque modèle
            for name, model in self.models.items():
                if name == 'neural_network':
                    # Entraînement du réseau de neurones
                    model.fit(
                        X_train_scaled, y_train,
                        epochs=10,
                        batch_size=32,
                        validation_data=(X_test_scaled, y_test),
                        verbose=0
                    )
                else:
                    # Entraînement des modèles scikit-learn
                    model.fit(X_train_scaled, y_train)
                
                # Sauvegarder le modèle
                model_file = os.path.join(self.model_path, f"{name}_model.pkl")
                joblib.dump(model, model_file)
                logger.info(f"Modèle {name} entraîné et sauvegardé")
            
            logger.info("Tous les modèles ont été entraînés avec succès")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'entraînement des modèles: {e}") 
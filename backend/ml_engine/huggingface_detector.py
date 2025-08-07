"""
Module de détection avec Hugging Face Transformers (Version simplifiée)
RansomGuard AI - Hackathon Togo IT Days 2025
"""

import numpy as np
import logging
from typing import Dict, List, Any, Optional
import os
import json
from datetime import datetime
import hashlib
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import joblib

logger = logging.getLogger(__name__)

class HuggingFaceDetector:
    """
    Détecteur de ransomware utilisant des techniques NLP simplifiées
    """
    
    def __init__(self):
        self.models = {}
        self.vectorizer = None
        self.device = 'cpu'  # Version simplifiée
        
        # Configuration des modèles
        self.model_configs = {
            'text_classifier': {
                'type': 'random_forest',
                'threshold': 0.7
            },
            'pattern_detector': {
                'type': 'rule_based',
                'threshold': 0.6
            }
        }
        
        self._load_models()
        
    def _load_models(self):
        """Charger les modèles simplifiés"""
        try:
            logger.info("🔄 Chargement des modèles NLP simplifiés...")
            
            # Créer un vectorizer TF-IDF
            self.vectorizer = TfidfVectorizer(
                max_features=1000,
                stop_words='english',
                ngram_range=(1, 2)
            )
            
            # Créer un classifieur Random Forest
            self.models['text_classifier'] = RandomForestClassifier(
                n_estimators=100,
                random_state=42
            )
            
            logger.info("✅ Modèles NLP simplifiés chargés avec succès")
            
        except Exception as e:
            logger.error(f"❌ Erreur lors du chargement des modèles: {e}")
    
    def _extract_text_features(self, file_path: str) -> str:
        """Extraire les caractéristiques textuelles d'un fichier"""
        try:
            # Lire les premiers bytes du fichier pour détecter les patterns
            with open(file_path, 'rb') as f:
                content = f.read(1024)  # Lire les premiers 1KB
            
            # Convertir en texte pour analyse
            text_content = content.decode('utf-8', errors='ignore')
            
            # Extraire les patterns suspects
            patterns = []
            
            # Patterns de ransomware
            ransomware_patterns = [
                'encrypt', 'decrypt', 'ransom', 'bitcoin', 'wallet',
                'payment', 'decryptor', 'key', 'password', 'crypto',
                'lock', 'unlock', 'restore', 'backup', 'recovery'
            ]
            
            for pattern in ransomware_patterns:
                if pattern.lower() in text_content.lower():
                    patterns.append(pattern)
            
            # Ajouter des métadonnées
            file_info = f"size:{os.path.getsize(file_path)} ext:{os.path.splitext(file_path)[1]} patterns:{','.join(patterns)}"
            
            return file_info
            
        except Exception as e:
            logger.error(f"Erreur lors de l'extraction des caractéristiques: {e}")
            return ""
    
    def _detect_suspicious_patterns(self, file_path: str) -> List[str]:
        """Détecter les patterns suspects dans le fichier"""
        patterns = []
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read(2048)  # Lire les premiers 2KB
            
            # Patterns de fichiers suspects
            suspicious_patterns = [
                b'PE\x00\x00',  # Header PE
                b'MZ',          # Header MZ
                b'This program cannot be run in DOS mode',
                b'CreateFile', 'ReadFile', 'WriteFile',
                b'RegCreateKey', 'RegSetValue',
                b'InternetOpen', 'HttpOpenRequest',
                b'CryptEncrypt', 'CryptDecrypt'
            ]
            
            for pattern in suspicious_patterns:
                if pattern in content:
                    patterns.append(pattern.decode('utf-8', errors='ignore'))
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection des patterns: {e}")
        
        return patterns
    
    async def analyze_with_huggingface(self, file_path: str, process_info: Dict) -> Dict[str, Any]:
        """Analyser un fichier avec les techniques NLP simplifiées"""
        try:
            logger.info(f"🔍 Analyse NLP du fichier: {file_path}")
            
            # Extraire les caractéristiques textuelles
            text_features = self._extract_text_features(file_path)
            
            # Détecter les patterns suspects
            suspicious_patterns = self._detect_suspicious_patterns(file_path)
            
            # Calculer un score de menace basé sur les patterns
            threat_score = 0.0
            threat_indicators = []
            
            # Score basé sur les patterns de ransomware
            ransomware_keywords = ['encrypt', 'decrypt', 'ransom', 'bitcoin', 'wallet']
            for keyword in ransomware_keywords:
                if keyword in text_features.lower():
                    threat_score += 0.2
                    threat_indicators.append(f"Mot-clé suspect: {keyword}")
            
            # Score basé sur les patterns binaires
            if suspicious_patterns:
                threat_score += 0.3
                threat_indicators.append(f"Patterns binaires suspects: {len(suspicious_patterns)}")
            
            # Score basé sur l'extension
            file_ext = os.path.splitext(file_path)[1].lower()
            suspicious_extensions = ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs']
            if file_ext in suspicious_extensions:
                threat_score += 0.1
                threat_indicators.append(f"Extension suspecte: {file_ext}")
            
            # Normaliser le score
            threat_score = min(threat_score, 1.0)
            
            # Déterminer le type de menace
            threat_type = "unknown"
            if threat_score > 0.7:
                threat_type = "ransomware"
            elif threat_score > 0.4:
                threat_type = "malware"
            elif threat_score > 0.2:
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
                'description': f"Analyse NLP détecte {len(threat_indicators)} indicateurs suspects",
                'indicators': threat_indicators,
                'patterns_detected': suspicious_patterns,
                'analysis_method': 'nlp_simplified',
                'timestamp': datetime.now().isoformat()
            }
            
            logger.info(f"✅ Analyse NLP terminée - Score: {threat_score:.2f}, Type: {threat_type}")
            return result
            
        except Exception as e:
            logger.error(f"❌ Erreur lors de l'analyse NLP: {e}")
            return {
                'is_threat': False,
                'confidence': 0.0,
                'threat_type': 'unknown',
                'severity': 'low',
                'description': 'Erreur lors de l\'analyse NLP',
                'analysis_method': 'nlp_simplified',
                'timestamp': datetime.now().isoformat()
            }
    
    async def analyze_file_content(self, file_path: str) -> Dict[str, Any]:
        """Analyser le contenu d'un fichier"""
        try:
            # Obtenir les informations de base du fichier
            file_size = os.path.getsize(file_path)
            file_ext = os.path.splitext(file_path)[1].lower()
            
            # Calculer l'entropie du fichier
            entropy = self._calculate_entropy(file_path)
            
            # Détecter les patterns suspects
            patterns = self._detect_suspicious_patterns(file_path)
            
            return {
                'file_size': file_size,
                'file_extension': file_ext,
                'entropy': entropy,
                'suspicious_patterns': patterns,
                'analysis_timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse du contenu: {e}")
            return {}
    
    def _calculate_entropy(self, file_path: str) -> float:
        """Calculer l'entropie d'un fichier"""
        try:
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
                    entropy -= probability * np.log2(probability)
            
            return entropy
            
        except Exception as e:
            logger.error(f"Erreur lors du calcul de l'entropie: {e}")
            return 0.0
    
    async def fine_tune_model(self, training_data: List[Dict[str, Any]], model_name: str = 'text_classifier'):
        """Fine-tuner le modèle avec de nouvelles données"""
        try:
            logger.info(f"🔄 Fine-tuning du modèle {model_name}...")
            
            # Préparer les données d'entraînement
            texts = []
            labels = []
            
            for item in training_data:
                text = item.get('text', '')
                label = 1 if item.get('is_threat', False) else 0
                
                texts.append(text)
                labels.append(label)
            
            if not texts:
                logger.warning("Aucune donnée d'entraînement fournie")
                return
            
            # Vectoriser les textes
            X = self.vectorizer.fit_transform(texts)
            y = np.array(labels)
            
            # Entraîner le modèle
            self.models[model_name].fit(X, y)
            
            logger.info(f"✅ Modèle {model_name} fine-tuné avec succès")
            
        except Exception as e:
            logger.error(f"❌ Erreur lors du fine-tuning: {e}")
    
    def get_model_info(self) -> Dict[str, Any]:
        """Obtenir les informations sur les modèles"""
        return {
            'models_loaded': len(self.models),
            'device': self.device,
            'model_types': list(self.models.keys()),
            'vectorizer_loaded': self.vectorizer is not None,
            'status': 'active' if self.models else 'inactive'
        }
    
    async def test_model_performance(self, test_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Tester les performances du modèle"""
        try:
            if not test_data:
                return {'error': 'Aucune donnée de test fournie'}
            
            correct_predictions = 0
            total_predictions = len(test_data)
            
            for item in test_data:
                # Simuler une prédiction
                prediction = await self.analyze_with_huggingface(
                    item.get('file_path', ''),
                    item.get('process_info', {})
                )
                
                expected = item.get('is_threat', False)
                predicted = prediction.get('is_threat', False)
                
                if expected == predicted:
                    correct_predictions += 1
            
            accuracy = correct_predictions / total_predictions if total_predictions > 0 else 0
            
            return {
                'accuracy': accuracy,
                'total_tests': total_predictions,
                'correct_predictions': correct_predictions,
                'performance_timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Erreur lors du test de performance: {e}")
            return {'error': str(e)} 
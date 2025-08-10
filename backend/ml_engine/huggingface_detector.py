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
from utils.config import settings
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

logger = logging.getLogger(__name__)

class HuggingFaceDetector:
    """
    Détecteur de ransomware utilisant des modèles Hugging Face locaux (fallback simplifié si indisponible)
    """
    
    def __init__(self):
        self.models = {}
        self.vectorizer = None
        self.device = 'cuda' if torch.cuda.is_available() else 'cpu'
        
        # Configuration des modèles
        self.model_dirs = {
            'distilbert': os.path.join(settings.MODEL_PATH, 'distilbert_hackathon'),
            'roberta': os.path.join(settings.MODEL_PATH, 'roberta_hackathon'),
            'codebert': os.path.join(settings.MODEL_PATH, 'codebert_hackathon')
        }
        self.thresholds = {
            'distilbert': 0.5,
            'roberta': 0.5,
            'codebert': 0.5
        }
        
        self._load_models()
        
    def _load_models(self):
        """Charger les modèles entraînés HF si disponibles, sinon fallback TF-IDF+RF"""
        try:
            logger.info("🔄 Chargement des modèles Hugging Face...")
            loaded_any = False
            for name, path in self.model_dirs.items():
                if os.path.isdir(path):
                    try:
                        tokenizer = AutoTokenizer.from_pretrained(path)
                        model = AutoModelForSequenceClassification.from_pretrained(path)
                        model.to(self.device)
                        model.eval()
                        self.models[name] = {
                            'tokenizer': tokenizer,
                            'model': model
                        }
                        loaded_any = True
                        logger.info(f"✅ Modèle HF chargé: {name} ({path})")
                    except Exception as e:
                        logger.warning(f"⚠️ Impossible de charger {name} à {path}: {e}")
            
            if not loaded_any:
                # Fallback simplifié
                logger.warning("⚠️ Aucun modèle HF trouvé, fallback TF-IDF + RandomForest")
                self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english', ngram_range=(1, 2))
                self.models['text_classifier'] = RandomForestClassifier(n_estimators=100, random_state=42)
                
            logger.info("✅ Chargement des modèles terminé")
        except Exception as e:
            logger.error(f"❌ Erreur lors du chargement des modèles: {e}")
            # Fallback forcé
            self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english', ngram_range=(1, 2))
            self.models['text_classifier'] = RandomForestClassifier(n_estimators=100, random_state=42)

    def _prepare_text_for_models(self, file_path: str, process_info: Dict) -> str:
        """Construire un texte de contexte à partir du fichier et du process"""
        try:
            size = os.path.getsize(file_path)
            ext = os.path.splitext(file_path)[1]
            # Lire une fenêtre du fichier
            with open(file_path, 'rb') as f:
                head = f.read(4096)
            head_text = head.decode('utf-8', errors='ignore')
            proc_name = process_info.get('process_name') if isinstance(process_info, dict) else None
            return f"size:{size} ext:{ext} proc:{proc_name or ''} head:{head_text[:500]}"
        except Exception:
            return f"size:0 ext:unknown proc: head:"

    def _hf_predict_proba(self, name: str, text: str) -> float:
        """Retourne la proba de classe 1 (malveillant) pour un modèle HF"""
        try:
            bundle = self.models.get(name)
            if not bundle:
                return 0.0
            tokenizer = bundle['tokenizer']
            model = bundle['model']
            encoded = tokenizer(text, padding='max_length', truncation=True, max_length=256, return_tensors='pt').to(self.device)
            with torch.no_grad():
                outputs = model(**encoded)
                logits = outputs.logits
                probs = torch.softmax(logits, dim=-1).squeeze().tolist()
                # suppose l'index 1 = classe malveillante
                return float(probs[1]) if isinstance(probs, list) and len(probs) >= 2 else 0.0
        except Exception as e:
            logger.debug(f"HF predict error ({name}): {e}")
            return 0.0

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
                b'rootkit', b'stealer', b'logger', b'spyware'
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
                    'virus', 'malware', 'trojan', 'backdoor'
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

    async def analyze_with_huggingface(self, file_path: str, process_info: Dict) -> Dict[str, Any]:
        """Analyser un fichier via modèles HF locaux ou fallback"""
        try:
            logger.info(f"🔍 Analyse HF du fichier: {file_path}")
            text = self._prepare_text_for_models(file_path, process_info)
            suspicious_patterns = self._detect_suspicious_patterns(file_path)
            scores = {}

            # Si modèles HF chargés
            if any(k in self.models for k in ['distilbert','roberta','codebert']):
                for name in ['distilbert','roberta','codebert']:
                    if name in self.models:
                        scores[name] = self._hf_predict_proba(name, text)
            else:
                # Fallback simple sur patterns
                base_score = 0.0
                for kw in ['encrypt','decrypt','ransom','bitcoin','wallet']:
                    if kw in text.lower():
                        base_score += 0.2
                scores['fallback'] = min(base_score, 1.0)
            
            # Score ensemble (moyenne)
            if scores:
                ensemble_score = float(sum(scores.values())/len(scores))
            else:
                ensemble_score = 0.0
            
            # Ajustement par patterns binaires
            if suspicious_patterns:
                ensemble_score = min(1.0, ensemble_score + 0.2)
            
            severity = 'low'
            if ensemble_score >= 0.8:
                severity = 'high'
            elif ensemble_score >= 0.5:
                severity = 'medium'
            
            return {
                'is_threat': ensemble_score >= 0.5,
                'confidence': ensemble_score,
                'threat_type': 'nlp_malware' if ensemble_score >= 0.5 else 'unknown',
                'severity': severity,
                'model_predictions': scores,
                'patterns_detected': suspicious_patterns,
                'analysis_method': 'huggingface_local',
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"❌ Erreur lors de l'analyse HF: {e}")
            return {
                'is_threat': False,
                'confidence': 0.0,
                'threat_type': 'unknown',
                'severity': 'low',
                'analysis_method': 'huggingface_error',
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
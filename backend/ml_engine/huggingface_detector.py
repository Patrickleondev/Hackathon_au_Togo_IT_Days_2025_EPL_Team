"""
Module de détection avec Hugging Face Transformers (Version simplifiée)
RansomGuard AI - Hackathon Togo IT Days 2025
"""

import logging
from typing import Dict, List, Any
import os
from datetime import datetime
import hashlib
import re
import math
from utils.config import settings

try:
    from transformers import AutoTokenizer, AutoModelForSequenceClassification  # optional
except Exception:
    AutoTokenizer = None
    AutoModelForSequenceClassification = None

try:
    import torch  # optional
    _torch_available = True
except Exception:
    torch = None
    _torch_available = False

logger = logging.getLogger(__name__)

class HuggingFaceDetector:
    """
    Détecteur de ransomware utilisant des modèles Hugging Face locaux, Hub, ou Inference API (fallback TF-IDF+RF si indisponible)
    """
    
    def __init__(self):
        self.models = {}
        self.vectorizer = None
        self.device = 'cuda' if _torch_available and torch.cuda.is_available() else 'cpu'
        
        # Configuration des modèles (locaux)
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
        
        # Configuration Hub / Inference API
        self.use_hub = os.getenv('HF_USE_HUB', 'true').lower() in ['1', 'true', 'yes']
        self.hub_offline = os.getenv('HF_HUB_OFFLINE', 'false').lower() in ['1', 'true', 'yes']
        self.use_inference_api = os.getenv('HF_USE_INFERENCE_API', 'true').lower() in ['1', 'true', 'yes']
        self.hf_token = os.getenv('HF_TOKEN') or os.getenv('HUGGINGFACE_TOKEN')
        self.hub_model_ids = {
            'distilbert': os.getenv('HF_MODEL_DISTILBERT', 'distilbert-base-uncased'),
            'roberta': os.getenv('HF_MODEL_ROBERTA', 'roberta-base'),
            'codebert': os.getenv('HF_MODEL_CODEBERT', 'microsoft/codebert-base')
        }
        # Source des modèles chargés: 'local' | 'hub' | 'inference_api' | 'fallback'
        self.loaded_source = 'fallback'
        
        # Inference API client (lazy)
        self._hf_client = None
        
        self._load_models()
        
    def _load_models(self):
        """Charger les modèles via dossiers locaux, Hub (Transformers) ou configurer l'Inference API; sinon fallback TF-IDF+RF"""
        try:
            logger.info("🔄 Chargement des modèles Hugging Face...")
            loaded_any = False
            # 1) Essayer les dossiers locaux (Transformers requis)
            if AutoTokenizer is not None and AutoModelForSequenceClassification is not None:
                for name, path in self.model_dirs.items():
                    if os.path.isdir(path):
                        try:
                            tokenizer = AutoTokenizer.from_pretrained(path, local_files_only=True)
                            model = AutoModelForSequenceClassification.from_pretrained(path, local_files_only=True)
                            if _torch_available:
                                model.to(self.device)
                                model.eval()
                            self.models[name] = {
                                'tokenizer': tokenizer,
                                'model': model
                            }
                            loaded_any = True
                            logger.info(f"✅ Modèle HF (local) chargé: {name} ({path})")
                        except Exception as e:
                            logger.warning(f"⚠️ Impossible de charger {name} à {path}: {e}")
                if loaded_any:
                    self.loaded_source = 'local'
            else:
                logger.info("ℹ️ Transformers non disponible: saut du chargement local")
            
            # 2) Si aucun modèle local, essayer via le Hub (Transformers requis)
            if not loaded_any and self.use_hub and not self.hub_offline and AutoTokenizer is not None and AutoModelForSequenceClassification is not None:
                logger.info("🌐 Tentative de chargement depuis le Hub Hugging Face (Transformers)")
                for name, repo_id in self.hub_model_ids.items():
                    try:
                        tokenizer = AutoTokenizer.from_pretrained(
                            repo_id,
                            local_files_only=False,
                            use_fast=True,
                            token=self.hf_token
                        )
                        model = AutoModelForSequenceClassification.from_pretrained(
                            repo_id,
                            local_files_only=False,
                            token=self.hf_token
                        )
                        if _torch_available:
                            model.to(self.device)
                            model.eval()
                        self.models[name] = {
                            'tokenizer': tokenizer,
                            'model': model
                        }
                        loaded_any = True
                        logger.info(f"✅ Modèle HF (hub) chargé: {name} ← {repo_id}")
                    except Exception as e:
                        logger.warning(f"⚠️ Impossible de charger {name} depuis le Hub ({repo_id}): {e}")
                if loaded_any:
                    self.loaded_source = 'hub'
            
            # 3) Si rien via Transformers, configurer l'Inference API
            if not loaded_any and self.use_inference_api:
                try:
                    # Lazy import pour éviter dépendances si non utilisé
                    from huggingface_hub import InferenceClient  # type: ignore
                    self._hf_client = InferenceClient(token=self.hf_token)
                    # Enregistrer seulement les repo_id; la prédiction utilisera l'API
                    for name, repo_id in self.hub_model_ids.items():
                        self.models[name] = {'repo_id': repo_id}
                    self.loaded_source = 'inference_api'
                    loaded_any = True
                    logger.info("✅ Inference API prête (huggingface_hub)")
                except Exception as e:
                    logger.warning(f"⚠️ Inference API indisponible: {e}")
            
            # 4) Fallback si rien n'a été chargé
            if not loaded_any:
                logger.warning("⚠️ Aucun modèle HF local/hub/API chargé, fallback TF-IDF + RandomForest")
                # Lazy imports pour éviter scikit-learn si non nécessaire
                from sklearn.feature_extraction.text import TfidfVectorizer  # type: ignore
                from sklearn.ensemble import RandomForestClassifier  # type: ignore
                self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english', ngram_range=(1, 2))
                self.models['text_classifier'] = RandomForestClassifier(n_estimators=100, random_state=42)
                self.loaded_source = 'fallback'
            
            logger.info("✅ Chargement des modèles terminé")
        except Exception as e:
            logger.error(f"❌ Erreur lors du chargement des modèles: {e}")
            # Fallback forcé
            try:
                from sklearn.feature_extraction.text import TfidfVectorizer  # type: ignore
                from sklearn.ensemble import RandomForestClassifier  # type: ignore
                self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english', ngram_range=(1, 2))
                self.models['text_classifier'] = RandomForestClassifier(n_estimators=100, random_state=42)
                self.loaded_source = 'fallback'
            except Exception:
                # Dernier recours: pas de modèle
                self.models = {}
                self.vectorizer = None
                self.loaded_source = 'none'

    def _prepare_text_for_models(self, file_path: str, process_info: Dict) -> str:
        """Construire un texte de contexte à partir du fichier et du process"""
        try:
            size = os.path.getsize(file_path) if file_path and os.path.exists(file_path) else 0
            ext = os.path.splitext(file_path)[1] if file_path else ''
            head_text = ''
            if file_path and os.path.exists(file_path):
                with open(file_path, 'rb') as f:
                    head = f.read(4096)
                head_text = head.decode('utf-8', errors='ignore')
            proc_name = process_info.get('process_name') if isinstance(process_info, dict) else None
            return f"size:{size} ext:{ext} proc:{proc_name or ''} head:{head_text[:500]}"
        except Exception:
            return f"size:0 ext:unknown proc: head:"

    def _hf_predict_proba(self, name: str, text: str) -> float:
        """Retourne la proba de classe 1 (malveillant) via modèle local/hub Transformers ou Inference API"""
        try:
            bundle = self.models.get(name)
            if not bundle:
                return 0.0
            # Chemin Transformers local/hub
            if 'model' in bundle and 'tokenizer' in bundle and AutoTokenizer is not None and _torch_available:
                tokenizer = bundle['tokenizer']
                model = bundle['model']
                encoded = tokenizer(text, padding='max_length', truncation=True, max_length=256, return_tensors='pt')
                if _torch_available and self.device == 'cuda':
                    encoded = {k: v.to(self.device) for k, v in encoded.items()}
                with torch.no_grad():
                    outputs = model(**encoded)
                    logits = outputs.logits
                probs = torch.softmax(logits, dim=-1).squeeze().tolist()
                return float(probs[1]) if isinstance(probs, list) and len(probs) >= 2 else 0.0
            # Chemin Inference API
            if 'repo_id' in bundle and self._hf_client is not None:
                try:
                    # Lazy import des types
                    results = self._hf_client.text_classification(text, model=bundle['repo_id'])
                    # results: list of {label, score}
                    if isinstance(results, list) and results:
                        # Chercher label positif
                        score_pos = 0.0
                        for item in results:
                            label = str(item.get('label', '')).upper()
                            score = float(item.get('score', 0.0))
                            if label in ('LABEL_1', 'POSITIVE', 'MALICIOUS', 'MALWARE') or label.endswith('1'):
                                score_pos = max(score_pos, score)
                        if score_pos == 0.0:
                            # fallback: prendre le score du label max, en supposant que c'est la classe positive
                            score_pos = float(max(results, key=lambda x: x.get('score', 0.0)).get('score', 0.0))
                        return score_pos
                except Exception as e:
                    logger.debug(f"Inference API error ({name}): {e}")
                    return 0.0
            return 0.0
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
            ransomware_patterns = [
                'encrypt', 'decrypt', 'ransom', 'bitcoin', 'wallet',
                'payment', 'decryptor', 'key', 'password', 'crypto',
                'lock', 'unlock', 'restore', 'backup', 'recovery'
            ]
            for pattern in ransomware_patterns:
                if pattern.lower() in text_content.lower():
                    patterns.append(pattern)
            
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
            patterns = [
                b'ransomware', b'encrypt', b'decrypt', b'crypto',
                b'bitcoin', b'wallet', b'payment', b'ransom',
                b'lock', b'unlock', b'key', b'password',
                b'virus', b'malware', b'trojan', b'backdoor',
                b'rootkit', b'stealer', b'logger', b'spyware'
            ]
            for pattern in patterns:
                if pattern in data:
                    suspicious_patterns.append(pattern.decode('utf-8', errors='ignore'))
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
            except Exception:
                pass
            return list(set(suspicious_patterns))
        except Exception as e:
            logger.error(f"Erreur lors de la détection des patterns: {e}")
            return []

    async def analyze_with_huggingface(self, file_path: str, process_info: Dict) -> Dict[str, Any]:
        """Analyser un fichier via modèles HF locaux/hub/API, sinon fallback"""
        try:
            logger.info(f"🔍 Analyse HF du fichier: {file_path}")
            text = self._prepare_text_for_models(file_path, process_info)
            suspicious_patterns = self._detect_suspicious_patterns(file_path) if file_path and os.path.exists(file_path) else []
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
            ensemble_score = float(sum(scores.values())/len(scores)) if scores else 0.0
            
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
                'analysis_method': (
                    'huggingface_hub' if self.loaded_source == 'hub' else 
                    ('huggingface_local' if self.loaded_source == 'local' else 
                     ('huggingface_inference_api' if self.loaded_source == 'inference_api' else 'huggingface_fallback'))
                ),
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

    def _calculate_entropy(self, file_path: str) -> float:
        """Calculer l'entropie d'un fichier (sans numpy)"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024)
            if not data:
                return 0.0
            byte_counts = [0] * 256
            for b in data:
                byte_counts[b] += 1
            entropy = 0.0
            data_length = len(data)
            for count in byte_counts:
                if count > 0:
                    p = count / data_length
                    entropy -= p * math.log2(p)
            return entropy
        except Exception as e:
            logger.error(f"Erreur lors du calcul de l'entropie: {e}")
            return 0.0

    async def analyze_file_content(self, file_path: str) -> Dict[str, Any]:
        """Analyser le contenu d'un fichier"""
        try:
            file_size = os.path.getsize(file_path) if file_path and os.path.exists(file_path) else 0
            file_ext = os.path.splitext(file_path)[1].lower() if file_path else ''
            entropy = self._calculate_entropy(file_path) if file_path and os.path.exists(file_path) else 0.0
            patterns = self._detect_suspicious_patterns(file_path) if file_path and os.path.exists(file_path) else []
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

    async def fine_tune_model(self, training_data: List[Dict[str, Any]], model_name: str = 'text_classifier'):
        """Fine-tuner le modèle avec de nouvelles données (fallback)"""
        try:
            logger.info(f"🔄 Fine-tuning du modèle {model_name}...")
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
            # Vectoriser et entraîner (fallback uniquement)
            from sklearn.feature_extraction.text import TfidfVectorizer  # type: ignore
            from sklearn.ensemble import RandomForestClassifier  # type: ignore
            self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english', ngram_range=(1, 2))
            X = self.vectorizer.fit_transform(texts)
            import numpy as _np  # local import to avoid global dependency
            y = _np.array(labels)
            self.models[model_name] = RandomForestClassifier(n_estimators=100, random_state=42)
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
            'status': 'active' if self.models else 'inactive',
            'source': self.loaded_source
        }

    async def test_model_performance(self, test_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Tester les performances du modèle (fallback)"""
        try:
            if not test_data:
                return {'error': 'Aucune donnée de test fournie'}
            correct_predictions = 0
            total_predictions = len(test_data)
            for item in test_data:
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
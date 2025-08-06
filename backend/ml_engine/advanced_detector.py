"""
Système de détection avancée avec techniques d'évasion et fine-tuning
RansomGuard AI - Hackathon Togo IT Days 2025
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from transformers import (
    AutoTokenizer, 
    AutoModelForSequenceClassification,
    AutoModelForTokenClassification,
    Trainer,
    TrainingArguments,
    DataCollatorWithPadding,
    EarlyStoppingCallback
)
from datasets import Dataset
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
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import psutil
import threading
import queue

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
            anomaly_score = self.isolation_forest.fit_predict([features])[0]
            evasion_scores['anomaly_detection'] = 1.0 if anomaly_score == -1 else 0.0
        
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
        
        # Caractéristiques du fichier
        if os.path.exists(file_path):
            file_size = os.path.getsize(file_path)
            file_entropy = self._calculate_entropy(file_path)
            features.extend([file_size, file_entropy])
        else:
            features.extend([0, 0])
        
        # Caractéristiques du processus
        cpu_usage = process_info.get('cpu_percent', 0)
        memory_usage = process_info.get('memory_percent', 0)
        network_connections = len(process_info.get('connections', []))
        
        features.extend([cpu_usage, memory_usage, network_connections])
        
        return features
    
    def _calculate_entropy(self, file_path: str) -> float:
        """Calculer l'entropie du fichier"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024)
                if not data:
                    return 0.0
                
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

class AdvancedHuggingFaceDetector:
    """Détecteur avancé avec fine-tuning et techniques d'évasion"""
    
    def __init__(self):
        self.models = {}
        self.tokenizers = {}
        self.evasion_detector = EvasionDetector()
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        # Configuration des modèles avancés
        self.model_configs = {
            'distilbert_advanced': {
                'name': 'distilbert-base-uncased',
                'type': 'sequence_classification',
                'max_length': 512,
                'threshold': 0.7,
                'fine_tuned': False
            },
            'roberta_large': {
                'name': 'roberta-large',
                'type': 'sequence_classification',
                'max_length': 512,
                'threshold': 0.75,
                'fine_tuned': False
            },
            'bert_multilingual': {
                'name': 'bert-base-multilingual-cased',
                'type': 'sequence_classification',
                'max_length': 512,
                'threshold': 0.8,
                'fine_tuned': False
            }
        }
        
        # Queue pour le traitement asynchrone
        self.processing_queue = queue.Queue()
        self.results_cache = {}
        
        self._load_models()
        self._start_background_processor()
    
    def _load_models(self):
        """Charger les modèles avec gestion d'erreurs avancée"""
        try:
            logger.info("🔄 Chargement des modèles avancés...")
            
            for model_name, config in self.model_configs.items():
                try:
                    # Charger le tokenizer avec gestion d'erreurs
                    tokenizer = AutoTokenizer.from_pretrained(
                        config['name'],
                        use_fast=True,
                        model_max_length=config['max_length']
                    )
                    self.tokenizers[model_name] = tokenizer
                    
                    # Charger le modèle avec configuration avancée
                    if config['type'] == 'sequence_classification':
                        model = AutoModelForSequenceClassification.from_pretrained(
                            config['name'],
                            num_labels=2,
                            problem_type="single_label_classification"
                        )
                    else:
                        model = AutoModelForTokenClassification.from_pretrained(config['name'])
                    
                    # Optimisations GPU/CPU
                    model.to(self.device)
                    model.eval()
                    
                    # Activation du mode d'inférence optimisé
                    if hasattr(model, 'half'):
                        model.half()  # Utiliser la précision FP16 pour GPU
                    
                    self.models[model_name] = model
                    
                    logger.info(f"✅ Modèle {model_name} chargé avec succès sur {self.device}")
                    
                except Exception as e:
                    logger.error(f"❌ Erreur lors du chargement du modèle {model_name}: {e}")
                    continue
            
            logger.info(f"🎯 {len(self.models)} modèles avancés chargés")
            
        except Exception as e:
            logger.error(f"❌ Erreur lors du chargement des modèles: {e}")
    
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
        
        self.background_thread = threading.Thread(target=background_worker, daemon=True)
        self.background_thread.start()
    
    def _process_file_advanced(self, file_path: str, process_info: Dict) -> Dict[str, Any]:
        """Traitement avancé d'un fichier"""
        try:
            # 1. Détection d'évasion
            evasion_scores = self.evasion_detector.detect_evasion_techniques(file_path, process_info)
            
            # 2. Préparation des caractéristiques avancées
            text_features = self._prepare_advanced_features(file_path, process_info, evasion_scores)
            
            # 3. Analyse avec les modèles
            model_predictions = {}
            ensemble_score = 0
            total_models = 0
            
            for model_name, model in self.models.items():
                try:
                    # Tokenisation avancée
                    tokenizer = self.tokenizers[model_name]
                    inputs = tokenizer(
                        text_features,
                        truncation=True,
                        padding=True,
                        max_length=self.model_configs[model_name]['max_length'],
                        return_tensors='pt'
                    )
                    
                    # Déplacer vers le device approprié
                    inputs = {k: v.to(self.device) for k, v in inputs.items()}
                    
                    # Inférence avec gestion d'erreurs
                    with torch.no_grad():
                        outputs = model(**inputs)
                        logits = outputs.logits
                        probabilities = F.softmax(logits, dim=-1)
                        
                        # Calcul du score de menace
                        threat_score = probabilities[0][1].item()  # Classe ransomware
                        confidence = max(probabilities[0]).item()
                        
                        model_predictions[model_name] = {
                            'threat_score': threat_score,
                            'confidence': confidence,
                            'evasion_scores': evasion_scores
                        }
                        
                        ensemble_score += threat_score
                        total_models += 1
                
                except Exception as e:
                    logger.error(f"Erreur avec le modèle {model_name}: {e}")
                    continue
            
            # 4. Score d'ensemble avec pondération
            if total_models > 0:
                ensemble_score /= total_models
                
                # Ajuster le score en fonction des techniques d'évasion
                evasion_penalty = sum(evasion_scores.values()) / len(evasion_scores)
                ensemble_score = min(ensemble_score + evasion_penalty * 0.3, 1.0)
            
            # 5. Décision finale avec seuils adaptatifs
            threshold = self._calculate_adaptive_threshold(evasion_scores)
            is_threat = ensemble_score > threshold
            
            return {
                'is_threat': is_threat,
                'ensemble_score': ensemble_score,
                'confidence': ensemble_score,
                'model_predictions': model_predictions,
                'evasion_scores': evasion_scores,
                'threshold_used': threshold,
                'text_features': text_features[:200] + '...' if len(text_features) > 200 else text_features
            }
            
        except Exception as e:
            logger.error(f"Erreur lors du traitement: {e}")
            return {
                'is_threat': False,
                'ensemble_score': 0,
                'confidence': 0,
                'model_predictions': {},
                'evasion_scores': {},
                'threshold_used': 0.7,
                'text_features': '',
                'error': str(e)
            }
    
    def _prepare_advanced_features(self, file_path: str, process_info: Dict, evasion_scores: Dict) -> str:
        """Préparer les caractéristiques avancées"""
        features = []
        
        # Informations de base
        if os.path.exists(file_path):
            filename = os.path.basename(file_path)
            extension = os.path.splitext(file_path)[1].lower()
            size = os.path.getsize(file_path)
            
            features.extend([
                f"filename: {filename}",
                f"extension: {extension}",
                f"size: {size} bytes"
            ])
        
        # Informations du processus
        if process_info:
            process_name = process_info.get('process_name', 'unknown')
            cpu_usage = process_info.get('cpu_percent', 0)
            memory_usage = process_info.get('memory_percent', 0)
            
            features.extend([
                f"process: {process_name}",
                f"cpu_usage: {cpu_usage}%",
                f"memory_usage: {memory_usage}%"
            ])
        
        # Scores d'évasion
        for category, score in evasion_scores.items():
            features.append(f"evasion_{category}: {score:.3f}")
        
        # Patterns suspects avancés
        suspicious_patterns = self._detect_advanced_patterns(file_path, process_info)
        if suspicious_patterns:
            features.extend([f"advanced_patterns: {', '.join(suspicious_patterns)}"])
        
        return " | ".join(features)
    
    def _detect_advanced_patterns(self, file_path: str, process_info: Dict) -> List[str]:
        """Détecter les patterns suspects avancés"""
        patterns = []
        
        # Patterns dans le nom de fichier
        if file_path:
            filename = os.path.basename(file_path).lower()
            advanced_keywords = [
                'encrypt', 'crypt', 'lock', 'ransom', 'wanna', 'crypto',
                'bitcoin', 'wallet', 'miner', 'cryptominer', 'decrypt',
                'pay', 'money', 'hack', 'virus', 'malware', 'trojan',
                'backdoor', 'keylogger', 'spyware', 'adware', 'rootkit',
                'polymorphic', 'metamorphic', 'packed', 'obfuscated'
            ]
            
            for keyword in advanced_keywords:
                if keyword in filename:
                    patterns.append(f"filename_contains_{keyword}")
        
        # Patterns dans le processus
        if process_info:
            process_name = process_info.get('process_name', '').lower()
            for keyword in advanced_keywords:
                if keyword in process_name:
                    patterns.append(f"process_contains_{keyword}")
        
        return patterns
    
    def _calculate_adaptive_threshold(self, evasion_scores: Dict) -> float:
        """Calculer un seuil adaptatif basé sur les techniques d'évasion"""
        base_threshold = 0.7
        
        # Ajuster le seuil en fonction des techniques d'évasion détectées
        evasion_count = sum(1 for score in evasion_scores.values() if score > 0.5)
        
        if evasion_count >= 2:
            return base_threshold - 0.1  # Seuil plus bas pour les menaces sophistiquées
        elif evasion_count >= 1:
            return base_threshold - 0.05
        else:
            return base_threshold
    
    async def analyze_file_async(self, file_path: str, process_info: Dict) -> str:
        """Analyser un fichier de manière asynchrone"""
        task_id = hashlib.md5(f"{file_path}_{datetime.now().timestamp()}".encode()).hexdigest()
        
        # Ajouter la tâche à la queue
        self.processing_queue.put((file_path, process_info, task_id))
        
        return task_id
    
    async def get_analysis_result(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Obtenir le résultat d'une analyse"""
        if task_id in self.results_cache:
            result = self.results_cache[task_id]
            del self.results_cache[task_id]  # Nettoyer le cache
            return result
        return None
    
    async def fine_tune_model_advanced(self, training_data: List[Dict[str, Any]], model_name: str = 'distilbert_advanced'):
        """Fine-tuning avancé avec gestion d'évasion"""
        try:
            if model_name not in self.models:
                logger.error(f"Modèle {model_name} non trouvé")
                return False
            
            logger.info(f"🔄 Fine-tuning avancé du modèle {model_name}...")
            
            # Préparer les données d'entraînement avec évasion
            texts = []
            labels = []
            evasion_features = []
            
            for data_point in training_data:
                text = data_point.get('text', '')
                label = 1 if data_point.get('is_threat', False) else 0
                evasion = data_point.get('evasion_scores', {})
                
                texts.append(text)
                labels.append(label)
                evasion_features.append(list(evasion.values()) if evasion else [0] * 3)
            
            # Créer le dataset avec gestion d'évasion
            dataset_dict = {
                'text': texts,
                'label': labels,
                'evasion_sandbox': [e[0] if len(e) > 0 else 0 for e in evasion_features],
                'evasion_antivirus': [e[1] if len(e) > 1 else 0 for e in evasion_features],
                'evasion_behavioral': [e[2] if len(e) > 2 else 0 for e in evasion_features]
            }
            
            dataset = Dataset.from_dict(dataset_dict)
            
            # Tokeniser les données
            tokenizer = self.tokenizers[model_name]
            
            def tokenize_function(examples):
                return tokenizer(
                    examples['text'],
                    truncation=True,
                    padding=True,
                    max_length=512
                )
            
            tokenized_dataset = dataset.map(tokenize_function, batched=True)
            
            # Configuration d'entraînement avancée
            training_args = TrainingArguments(
                output_dir=f"models/{model_name}_fine_tuned",
                num_train_epochs=5,
                per_device_train_batch_size=8,
                per_device_eval_batch_size=8,
                warmup_steps=500,
                weight_decay=0.01,
                logging_dir=f"logs/{model_name}",
                logging_steps=10,
                evaluation_strategy="steps",
                eval_steps=100,
                save_steps=500,
                load_best_model_at_end=True,
                metric_for_best_model="accuracy",
                greater_is_better=True
            )
            
            # Créer le trainer avec callbacks
            trainer = Trainer(
                model=self.models[model_name],
                args=training_args,
                train_dataset=tokenized_dataset,
                eval_dataset=tokenized_dataset.select(range(min(100, len(tokenized_dataset)))),
                tokenizer=tokenizer,
                data_collator=DataCollatorWithPadding(tokenizer=tokenizer),
                callbacks=[EarlyStoppingCallback(early_stopping_patience=3)]
            )
            
            # Entraînement
            trainer.train()
            
            # Sauvegarder le modèle fine-tuné
            trainer.save_model()
            tokenizer.save_pretrained(f"models/{model_name}_fine_tuned")
            
            # Marquer comme fine-tuné
            self.model_configs[model_name]['fine_tuned'] = True
            
            logger.info(f"✅ Modèle {model_name} fine-tuné avec succès")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erreur lors du fine-tuning avancé: {e}")
            return False
    
    def get_model_statistics(self) -> Dict[str, Any]:
        """Obtenir les statistiques des modèles"""
        stats = {
            'total_models': len(self.models),
            'fine_tuned_models': sum(1 for config in self.model_configs.values() if config.get('fine_tuned', False)),
            'device': str(self.device),
            'model_configs': self.model_configs,
            'evasion_detector_loaded': True,
            'background_processor_active': self.background_thread.is_alive()
        }
        return stats
    
    async def test_evasion_detection(self, test_files: List[str]) -> Dict[str, Any]:
        """Tester la détection d'évasion"""
        results = {}
        
        for file_path in test_files:
            try:
                process_info = {'cpu_percent': 0, 'memory_percent': 0, 'connections': []}
                evasion_scores = self.evasion_detector.detect_evasion_techniques(file_path, process_info)
                
                results[file_path] = {
                    'evasion_scores': evasion_scores,
                    'total_evasion_score': sum(evasion_scores.values()) / len(evasion_scores),
                    'high_risk': any(score > 0.7 for score in evasion_scores.values())
                }
                
            except Exception as e:
                logger.error(f"Erreur lors du test d'évasion pour {file_path}: {e}")
                results[file_path] = {'error': str(e)}
        
        return results 
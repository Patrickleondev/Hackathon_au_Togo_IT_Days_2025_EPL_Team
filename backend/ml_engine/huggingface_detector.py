"""
Module de détection avec Hugging Face Transformers
RansomGuard AI - Hackathon Togo IT Days 2025
"""

import torch
from transformers import (
    AutoTokenizer, 
    AutoModelForSequenceClassification,
    AutoModelForTokenClassification,
    pipeline,
    DistilBertTokenizer,
    DistilBertForSequenceClassification
)
import numpy as np
import logging
from typing import Dict, List, Any, Optional
import os
import json
from datetime import datetime

logger = logging.getLogger(__name__)

class HuggingFaceDetector:
    """
    Détecteur de ransomware utilisant les modèles Hugging Face
    """
    
    def __init__(self):
        self.models = {}
        self.tokenizers = {}
        self.classifiers = {}
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        # Configuration des modèles
        self.model_configs = {
            'distilbert': {
                'name': 'distilbert-base-uncased',
                'type': 'sequence_classification',
                'max_length': 512,
                'threshold': 0.7
            },
            'roberta': {
                'name': 'roberta-base',
                'type': 'sequence_classification', 
                'max_length': 512,
                'threshold': 0.75
            },
            'bert': {
                'name': 'bert-base-uncased',
                'type': 'sequence_classification',
                'max_length': 512,
                'threshold': 0.8
            }
        }
        
        self._load_models()
        
    def _load_models(self):
        """Charger les modèles Hugging Face"""
        try:
            logger.info("🔄 Chargement des modèles Hugging Face...")
            
            for model_name, config in self.model_configs.items():
                try:
                    # Charger le tokenizer
                    tokenizer = AutoTokenizer.from_pretrained(config['name'])
                    self.tokenizers[model_name] = tokenizer
                    
                    # Charger le modèle
                    if config['type'] == 'sequence_classification':
                        model = AutoModelForSequenceClassification.from_pretrained(
                            config['name'],
                            num_labels=2  # Binaire: ransomware ou non
                        )
                    else:
                        model = AutoModelForTokenClassification.from_pretrained(config['name'])
                    
                    model.to(self.device)
                    model.eval()
                    self.models[model_name] = model
                    
                    # Créer le pipeline de classification
                    classifier = pipeline(
                        'text-classification',
                        model=model,
                        tokenizer=tokenizer,
                        device=0 if torch.cuda.is_available() else -1
                    )
                    self.classifiers[model_name] = classifier
                    
                    logger.info(f"✅ Modèle {model_name} chargé avec succès")
                    
                except Exception as e:
                    logger.error(f"❌ Erreur lors du chargement du modèle {model_name}: {e}")
                    continue
            
            logger.info(f"🎯 {len(self.models)} modèles chargés sur {self.device}")
            
        except Exception as e:
            logger.error(f"❌ Erreur lors du chargement des modèles: {e}")
    
    def _prepare_text_features(self, file_path: str, process_info: Dict) -> str:
        """Préparer les caractéristiques textuelles pour l'analyse"""
        features = []
        
        # Informations sur le fichier
        if os.path.exists(file_path):
            filename = os.path.basename(file_path)
            extension = os.path.splitext(file_path)[1].lower()
            size = os.path.getsize(file_path)
            
            features.extend([
                f"filename: {filename}",
                f"extension: {extension}",
                f"size: {size} bytes"
            ])
        
        # Informations sur le processus
        if process_info:
            process_name = process_info.get('process_name', 'unknown')
            cpu_usage = process_info.get('cpu_percent', 0)
            memory_usage = process_info.get('memory_percent', 0)
            
            features.extend([
                f"process: {process_name}",
                f"cpu_usage: {cpu_usage}%",
                f"memory_usage: {memory_usage}%"
            ])
        
        # Patterns suspects
        suspicious_patterns = self._detect_suspicious_patterns(file_path, process_info)
        if suspicious_patterns:
            features.extend([f"suspicious_patterns: {', '.join(suspicious_patterns)}"])
        
        return " | ".join(features)
    
    def _detect_suspicious_patterns(self, file_path: str, process_info: Dict) -> List[str]:
        """Détecter les patterns suspects"""
        patterns = []
        
        # Patterns dans le nom de fichier
        if file_path:
            filename = os.path.basename(file_path).lower()
            suspicious_keywords = [
                'encrypt', 'crypt', 'lock', 'ransom', 'wanna', 'crypto',
                'bitcoin', 'wallet', 'miner', 'cryptominer', 'decrypt',
                'pay', 'money', 'hack', 'virus', 'malware'
            ]
            
            for keyword in suspicious_keywords:
                if keyword in filename:
                    patterns.append(f"filename_contains_{keyword}")
        
        # Patterns dans le processus
        if process_info:
            process_name = process_info.get('process_name', '').lower()
            for keyword in suspicious_keywords:
                if keyword in process_name:
                    patterns.append(f"process_contains_{keyword}")
        
        return patterns
    
    async def analyze_with_huggingface(self, file_path: str, process_info: Dict) -> Dict[str, Any]:
        """Analyser avec les modèles Hugging Face"""
        try:
            # Préparer les caractéristiques textuelles
            text_features = self._prepare_text_features(file_path, process_info)
            
            results = {}
            ensemble_score = 0
            total_models = 0
            
            # Analyser avec chaque modèle
            for model_name, classifier in self.classifiers.items():
                try:
                    # Classification du texte
                    prediction = classifier(text_features)
                    
                    # Interpréter les résultats
                    if isinstance(prediction, list):
                        prediction = prediction[0]
                    
                    # Calculer le score de menace
                    if prediction['label'] == 'LABEL_1':  # Ransomware
                        threat_score = prediction['score']
                    else:  # LABEL_0 - Normal
                        threat_score = 1 - prediction['score']
                    
                    results[model_name] = {
                        'threat_score': threat_score,
                        'confidence': prediction['score'],
                        'label': prediction['label']
                    }
                    
                    ensemble_score += threat_score
                    total_models += 1
                    
                except Exception as e:
                    logger.error(f"Erreur avec le modèle {model_name}: {e}")
                    continue
            
            # Score d'ensemble
            if total_models > 0:
                ensemble_score /= total_models
            else:
                ensemble_score = 0
            
            # Décision finale
            threshold = 0.7  # Seuil configurable
            is_threat = ensemble_score > threshold
            
            return {
                'is_threat': is_threat,
                'ensemble_score': ensemble_score,
                'confidence': ensemble_score,
                'model_predictions': results,
                'text_features': text_features
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse Hugging Face: {e}")
            return {
                'is_threat': False,
                'ensemble_score': 0,
                'confidence': 0,
                'model_predictions': {},
                'text_features': '',
                'error': str(e)
            }
    
    async def analyze_file_content(self, file_path: str) -> Dict[str, Any]:
        """Analyser le contenu d'un fichier avec les modèles"""
        try:
            if not os.path.exists(file_path):
                return {'error': 'Fichier non trouvé'}
            
            # Lire le début du fichier pour l'analyse
            with open(file_path, 'rb') as f:
                content = f.read(1024)  # Premiers 1024 bytes
            
            # Convertir en texte pour l'analyse
            try:
                text_content = content.decode('utf-8', errors='ignore')
            except:
                text_content = str(content)
            
            # Analyser avec les modèles
            results = {}
            for model_name, classifier in self.classifiers.items():
                try:
                    prediction = classifier(text_content[:512])  # Limiter la longueur
                    
                    if isinstance(prediction, list):
                        prediction = prediction[0]
                    
                    threat_score = prediction['score'] if prediction['label'] == 'LABEL_1' else 1 - prediction['score']
                    
                    results[model_name] = {
                        'threat_score': threat_score,
                        'confidence': prediction['score']
                    }
                    
                except Exception as e:
                    logger.error(f"Erreur lors de l'analyse du contenu avec {model_name}: {e}")
            
            return {
                'file_analysis': results,
                'content_preview': text_content[:200] + '...' if len(text_content) > 200 else text_content
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse du contenu: {e}")
            return {'error': str(e)}
    
    async def fine_tune_model(self, training_data: List[Dict[str, Any]], model_name: str = 'distilbert'):
        """Fine-tuner un modèle avec de nouvelles données"""
        try:
            if model_name not in self.models:
                logger.error(f"Modèle {model_name} non trouvé")
                return False
            
            logger.info(f"🔄 Fine-tuning du modèle {model_name}...")
            
            # Préparer les données d'entraînement
            texts = []
            labels = []
            
            for data_point in training_data:
                text = data_point.get('text', '')
                label = 1 if data_point.get('is_threat', False) else 0
                
                texts.append(text)
                labels.append(label)
            
            # Tokeniser les données
            tokenizer = self.tokenizers[model_name]
            encodings = tokenizer(
                texts,
                truncation=True,
                padding=True,
                max_length=512,
                return_tensors='pt'
            )
            
            # Créer le dataset
            dataset = torch.utils.data.TensorDataset(
                encodings['input_ids'],
                encodings['attention_mask'],
                torch.tensor(labels)
            )
            
            # Configuration de l'entraînement
            model = self.models[model_name]
            optimizer = torch.optim.AdamW(model.parameters(), lr=2e-5)
            
            # Entraînement
            model.train()
            for epoch in range(3):  # 3 époques
                total_loss = 0
                for batch in torch.utils.data.DataLoader(dataset, batch_size=8):
                    optimizer.zero_grad()
                    
                    input_ids = batch[0].to(self.device)
                    attention_mask = batch[1].to(self.device)
                    labels = batch[2].to(self.device)
                    
                    outputs = model(
                        input_ids=input_ids,
                        attention_mask=attention_mask,
                        labels=labels
                    )
                    
                    loss = outputs.loss
                    loss.backward()
                    optimizer.step()
                    
                    total_loss += loss.item()
                
                logger.info(f"Époque {epoch+1}, Loss: {total_loss/len(dataset)}")
            
            # Sauvegarder le modèle fine-tuné
            model_path = f"models/{model_name}_fine_tuned"
            model.save_pretrained(model_path)
            tokenizer.save_pretrained(model_path)
            
            logger.info(f"✅ Modèle {model_name} fine-tuné et sauvegardé")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erreur lors du fine-tuning: {e}")
            return False
    
    def get_model_info(self) -> Dict[str, Any]:
        """Obtenir les informations sur les modèles"""
        info = {
            'loaded_models': list(self.models.keys()),
            'device': str(self.device),
            'total_models': len(self.models),
            'model_configs': self.model_configs
        }
        return info
    
    async def test_model_performance(self, test_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Tester la performance des modèles"""
        try:
            results = {}
            
            for model_name in self.models.keys():
                correct = 0
                total = 0
                
                for data_point in test_data:
                    text = data_point.get('text', '')
                    expected_label = data_point.get('is_threat', False)
                    
                    try:
                        prediction = await self.analyze_with_huggingface('', {'text': text})
                        predicted_threat = prediction.get('is_threat', False)
                        
                        if predicted_threat == expected_label:
                            correct += 1
                        total += 1
                        
                    except Exception as e:
                        logger.error(f"Erreur lors du test avec {model_name}: {e}")
                        continue
                
                if total > 0:
                    accuracy = correct / total
                    results[model_name] = {
                        'accuracy': accuracy,
                        'correct_predictions': correct,
                        'total_predictions': total
                    }
            
            return results
            
        except Exception as e:
            logger.error(f"Erreur lors du test de performance: {e}")
            return {'error': str(e)} 
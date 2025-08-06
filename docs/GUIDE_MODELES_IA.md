# 🧠 Guide Complet des Modèles IA - RansomGuard AI

## 🎯 Vue d'Ensemble des Modèles

### 📊 Système Multi-Modèles

RansomGuard AI utilise un système hybride combinant **7 modèles IA** spécialisés :

```
┌─────────────────────────────────────────────────────────────────┐
│                    SYSTÈME MULTI-MODÈLES                      │
├─────────────────────────────────────────────────────────────────┤
│  ML Traditionnel  │  NLP Hugging Face  │  Détection Évasion   │
│  ┌─────────────┐  │  ┌─────────────┐   │  ┌─────────────┐     │
│  │ Random      │  │  │ DistilBERT  │   │  │ Sandbox     │     │
│  │ Forest      │  │  │ RoBERTa     │   │  │ Évasion     │     │
│  │ SVM         │  │  │ DialoGPT    │   │  │ Antivirus   │     │
│  │ Neural      │  │  │ CodeBERT    │   │  │ Évasion     │     │
│  │ Network     │  │  │             │   │  │ Behavioral  │     │
│  └─────────────┘  │  └─────────────┘   │  └─────────────┘     │
└─────────────────────────────────────────────────────────────────┘
```

## 🤖 Modèles ML Traditionnels

### 1. **Random Forest** (`ml_engine/ransomware_detector.py`)

#### 🎯 Spécialisation
- **Type** : Ensemble Learning
- **Algorithme** : Forêt d'arbres de décision
- **Spécialisation** : Classification robuste et interprétable

#### 📊 Caractéristiques
```python
# Configuration
random_forest_config = {
    'n_estimators': 100,        # Nombre d'arbres
    'max_depth': 10,            # Profondeur maximale
    'min_samples_split': 2,     # Échantillons min pour diviser
    'min_samples_leaf': 1,      # Échantillons min par feuille
    'random_state': 42          # Reproductibilité
}

# Features utilisées
features = [
    'file_entropy',           # Entropie du fichier
    'file_size',              # Taille du fichier
    'process_count',          # Nombre de processus
    'network_connections',     # Connexions réseau
    'registry_changes',        # Modifications registre
    'file_operations',         # Opérations fichiers
    'cpu_usage',              # Utilisation CPU
    'memory_usage',           # Utilisation mémoire
    'suspicious_strings',      # Chaînes suspectes
    'encryption_indicators'    # Indicateurs chiffrement
]
```

#### 🎯 Avantages
- ✅ **Robustesse** : Résistant au surapprentissage
- ✅ **Interprétabilité** : Importance des features
- ✅ **Données manquantes** : Gestion automatique
- ✅ **Stabilité** : Peu sensible aux outliers

#### 📈 Performance Attendue
```python
expected_performance = {
    'accuracy': 0.94,
    'precision': 0.92,
    'recall': 0.93,
    'f1_score': 0.925,
    'training_time': '30s',
    'prediction_time': '0.1ms'
}
```

### 2. **Support Vector Machine (SVM)** (`ml_engine/ransomware_detector.py`)

#### 🎯 Spécialisation
- **Type** : Classification linéaire/non-linéaire
- **Algorithme** : Support Vector Machine avec noyau RBF
- **Spécialisation** : Détection de patterns complexes

#### 📊 Configuration
```python
# Configuration SVM
svm_config = {
    'kernel': 'rbf',           # Noyau Radial Basis Function
    'C': 1.0,                 # Paramètre de régularisation
    'gamma': 'scale',          # Paramètre du noyau
    'random_state': 42,        # Reproductibilité
    'probability': True        # Probabilités de prédiction
}

# Features normalisées
normalized_features = [
    'file_entropy_normalized',
    'file_size_normalized',
    'process_count_normalized',
    'network_connections_normalized',
    'registry_changes_normalized',
    'file_operations_normalized',
    'cpu_usage_normalized',
    'memory_usage_normalized',
    'suspicious_strings_normalized',
    'encryption_indicators_normalized'
]
```

#### 🎯 Avantages
- ✅ **Haute dimension** : Efficace avec beaucoup de features
- ✅ **Noyau RBF** : Capture patterns non-linéaires
- ✅ **Marge optimale** : Généralisation robuste
- ✅ **Probabilités** : Scores de confiance

#### 📈 Performance Attendue
```python
expected_performance = {
    'accuracy': 0.93,
    'precision': 0.91,
    'recall': 0.92,
    'f1_score': 0.915,
    'training_time': '45s',
    'prediction_time': '0.2ms'
}
```

### 3. **Neural Network (MLP)** (`ml_engine/ransomware_detector.py`)

#### 🎯 Spécialisation
- **Type** : Deep Learning
- **Architecture** : Multi-Layer Perceptron
- **Spécialisation** : Apprentissage de patterns complexes

#### 📊 Configuration
```python
# Configuration Neural Network
neural_network_config = {
    'hidden_layer_sizes': (100, 50),  # Couches cachées
    'activation': 'relu',              # Fonction d'activation
    'solver': 'adam',                  # Optimiseur
    'alpha': 0.0001,                  # Régularisation L2
    'learning_rate': 'adaptive',       # Taux d'apprentissage
    'max_iter': 500,                  # Époques max
    'random_state': 42                # Reproductibilité
}

# Architecture
architecture = {
    'input_layer': 10,        # 10 features d'entrée
    'hidden_layer_1': 100,    # 100 neurones
    'hidden_layer_2': 50,     # 50 neurones
    'output_layer': 1         # 1 sortie (binaire)
}
```

#### 🎯 Avantages
- ✅ **Patterns complexes** : Apprentissage non-linéaire
- ✅ **Adaptabilité** : Ajustement automatique
- ✅ **Features automatiques** : Extraction de features
- ✅ **Performance** : Optimisation continue

#### 📈 Performance Attendue
```python
expected_performance = {
    'accuracy': 0.95,
    'precision': 0.93,
    'recall': 0.94,
    'f1_score': 0.935,
    'training_time': '60s',
    'prediction_time': '0.3ms'
}
```

## 🧠 Modèles NLP Hugging Face

### 1. **DistilBERT** (`ml_engine/advanced_detector.py`)

#### 🎯 Spécialisation
- **Modèle** : `distilbert-base-uncased`
- **Type** : Transformer léger
- **Spécialisation** : Analyse de texte rapide et robuste

#### 📊 Configuration
```python
# Configuration DistilBERT
distilbert_config = {
    'model_name': 'distilbert-base-uncased',
    'max_length': 512,                # Longueur max des tokens
    'truncation': True,               # Troncature automatique
    'padding': 'max_length',          # Padding automatique
    'return_tensors': 'pt',           # Tenseurs PyTorch
    'num_labels': 2,                  # Classification binaire
    'problem_type': 'single_label_classification'
}

# Tokenisation
tokenizer_config = {
    'do_lower_case': True,            # Conversion minuscules
    'add_special_tokens': True,       # Tokens spéciaux
    'return_attention_mask': True,    # Masque d'attention
    'return_token_type_ids': False    # Pas d'IDs de type
}
```

#### 🎯 Avantages
- ✅ **Vitesse** : 60% plus rapide que BERT
- ✅ **Taille** : 40% plus petit que BERT
- ✅ **Performance** : 97% des performances de BERT
- ✅ **Robustesse** : Distillation de connaissances

#### 📈 Performance Attendue
```python
expected_performance = {
    'accuracy': 0.92,
    'precision': 0.89,
    'recall': 0.94,
    'f1_score': 0.915,
    'training_time': '15min',
    'prediction_time': '50ms'
}
```

### 2. **RoBERTa** (`ml_engine/advanced_detector.py`)

#### 🎯 Spécialisation
- **Modèle** : `roberta-base`
- **Type** : Transformer optimisé
- **Spécialisation** : Analyse de texte précise

#### 📊 Configuration
```python
# Configuration RoBERTa
roberta_config = {
    'model_name': 'roberta-base',
    'max_length': 512,                # Longueur max
    'truncation': True,               # Troncature
    'padding': 'max_length',          # Padding
    'return_tensors': 'pt',           # Tenseurs PyTorch
    'num_labels': 2,                  # Classification binaire
    'problem_type': 'single_label_classification'
}

# Optimisations
training_config = {
    'learning_rate': 2e-5,            # Taux d'apprentissage
    'warmup_steps': 500,              # Échauffement
    'weight_decay': 0.01,             # Régularisation
    'num_train_epochs': 3,            # Époques
    'per_device_train_batch_size': 8, # Taille batch
    'gradient_accumulation_steps': 4  # Accumulation gradients
}
```

#### 🎯 Avantages
- ✅ **Précision** : Meilleure que BERT original
- ✅ **Optimisation** : Entraînement optimisé
- ✅ **Robustesse** : Généralisation améliorée
- ✅ **Efficacité** : Utilisation optimale des données

#### 📈 Performance Attendue
```python
expected_performance = {
    'accuracy': 0.94,
    'precision': 0.91,
    'recall': 0.96,
    'f1_score': 0.935,
    'training_time': '25min',
    'prediction_time': '80ms'
}
```

### 3. **DialoGPT** (`ml_engine/advanced_detector.py`)

#### 🎯 Spécialisation
- **Modèle** : `microsoft/DialoGPT-medium`
- **Type** : Transformer conversationnel
- **Spécialisation** : Analyse de conversations malveillantes

#### 📊 Configuration
```python
# Configuration DialoGPT
dialogpt_config = {
    'model_name': 'microsoft/DialoGPT-medium',
    'max_length': 512,                # Longueur max
    'truncation': True,               # Troncature
    'padding': 'max_length',          # Padding
    'return_tensors': 'pt',           # Tenseurs PyTorch
    'num_labels': 2,                  # Classification binaire
    'problem_type': 'single_label_classification'
}

# Spécialisation sécurité
security_features = {
    'command_detection': True,        # Détection commandes
    'context_analysis': True,         # Analyse contexte
    'conversation_flow': True,        # Flux conversationnel
    'malicious_patterns': True        # Patterns malveillants
}
```

#### 🎯 Avantages
- ✅ **Contexte** : Compréhension conversationnelle
- ✅ **Commandes** : Détection commandes malveillantes
- ✅ **Flow** : Analyse du flux conversationnel
- ✅ **Patterns** : Reconnaissance patterns suspects

#### 📈 Performance Attendue
```python
expected_performance = {
    'accuracy': 0.93,
    'precision': 0.90,
    'recall': 0.95,
    'f1_score': 0.925,
    'training_time': '20min',
    'prediction_time': '70ms'
}
```

### 4. **CodeBERT** (`ml_engine/advanced_detector.py`)

#### 🎯 Spécialisation
- **Modèle** : `microsoft/codebert-base`
- **Type** : Transformer spécialisé code
- **Spécialisation** : Analyse de code malveillant

#### 📊 Configuration
```python
# Configuration CodeBERT
codebert_config = {
    'model_name': 'microsoft/codebert-base',
    'max_length': 512,                # Longueur max
    'truncation': True,               # Troncature
    'padding': 'max_length',          # Padding
    'return_tensors': 'pt',           # Tenseurs PyTorch
    'num_labels': 2,                  # Classification binaire
    'problem_type': 'single_label_classification'
}

# Spécialisation code
code_features = {
    'syntax_analysis': True,          # Analyse syntaxique
    'semantic_analysis': True,        # Analyse sémantique
    'malicious_patterns': True,       # Patterns malveillants
    'obfuscation_detection': True     # Détection obfuscation
}
```

#### 🎯 Avantages
- ✅ **Syntaxe** : Compréhension syntaxe code
- ✅ **Sémantique** : Analyse sémantique code
- ✅ **Malveillant** : Détection code malveillant
- ✅ **Obfuscation** : Reconnaissance code obfusqué

#### 📈 Performance Attendue
```python
expected_performance = {
    'accuracy': 0.95,
    'precision': 0.93,
    'recall': 0.96,
    'f1_score': 0.945,
    'training_time': '30min',
    'prediction_time': '90ms'
}
```

## 🛡️ Détecteur d'Évasion

### 🎯 Vue d'Ensemble

Le détecteur d'évasion analyse les techniques de contournement utilisées par les malwares :

```python
# Types d'évasion détectées
evasion_types = {
    'sandbox_evasion': {
        'description': 'Contournement environnements virtuels',
        'techniques': ['délais', 'mouvements_souris', 'vérifications_système'],
        'threshold': 0.7
    },
    'antivirus_evasion': {
        'description': 'Contournement antivirus',
        'techniques': ['packing', 'obfuscation', 'polymorphisme'],
        'threshold': 0.6
    },
    'behavioral_evasion': {
        'description': 'Actions furtives',
        'techniques': ['opérations_cachées', 'timing_suspect', 'comportement_anormal'],
        'threshold': 0.5
    }
}
```

### 1. **Sandbox Évasion**

#### 🎯 Détection
```python
def detect_sandbox_evasion():
    indicators = {
        'sleep_detected': check_sleep_calls(),
        'mouse_movement': check_mouse_activity(),
        'vm_indicators': check_vm_environment(),
        'system_checks': check_system_info(),
        'timing_anomalies': check_timing_patterns(),
        'environment_checks': check_environment_variables()
    }
    
    # Calcul du score d'évasion
    evasion_score = calculate_evasion_score(indicators)
    return {
        'evasion_type': 'sandbox',
        'score': evasion_score,
        'indicators': indicators,
        'confidence': calculate_confidence(indicators)
    }
```

#### 📊 Techniques Détectées
- **Délais d'exécution** : `Sleep()`, `WaitForSingleObject()`
- **Mouvements de souris** : `GetCursorPos()`, `SetCursorPos()`
- **Vérifications VM** : `GetSystemFirmwareTable()`, `WMI queries`
- **Timing suspect** : Patterns de délais anormaux

### 2. **Antivirus Évasion**

#### 🎯 Détection
```python
def detect_antivirus_evasion():
    indicators = {
        'packing_detected': detect_packing_techniques(),
        'obfuscation': detect_code_obfuscation(),
        'polymorphic': detect_polymorphic_behavior(),
        'code_injection': detect_code_injection(),
        'signature_evasion': detect_signature_evasion(),
        'encryption': detect_encryption_layers()
    }
    
    # Calcul du score d'évasion
    evasion_score = calculate_evasion_score(indicators)
    return {
        'evasion_type': 'antivirus',
        'score': evasion_score,
        'indicators': indicators,
        'confidence': calculate_confidence(indicators)
    }
```

#### 📊 Techniques Détectées
- **Packing** : UPX, Themida, VMProtect
- **Obfuscation** : Chaînes chiffrées, code obfusqué
- **Polymorphisme** : Code auto-modifiant
- **Injection** : DLL injection, process hollowing

### 3. **Évasion Comportementale**

#### 🎯 Détection
```python
def detect_behavioral_evasion():
    indicators = {
        'stealth_operations': detect_stealth_behavior(),
        'timing_anomalies': detect_timing_patterns(),
        'hidden_actions': detect_hidden_operations(),
        'behavior_changes': detect_behavior_changes(),
        'process_hiding': detect_process_hiding(),
        'file_hiding': detect_file_hiding()
    }
    
    # Calcul du score d'évasion
    evasion_score = calculate_evasion_score(indicators)
    return {
        'evasion_type': 'behavioral',
        'score': evasion_score,
        'indicators': indicators,
        'confidence': calculate_confidence(indicators)
    }
```

#### 📊 Techniques Détectées
- **Actions furtives** : Opérations cachées
- **Timing suspect** : Délais anormaux
- **Comportement anormal** : Patterns suspects
- **Dissimulation** : Masquage processus/fichiers

## 🔄 Combinaison des Modèles

### 🎯 Système Hybride

```python
def combine_model_results(ml_results, nlp_results, evasion_results):
    # Poids des modèles
    weights = {
        'ml_traditional': 0.3,      # 30% ML traditionnel
        'nlp_huggingface': 0.4,     # 40% NLP Hugging Face
        'evasion_detection': 0.3     # 30% Détection évasion
    }
    
    # Calcul du score hybride
    hybrid_score = (
        ml_results['confidence'] * weights['ml_traditional'] +
        nlp_results['confidence'] * weights['nlp_huggingface'] +
        evasion_results['evasion_score'] * weights['evasion_detection']
    )
    
    return {
        'hybrid_score': hybrid_score,
        'final_decision': make_final_decision(hybrid_score),
        'confidence': calculate_overall_confidence(ml_results, nlp_results, evasion_results),
        'model_contributions': {
            'ml_traditional': ml_results['confidence'],
            'nlp_huggingface': nlp_results['confidence'],
            'evasion_detection': evasion_results['evasion_score']
        }
    }
```

### 📊 Décision Finale

```python
def make_final_decision(hybrid_score):
    if hybrid_score >= 0.8:
        return 'malicious_high'
    elif hybrid_score >= 0.6:
        return 'malicious_medium'
    elif hybrid_score >= 0.4:
        return 'suspicious'
    else:
        return 'benign'
```

## 📈 Performance Globale

### 🎯 Métriques Attendues

```python
# Performance globale du système
global_performance = {
    'accuracy': 0.95,                # 95% de précision
    'precision': 0.93,               # 93% de précision
    'recall': 0.92,                  # 92% de rappel
    'f1_score': 0.93,                # 93% F1-Score
    'false_positive_rate': 0.03,     # 3% de faux positifs
    'processing_time': 2.0,          # < 2 secondes par fichier
    'throughput': 30,                # 30 fichiers/minute
    'model_loading_time': 5.0,       # 5 secondes chargement
    'memory_usage': '2GB',           # Utilisation mémoire
    'gpu_acceleration': True         # Accélération GPU si disponible
}
```

### 📊 Comparaison des Modèles

| Modèle | Précision | Rappel | F1-Score | Temps (ms) |
|--------|-----------|--------|----------|------------|
| Random Forest | 0.94 | 0.93 | 0.925 | 0.1 |
| SVM | 0.93 | 0.92 | 0.915 | 0.2 |
| Neural Network | 0.95 | 0.94 | 0.935 | 0.3 |
| DistilBERT | 0.92 | 0.94 | 0.915 | 50 |
| RoBERTa | 0.94 | 0.96 | 0.935 | 80 |
| DialoGPT | 0.93 | 0.95 | 0.925 | 70 |
| CodeBERT | 0.95 | 0.96 | 0.945 | 90 |
| **Système Hybride** | **0.95** | **0.92** | **0.93** | **200** |

## 🔧 Configuration et Optimisation

### ⚙️ Configuration des Modèles

```python
# Configuration globale
MODEL_CONFIG = {
    'hybrid_weights': {
        'ml_traditional': 0.3,
        'nlp_huggingface': 0.4,
        'evasion_detection': 0.3
    },
    'detection_thresholds': {
        'high_threat': 0.8,
        'medium_threat': 0.6,
        'low_threat': 0.4
    },
    'evasion_thresholds': {
        'sandbox_evasion': 0.7,
        'antivirus_evasion': 0.6,
        'behavioral_evasion': 0.5
    },
    'performance_optimizations': {
        'use_gpu': True,
        'batch_size': 8,
        'max_workers': 4,
        'cache_results': True
    }
}
```

### 🚀 Optimisations

#### 1. **GPU/CPU Optimisation**
```python
def optimize_hardware():
    if torch.cuda.is_available():
        device = 'cuda'
        torch.set_float32_matmul_precision('high')
        torch.backends.cudnn.benchmark = True
    else:
        device = 'cpu'
        torch.set_num_threads(4)
    return device
```

#### 2. **Cache et Mémoire**
```python
@lru_cache(maxsize=1000)
def cached_model_prediction(file_hash: str, model_name: str):
    return model.predict(file_hash)

def optimize_memory():
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
```

#### 3. **Traitement Asynchrone**
```python
async def process_file_queue():
    queue = asyncio.Queue()
    workers = [asyncio.create_task(worker(queue)) for _ in range(4)]
    return workers
```

## 🎯 Conclusion

Ce système multi-modèles offre :

- ✅ **Robustesse** : 7 modèles complémentaires
- ✅ **Performance** : Optimisation automatique GPU/CPU
- ✅ **Précision** : Combinaison intelligente des résultats
- ✅ **Spécialisation** : Chaque modèle a son domaine d'expertise
- ✅ **Évolutivité** : Ajout facile de nouveaux modèles

Le système RansomGuard AI est conçu pour être **maximalement efficace** tout en restant **compréhensible** pour tous les membres de l'équipe. 
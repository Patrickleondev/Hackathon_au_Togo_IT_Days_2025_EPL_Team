# 🏗️ Architecture Complète - RansomGuard AI

## 🎯 Vue d'Ensemble du Système

### 📋 Architecture Générale

```
┌─────────────────────────────────────────────────────────────────┐
│                    RansomGuard AI v2.0                        │
├─────────────────────────────────────────────────────────────────┤
│  Frontend (React)  │  Backend (FastAPI)  │  ML Engine (Python) │
│  ┌─────────────┐   │  ┌─────────────┐    │  ┌─────────────┐    │
│  │ Dashboard   │   │  │ API REST    │    │  │ Hybrid      │    │
│  │ Scanner     │◄──┤  │ Endpoints   │◄───┤  │ Detector    │    │
│  │ Threats     │   │  │             │    │  │             │    │
│  │ Statistics  │   │  │ Model       │    │  │ Advanced    │    │
│  │ Settings    │   │  │ Loader      │    │  │ Detector    │    │
│  └─────────────┘   │  └─────────────┘    │  └─────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### 🔄 Flux de Données

```
1. Fichier suspect → 2. API Backend → 3. ML Engine → 4. Analyse → 5. Résultat
   ↓                    ↓                ↓              ↓           ↓
Frontend ←─────────── FastAPI ←─────── Hybrid ←─────── Modèles ←─── Détection
```

## 🧠 Architecture des Modèles IA

### 📊 Système Hybride Multi-Modèles

```
┌─────────────────────────────────────────────────────────────────┐
│                    SYSTÈME HYBRIDE                             │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │   ML        │  │   NLP       │  │   Évasion   │           │
│  │ Traditionnel│  │ HuggingFace │  │  Detection  │           │
│  │             │  │             │  │             │           │
│  │ • Random    │  │ • DistilBERT│  │ • Sandbox   │           │
│  │   Forest    │  │ • RoBERTa   │  │ • Antivirus │           │
│  │ • SVM       │  │ • DialoGPT  │  │ • Behavioral│           │
│  │ • Neural    │  │ • CodeBERT  │  │             │           │
│  │   Network   │  │             │  │             │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
│         │                │                │                   │
│         └────────────────┼────────────────┘                   │
│                          │                                    │
│                    ┌─────────────┐                            │
│                    │   Hybrid    │                            │
│                    │  Detector   │                            │
│                    │             │                            │
│                    │ • Ensemble  │                            │
│                    │ • Weighting │                            │
│                    │ • Decision  │                            │
│                    └─────────────┘                            │
└─────────────────────────────────────────────────────────────────┘
```

### 🎯 Spécialisation des Modèles

#### 1. **Modèles ML Traditionnels** (`ml_engine/ransomware_detector.py`)

```python
# Random Forest - Classification robuste
- Algorithme : Ensemble de décisions
- Avantages : Résistant au surapprentissage, gère les données manquantes
- Utilisation : Classification binaire (malveillant/normal)
- Features : Entropie, taille, processus, réseau, registre

# SVM - Séparation linéaire/non-linéaire  
- Algorithme : Support Vector Machine
- Avantages : Efficace en haute dimension, noyau RBF
- Utilisation : Détection de patterns complexes
- Features : Vecteurs de caractéristiques normalisés

# Neural Network - Apprentissage profond
- Architecture : MLP (Multi-Layer Perceptron)
- Avantages : Apprentissage de patterns complexes
- Utilisation : Classification non-linéaire
- Features : Features extraites automatiquement
```

#### 2. **Modèles NLP Hugging Face** (`ml_engine/advanced_detector.py`)

```python
# DistilBERT - Robustesse et vitesse
- Modèle : distilbert-base-uncased
- Spécialisation : Analyse de texte rapide
- Avantages : Plus léger que BERT, vitesse optimisée
- Utilisation : Détection de patterns textuels malveillants

# RoBERTa - Performance et précision
- Modèle : roberta-base  
- Spécialisation : Analyse de texte précise
- Avantages : Meilleure précision que BERT
- Utilisation : Classification fine des menaces

# DialoGPT - Spécialisation sécurité
- Modèle : microsoft/DialoGPT-medium
- Spécialisation : Analyse de conversations malveillantes
- Avantages : Compréhension du contexte conversationnel
- Utilisation : Détection de commandes malveillantes

# CodeBERT - Code malveillant
- Modèle : microsoft/codebert-base
- Spécialisation : Analyse de code source
- Avantages : Compréhension de la syntaxe et sémantique
- Utilisation : Détection de code malveillant
```

#### 3. **Détecteur d'Évasion** (`ml_engine/advanced_detector.py`)

```python
# Sandbox Évasion
- Détection : Environnements virtuels, VMs
- Techniques : Délais, mouvements de souris, vérifications système
- Score : 0.0-1.0 (probabilité d'évasion)

# Antivirus Évasion  
- Détection : Techniques de contournement
- Techniques : Packing, obfuscation, polymorphisme
- Score : 0.0-1.0 (probabilité d'évasion)

# Évasion Comportementale
- Détection : Actions furtives
- Techniques : Opérations cachées, timing
- Score : 0.0-1.0 (probabilité d'évasion)
```

## 🔧 Architecture Technique

### 📁 Structure des Fichiers

```
backend/
├── main.py                          # Point d'entrée API
├── start_hackathon.py               # Démarrage automatique
├── train_models_for_hackathon.py    # Entraînement unifié
├── ml_engine/                       # Moteurs IA
│   ├── hybrid_detector.py          # Orchestrateur principal
│   ├── advanced_detector.py        # Détection avancée
│   ├── ransomware_detector.py      # ML traditionnel
│   ├── huggingface_detector.py     # NLP Hugging Face
│   ├── model_loader.py             # Chargement des modèles
│   └── system_monitor.py           # Monitoring système
├── models/                          # Modèles entraînés
│   ├── frontend_unified_model.pkl  # Modèle principal
│   ├── random_forest_model.pkl     # Random Forest
│   ├── svm_model.pkl              # SVM
│   ├── neural_network_model.pkl   # Neural Network
│   ├── distilbert_hackathon/      # DistilBERT
│   ├── roberta_hackathon/         # RoBERTa
│   ├── dialogpt_hackathon/        # DialoGPT
│   └── codebert_hackathon/        # CodeBERT
├── test_suite/                      # Tests complets
│   ├── test_advanced_detection.py  # Tests multi-fichiers
│   ├── test_single_executable.py   # Test fichier unique
│   ├── test_naming_evasion.py      # Tests d'évasion
│   └── test_file_types.py          # Tests types trompeurs
└── utils/                          # Utilitaires
    └── config.py                   # Configuration
```

### 🔄 Flux de Traitement

#### 1. **Réception d'un Fichier**

```python
# 1. Upload via Frontend
POST /api/analyze/file
{
    "file": <binary_data>,
    "filename": "suspicious.exe"
}

# 2. Traitement Backend
def analyze_file(file_path: str):
    # Extraction des features
    features = extract_features(file_path)
    
    # Analyse par tous les modèles
    results = hybrid_detector.analyze_file_hybrid(file_path, features)
    
    # Retour du résultat
    return results
```

#### 2. **Extraction des Features**

```python
def extract_features(file_path: str) -> Dict[str, Any]:
    return {
        # Features ML traditionnel
        'file_entropy': calculate_entropy(file_path),
        'file_size': get_file_size(file_path),
        'process_count': count_processes(),
        'network_connections': count_network_connections(),
        'registry_changes': count_registry_changes(),
        'file_operations': count_file_operations(),
        'cpu_usage': get_cpu_usage(),
        'memory_usage': get_memory_usage(),
        'suspicious_strings': extract_suspicious_strings(file_path),
        'encryption_indicators': detect_encryption(file_path),
        
        # Features NLP
        'text_content': extract_text_content(file_path),
        'code_content': extract_code_content(file_path),
        'strings': extract_strings(file_path),
        
        # Features d'évasion
        'sandbox_indicators': detect_sandbox_evasion(),
        'antivirus_indicators': detect_antivirus_evasion(),
        'behavioral_indicators': detect_behavioral_evasion()
    }
```

#### 3. **Analyse Multi-Modèles**

```python
def analyze_file_hybrid(file_path: str, features: Dict) -> Dict[str, Any]:
    results = {}
    
    # 1. Analyse ML traditionnel
    ml_results = traditional_detector.analyze(features)
    results['ml_detection'] = ml_results
    
    # 2. Analyse NLP
    nlp_results = huggingface_detector.analyze(features['text_content'])
    results['nlp_detection'] = nlp_results
    
    # 3. Analyse d'évasion
    evasion_results = advanced_detector.analyze_evasion(features)
    results['evasion_detection'] = evasion_results
    
    # 4. Combinaison hybride
    hybrid_score = combine_results(ml_results, nlp_results, evasion_results)
    results['hybrid_score'] = hybrid_score
    
    # 5. Décision finale
    final_decision = make_final_decision(hybrid_score)
    results['final_decision'] = final_decision
    
    return results
```

#### 4. **Combinaison des Résultats**

```python
def combine_results(ml_results, nlp_results, evasion_results):
    # Poids des modèles
    weights = {
        'ml_traditional': 0.3,
        'nlp_huggingface': 0.4,
        'evasion_detection': 0.3
    }
    
    # Score pondéré
    hybrid_score = (
        ml_results['confidence'] * weights['ml_traditional'] +
        nlp_results['confidence'] * weights['nlp_huggingface'] +
        evasion_results['evasion_score'] * weights['evasion_detection']
    )
    
    return hybrid_score
```

## 🎯 Détection Spécialisée

### 🛡️ Types de Menaces Détectées

#### 1. **Ransomware**
```python
# Patterns détectés
- Chiffrement de fichiers
- Demande de rançon
- Modification d'extensions
- Communication réseau suspecte
- Opérations de registre

# Modèles utilisés
- Random Forest : Patterns de comportement
- DistilBERT : Analyse de ransom notes
- CodeBERT : Code de chiffrement
```

#### 2. **Spyware**
```python
# Patterns détectés
- Surveillance de frappe
- Capture d'écran
- Enregistrement audio
- Vol de données
- Communication furtive

# Modèles utilisés
- SVM : Patterns de surveillance
- RoBERTa : Analyse de logs
- DialoGPT : Commandes suspectes
```

#### 3. **Trojans**
```python
# Patterns détectés
- Déguisement en logiciel légitime
- Installation silencieuse
- Backdoor réseau
- Contrôle à distance

# Modèles utilisés
- Neural Network : Patterns complexes
- CodeBERT : Code malveillant
- Advanced Detector : Évasion
```

### 🎭 Techniques d'Évasion Détectées

#### 1. **Sandbox Évasion**
```python
# Techniques détectées
- Délais d'exécution
- Mouvements de souris
- Vérifications d'environnement
- Détection de VM

# Détection
def detect_sandbox_evasion():
    indicators = {
        'sleep_detected': check_sleep_calls(),
        'mouse_movement': check_mouse_activity(),
        'vm_indicators': check_vm_environment(),
        'system_checks': check_system_info()
    }
    return calculate_evasion_score(indicators)
```

#### 2. **Antivirus Évasion**
```python
# Techniques détectées
- Packing/obfuscation
- Polymorphisme
- Métamorphisme
- Injection de code

# Détection
def detect_antivirus_evasion():
    indicators = {
        'packing_detected': detect_packing(),
        'obfuscation': detect_obfuscation(),
        'polymorphic': detect_polymorphism(),
        'code_injection': detect_injection()
    }
    return calculate_evasion_score(indicators)
```

#### 3. **Évasion Comportementale**
```python
# Techniques détectées
- Actions furtives
- Timing suspect
- Opérations cachées
- Comportement anormal

# Détection
def detect_behavioral_evasion():
    indicators = {
        'stealth_operations': detect_stealth(),
        'timing_anomalies': detect_timing(),
        'hidden_actions': detect_hidden_ops(),
        'behavior_changes': detect_behavior_changes()
    }
    return calculate_evasion_score(indicators)
```

## 📊 Performance et Métriques

### 🎯 Métriques de Performance

```python
# Métriques attendues
performance_metrics = {
    'accuracy': 0.95,        # 95% de précision
    'precision': 0.93,       # 93% de précision
    'recall': 0.92,          # 92% de rappel
    'f1_score': 0.93,        # 93% F1-Score
    'false_positive_rate': 0.03,  # 3% de faux positifs
    'processing_time': 2.0,   # < 2 secondes par fichier
    'throughput': 30          # 30 fichiers/minute
}
```

### 📈 Optimisations

#### 1. **Optimisations GPU/CPU**
```python
# Configuration automatique
def optimize_hardware():
    if torch.cuda.is_available():
        device = 'cuda'
        torch.set_float32_matmul_precision('high')
    else:
        device = 'cpu'
        torch.set_num_threads(4)
    return device
```

#### 2. **Cache et Mémoire**
```python
# Cache des résultats
@lru_cache(maxsize=1000)
def cached_analysis(file_hash: str):
    return analyze_file(file_hash)

# Gestion mémoire
def optimize_memory():
    gc.collect()
    torch.cuda.empty_cache() if torch.cuda.is_available() else None
```

#### 3. **Traitement Asynchrone**
```python
# Queue de traitement
async def process_file_queue():
    queue = asyncio.Queue()
    workers = [asyncio.create_task(worker(queue)) for _ in range(4)]
    return workers
```

## 🔧 Configuration et Déploiement

### ⚙️ Configuration des Modèles

```python
# backend/utils/config.py
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
    }
}
```

### 🚀 Déploiement

#### 1. **Environnement de Développement**
```bash
# Installation
pip install -r requirements.txt
python train_models_for_hackathon.py
python main.py
```

#### 2. **Environnement de Production**
```bash
# Docker
docker build -t ransomguard-ai .
docker run -p 8000:8000 ransomguard-ai

# Kubernetes
kubectl apply -f k8s/
```

#### 3. **Monitoring**
```python
# Métriques système
def monitor_system():
    return {
        'cpu_usage': psutil.cpu_percent(),
        'memory_usage': psutil.virtual_memory().percent,
        'disk_usage': psutil.disk_usage('/').percent,
        'network_io': psutil.net_io_counters(),
        'active_connections': len(psutil.net_connections())
    }
```

## 🔍 Tests et Validation

### 🧪 Suite de Tests

#### 1. **Tests Unitaires**
```python
# Test des modèles individuels
def test_random_forest():
    model = load_model('random_forest_model.pkl')
    result = model.predict(test_features)
    assert result.shape == (len(test_features),)

def test_huggingface_models():
    for model_name in ['distilbert', 'roberta', 'dialogpt', 'codebert']:
        model = load_huggingface_model(model_name)
        result = model.predict(test_texts)
        assert result.shape == (len(test_texts), 2)
```

#### 2. **Tests d'Intégration**
```python
# Test du système hybride
def test_hybrid_system():
    detector = HybridDetector()
    result = detector.analyze_file_hybrid(test_file)
    assert 'hybrid_score' in result
    assert 'final_decision' in result
    assert 0 <= result['hybrid_score'] <= 1
```

#### 3. **Tests de Performance**
```python
# Test de performance
def test_performance():
    start_time = time.time()
    for file in test_files:
        result = hybrid_detector.analyze_file_hybrid(file)
    end_time = time.time()
    
    avg_time = (end_time - start_time) / len(test_files)
    assert avg_time < 2.0  # < 2 secondes par fichier
```

## 📚 Documentation API

### 🔗 Endpoints Principaux

#### 1. **Analyse de Fichiers**
```python
POST /api/analyze/file
{
    "file": <binary_data>,
    "filename": "suspicious.exe"
}

Response:
{
    "success": true,
    "analysis": {
        "hybrid_score": 0.85,
        "final_decision": "malicious",
        "confidence": 0.92,
        "threat_type": "ransomware",
        "evasion_techniques": ["sandbox_evasion", "antivirus_evasion"],
        "ml_detection": {...},
        "nlp_detection": {...},
        "evasion_detection": {...}
    }
}
```

#### 2. **Statut des Modèles**
```python
GET /api/models/status

Response:
{
    "models_loaded": true,
    "models_available": ["random_forest", "svm", "neural_network", "distilbert", "roberta", "dialogpt", "codebert"],
    "hybrid_detector": {
        "status": "active",
        "version": "2.0.0",
        "performance": {...}
    },
    "fallback_mode": false
}
```

#### 3. **Scan du Système**
```python
POST /api/scan
{
    "scan_type": "full",
    "target_paths": ["C:\\Users\\Documents"]
}

Response:
{
    "scan_id": "scan_12345",
    "status": "running",
    "progress": 45,
    "threats_detected": 3,
    "files_scanned": 1250
}
```

## 🎯 Conclusion

Cette architecture hybride multi-modèles offre :

- ✅ **Robustesse** : Ensemble de modèles complémentaires
- ✅ **Performance** : Optimisation GPU/CPU automatique  
- ✅ **Précision** : Combinaison intelligente des résultats
- ✅ **Évolutivité** : Ajout facile de nouveaux modèles
- ✅ **Maintenabilité** : Code modulaire et documenté

Le système RansomGuard AI est conçu pour être à la fois **performant** et **compréhensible**, permettant à tous les membres de l'équipe de contribuer efficacement au projet. 
# 🎯 Diagramme d'Architecture - RansomGuard AI

## 📊 **FLUX COMPLET DE DÉTECTION**

```
┌─────────────────────────────────────────────────────────────────┐
│                    FRONTEND (React/TypeScript)                  │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │   Upload File   │  │  Detection      │  │   Results       │  │
│  │   Interface     │  │  Avancée        │  │   Display       │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    API GATEWAY (FastAPI)                        │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │  /api/analyze/  │  │  /api/scan/     │  │  /api/status/   │  │
│  │  file/ultra     │  │  system         │  │  monitoring     │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ULTRA DETECTOR ENGINE                        │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                    FILE TYPE DETECTION                      │ │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │ │
│  │  │   Binary    │ │   Script    │ │   Source    │           │ │
│  │  │  (.exe/.dll)│ │  (.py/.js)  │ │  (.c/.cpp)  │           │ │
│  │  └─────────────┘ └─────────────┘ └─────────────┘           │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                                │                                │
│                                ▼                                │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                    ANALYSIS PIPELINE                        │ │
│  │                                                                 │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │ │
│  │  │   Pattern   │ │  Obfuscation│ │   Strings   │           │ │
│  │  │  Detection  │ │  Detection  │ │  Analysis   │           │ │
│  │  └─────────────┘ └─────────────┘ └─────────────┘           │ │
│  │                                                                 │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │ │
│  │  │   Entropy   │ │   Encoding  │ │  Behavior   │           │ │
│  │  │  Analysis   │ │  Detection  │ │  Analysis   │           │ │
│  │  └─────────────┘ └─────────────┘ └─────────────┘           │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    NLP MODELS INTEGRATION                       │
│                                                                  │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐               │
│  │ DistilBERT  │ │   RoBERTa   │ │  CodeBERT   │               │
│  │ Ransomware  │ │   Malware   │ │   Analysis  │               │
│  │ Detection   │ │  Detection  │ │   Engine    │               │
│  └─────────────┘ └─────────────┘ └─────────────┘               │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                    MODEL LOADER                             │ │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │ │
│  │  │   Load      │ │   Cache     │ │   Fallback  │           │ │
│  │  │  Models     │ │  Results    │ │   Models    │           │ │
│  │  └─────────────┘ └─────────────┘ └─────────────┘           │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    SCORE CALCULATION                            │
│                                                                  │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐               │
│  │   Pattern   │ │ Obfuscation │ │   Strings   │               │
│  │   Score     │ │   Score     │ │   Score     │               │ │
│  │   (40%)     │ │   (25%)     │ │   (15%)     │               │ │
│  └─────────────┘ └─────────────┘ └─────────────┘               │ │
│                                                                  │ │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐               │ │
│  │   Encoding  │ │   NLP       │ │   Final     │               │ │
│  │   Score     │ │   Score     │ │   Score     │               │ │
│  │   (20%)     │ │   (Bonus)   │ │   (100%)    │               │ │
│  └─────────────┘ └─────────────┘ └─────────────┘               │ │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    THREAT CLASSIFICATION                        │
│                                                                  │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ │
│  │   Critical  │ │    High     │ │   Medium    │ │     Low     │ │
│  │   (≥0.9)    │ │   (≥0.75)   │ │   (≥0.5)    │ │    (<0.5)   │ │
│  │             │ │             │ │             │ │             │ │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    RESPONSE GENERATION                          │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                    JSON RESPONSE                            │ │
│  │  {                                                          │ │
│  │    "file_name": "ircbot",                                   │ │
│  │    "is_threat": true,                                       │ │
│  │    "confidence": 1.0,                                       │ │
│  │    "threat_type": "suspicious_executable",                  │ │
│  │    "severity": "critical",                                  │ │
│  │    "pattern_analysis": {                                    │ │
│  │      "malicious_patterns": 10,                              │ │
│  │      "detected_patterns": ["socket", "connect"]             │ │
│  │    },                                                       │ │
│  │    "detected_strings": ["NICK ircbot", "JOIN #bots"]        │ │
│  │  }                                                          │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## 🔍 **DÉTAIL DES COMPOSANTS**

### **1. FILE TYPE DETECTION**
```
┌─────────────────────────────────────────────────────────────┐
│                    FILE TYPE DETECTION                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   HEADERS   │  │  EXTENSION  │  │  ENTROPY    │         │
│  │   ANALYSIS  │  │  ANALYSIS   │  │  ANALYSIS   │         │
│  │             │  │             │  │             │         │
│  │ • MZ (PE)   │  │ • .exe/.dll │  │ • >6.0 =    │         │
│  │ • ELF       │  │ • .py/.js   │  │   Binary    │         │
│  │ • MACHO     │  │ • .c/.cpp   │  │ • <6.0 =    │         │
│  │             │  │             │  │   Script    │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### **2. PATTERN DETECTION**
```
┌─────────────────────────────────────────────────────────────┐
│                    PATTERN DETECTION                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   PYTHON    │  │ JAVASCRIPT  │  │     C/C++   │         │
│  │  PATTERNS   │  │  PATTERNS   │  │  PATTERNS   │         │
│  │             │  │             │  │             │         │
│  │ • exec()    │  │ • eval()    │  │ • system()  │         │
│  │ • eval()    │  │ • Function()│  │ • exec()    │         │
│  │ • os.system │  │ • atob()    │  │ • CreateProcess│      │
│  │ • base64    │  │ • innerHTML │  │ • VirtualAlloc│       │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### **3. NLP MODELS INTEGRATION**
```
┌─────────────────────────────────────────────────────────────┐
│                    NLP MODELS INTEGRATION                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │ DistilBERT  │  │   RoBERTa   │  │  CodeBERT   │         │
│  │ Ransomware  │  │   Malware   │  │   Analysis  │         │
│  │ Detection   │  │  Detection  │  │   Engine    │         │
│  │             │  │             │  │             │         │
│  │ • Fast      │  │ • Accurate  │  │ • Code      │         │
│  │ • Lightweight│  │ • Robust    │  │   Specific  │         │
│  │ • General   │  │ • Malware   │  │ • Syntax    │         │
│  │   Purpose   │  │   Focused   │  │   Aware     │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## 🎯 **AVANTAGES DE L'ARCHITECTURE**

### **1. Multi-Couches**
- ✅ **Détection traditionnelle** : Patterns, signatures, heuristiques
- ✅ **IA/ML** : Modèles scikit-learn, Random Forest, SVM
- ✅ **NLP avancé** : DistilBERT, RoBERTa, CodeBERT
- ✅ **Analyse comportementale** : Obfuscation, encodage, entropie

### **2. Adaptative**
- ✅ **Seuils dynamiques** : Ajustement selon le contexte
- ✅ **Poids configurables** : Importance relative des méthodes
- ✅ **Cache intelligent** : Réutilisation des résultats

### **3. Extensible**
- ✅ **Nouveaux modèles** : Ajout facile de modèles NLP
- ✅ **Nouveaux patterns** : Patterns par langage
- ✅ **Nouvelles méthodes** : Intégration de nouvelles techniques

## 🚀 **INTÉGRATION DES MODÈLES NLP**

### **Structure des Modèles**
```
models/
├── distilbert_ransomware/
│   ├── config.json
│   ├── pytorch_model.bin
│   └── tokenizer.json
├── roberta_malware/
│   ├── config.json
│   ├── pytorch_model.bin
│   └── tokenizer.json
├── codebert_analysis/
│   ├── config.json
│   ├── pytorch_model.bin
│   └── tokenizer.json
└── ultra_classifier.pkl
```

### **Chargement Dynamique**
```python
# Dans ultra_detector.py
def _load_ml_models(self):
    try:
        # Charger les modèles NLP
        if os.path.exists('models/distilbert_ransomware/'):
            self.nlp_models['distilbert'] = AutoModelForSequenceClassification.from_pretrained(
                'models/distilbert_ransomware/'
            )
            self.nlp_tokenizers['distilbert'] = AutoTokenizer.from_pretrained(
                'models/distilbert_ransomware/'
            )
        
        # Charger le classifieur ultra
        if os.path.exists('models/ultra_classifier.pkl'):
            self.models['ultra'] = joblib.load('models/ultra_classifier.pkl')
            
    except Exception as e:
        logger.warning(f"⚠️ Modèles ML non disponibles: {e}")
```

Cette architecture permet une détection **ultra-puissante** et **adaptative** qui s'améliore avec l'ajout de nouveaux modèles NLP !

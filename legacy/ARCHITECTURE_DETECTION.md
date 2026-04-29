# 🎯 Architecture de Détection - RansomGuard AI

## 📊 **FLUX COMPLET D'ANALYSE**

### **1. ENTRÉE - API Endpoint**
```
POST /api/analyze/file/ultra
├── Fichier uploadé (IRCBot, malware, etc.)
├── Métadonnées (nom, taille, type)
└── Paramètres d'analyse
```

### **2. DÉTECTION DU TYPE DE FICHIER**
```python
def _detect_file_type(file_path):
    # 1. Analyse de l'extension (.exe, .py, .js, etc.)
    # 2. Lecture des headers (MZ, ELF, PE, etc.)
    # 3. Calcul d'entropie pour détecter l'obfuscation
    # 4. Classification binaire vs script
```

**Types supportés :**
- ✅ **Binaires** : .exe, .dll, .elf, .macho
- ✅ **Scripts** : .py, .js, .bat, .sh, .ps1
- ✅ **Code source** : .c, .cpp, .java, .go
- ✅ **Obfusqués** : Détection par entropie

### **3. ANALYSE SPÉCIFIQUE PAR TYPE**

#### **A. BINAIRES (ELF, PE, MACHO)**
```python
async def _analyze_binary_ultra(file_path, file_type):
    # 1. Extraction de strings avancée
    strings = self._extract_strings_advanced(file_path)
    
    # 2. Analyse des patterns suspects
    patterns = self._analyze_binary_patterns_advanced(strings, file_type)
    
    # 3. Détection de packers/obfuscation
    packer_detection = self._detect_binary_obfuscation_advanced(file_path, file_type)
    
    # 4. Analyse des sections suspectes
    sections = self._analyze_suspicious_sections(file_path, file_type)
    
    # 5. Détection de comportements malveillants
    behavior = self._analyze_malicious_behavior(strings, file_type)
```

#### **B. SCRIPTS (Python, JavaScript, Batch, etc.)**
```python
async def _analyze_script_ultra(file_path, file_type):
    # 1. Lecture complète du contenu
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    # 2. Analyse des patterns malveillants
    patterns = self._analyze_malware_patterns(content, file_type['language'])
    
    # 3. Analyse de l'obfuscation
    obfuscation = self._analyze_script_obfuscation(content)
    
    # 4. Détection de code encodé
    encoded = self._detect_encoded_code(content)
```

### **4. INTÉGRATION DES MODÈLES NLP**

#### **A. Chargement des Modèles**
```python
class ModelLoader:
    def load_models(self):
        # 1. Vérifier le dossier models/
        # 2. Charger les modèles pré-entraînés
        # 3. Fallback vers des modèles de base
        
        models = {
            'distilbert': 'models/distilbert_ransomware/',
            'roberta': 'models/roberta_malware/',
            'codebert': 'models/codebert_analysis/',
            'ultra_classifier': 'models/ultra_classifier.pkl'
        }
```

#### **B. Analyse NLP**
```python
class HuggingFaceDetector:
    async def analyze_file_nlp(self, file_path):
        # 1. Tokenisation du contenu
        tokens = self.tokenizer(content, truncation=True, padding=True)
        
        # 2. Prédiction avec DistilBERT
        distilbert_result = self.distilbert_model(**tokens)
        
        # 3. Prédiction avec RoBERTa
        roberta_result = self.roberta_model(**tokens)
        
        # 4. Prédiction avec CodeBERT
        codebert_result = self.codebert_model(**tokens)
        
        # 5. Fusion des résultats
        final_score = self._combine_nlp_predictions([
            distilbert_result, roberta_result, codebert_result
        ])
```

### **5. DÉTECTION DE PATTERNS MALVEILLANTS**

#### **A. Patterns par Langage**
```python
malware_patterns = {
    'python': [
        r'exec\s*\(', r'eval\s*\(', r'__import__\s*\(',
        r'subprocess\.call', r'os\.system', r'os\.popen',
        r'base64\.b64decode', r'urllib\.urlopen'
    ],
    'javascript': [
        r'eval\s*\(', r'Function\s*\(', r'setTimeout\s*\(',
        r'document\.write', r'innerHTML\s*=', r'atob\s*\('
    ],
    'c_cpp': [
        r'system\s*\(', r'exec\s*\(', r'popen\s*\(',
        r'CreateProcess', r'ShellExecute', r'VirtualAlloc'
    ],
    'batch': [
        r'del\s+/s', r'format\s+', r'net\s+user',
        r'schtasks', r'reg\s+add', r'reg\s+delete'
    ]
}
```

#### **B. Détection d'Obfuscation**
```python
def _analyze_script_obfuscation(content):
    indicators = []
    
    # Base64 encodé
    if re.findall(r'[A-Za-z0-9+/]{50,}={0,2}', content):
        indicators.append('long_base64_strings')
    
    # Code hexadécimal
    if re.findall(r'\\x[0-9a-fA-F]{2}', content):
        indicators.append('hex_encoded_strings')
    
    # Variables suspectes
    if re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*[\'"][^\'"]{20,}[\'"]', content):
        indicators.append('suspicious_variables')
    
    # Évaluation dynamique
    if re.findall(r'eval\s*\(|exec\s*\(|compile\s*\(', content):
        indicators.append('dynamic_evaluation')
```

### **6. CALCUL DU SCORE FINAL**

#### **A. Score Ultra-Puissant**
```python
def _calculate_ultra_score(result):
    score = 0.0
    
    # Patterns malveillants (40%)
    patterns_score = len(result.get('patterns_analysis', {}).get('found_patterns', [])) * 0.1
    score += min(patterns_score, 0.4)
    
    # Obfuscation (25%)
    obfuscation_score = len(result.get('obfuscation_analysis', {}).get('indicators', [])) * 0.05
    score += min(obfuscation_score, 0.25)
    
    # Code encodé (20%)
    encoded_score = len(result.get('encoded_analysis', {}).get('indicators', [])) * 0.05
    score += min(encoded_score, 0.2)
    
    # Strings suspectes (15%)
    strings_score = len(result.get('strings_analysis', {}).get('suspicious_strings', [])) * 0.01
    score += min(strings_score, 0.15)
    
    return min(score, 1.0)
```

#### **B. Seuils de Détection**
```python
def _determine_severity(score):
    if score >= 0.9:
        return 'critical'
    elif score >= 0.75:
        return 'high'
    elif score >= 0.5:
        return 'medium'
    else:
        return 'low'
```

### **7. INTÉGRATION AVEC LES MODÈLES NLP**

#### **A. Structure des Modèles**
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

#### **B. Chargement Dynamique**
```python
class UltraDetector:
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

### **8. RÉPONSE FINALE**

#### **A. Format de Réponse**
```python
response = {
    "file_name": "ircbot",
    "file_size": 17256,
    "is_threat": True,
    "confidence": 1.0,
    "threat_type": "suspicious_executable",
    "severity": "critical",
    "details": "Type: suspicious_executable\nLangage: elf\nScore final: 1.00\nPatterns malveillants trouvés: 10",
    "recommendations": [
        "Fichier analysé avec le détecteur ultra-puissant",
        "Analyse multi-couches effectuée",
        "Détection d'obfuscation et de patterns malveillants"
    ],
    "analysis_method": "ultra_powerful",
    "timestamp": "2025-08-08T18:53:10.058414",
    "pattern_analysis": {
        "malicious_patterns": 10,
        "encryption_patterns": 0,
        "detected_patterns": ["socket: 1 matches", "connect: 1 matches"],
        "total_patterns": 10,
        "risk_score": 1.0
    },
    "detected_strings": [
        "NICK ircbot_0000",
        "USER ircbot 0 * :ircbot",
        "JOIN #bots",
        "PRIVMSG #bots :@exec"
    ],
    "threat_family": "Generic Malware"
}
```

## 🎯 **AVANTAGES DE CETTE ARCHITECTURE**

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

### **Étapes pour Intégrer les Modèles**

1. **Placer les modèles dans `models/`**
2. **Modifier `model_loader.py`** pour charger les nouveaux modèles
3. **Adapter `ultra_detector.py`** pour utiliser les modèles NLP
4. **Tester l'intégration** avec des fichiers malveillants

### **Exemple d'Intégration**
```python
# Dans ultra_detector.py
async def _analyze_with_nlp(self, content: str) -> Dict[str, Any]:
    results = {}
    
    # DistilBERT pour la classification générale
    if 'distilbert' in self.nlp_models:
        distilbert_result = await self._analyze_with_distilbert(content)
        results['distilbert'] = distilbert_result
    
    # RoBERTa pour l'analyse de malware
    if 'roberta' in self.nlp_models:
        roberta_result = await self._analyze_with_roberta(content)
        results['roberta'] = roberta_result
    
    # CodeBERT pour l'analyse de code
    if 'codebert' in self.nlp_models:
        codebert_result = await self._analyze_with_codebert(content)
        results['codebert'] = codebert_result
    
    return results
```

Cette architecture permet une détection **ultra-puissante** et **adaptative** qui s'améliore avec l'ajout de nouveaux modèles NLP !

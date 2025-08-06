# Suite de Tests - RansomGuard AI

## 📁 Structure du Dossier

```
test_suite/
├── README.md                    # Ce fichier
├── test_advanced_detection.py   # Tests complets multi-fichiers
├── test_single_executable.py    # Test d'un seul fichier
├── test_evasion_techniques.py   # Tests spécifiques d'évasion
├── test_file_types.py           # Tests des types de fichiers trompeurs
├── test_naming_evasion.py       # Tests des noms d'évasion
├── test_hybrid_system.py        # Tests du système hybride
├── test_performance.py          # Tests de performance
├── samples/                     # Échantillons de test
│   ├── legitimate/             # Fichiers légitimes
│   ├── malicious/              # Fichiers malveillants
│   └── evasion/                # Fichiers avec techniques d'évasion
└── results/                    # Résultats des tests
    ├── json/                   # Résultats JSON
    ├── reports/                # Rapports détaillés
    └── logs/                   # Logs de test
```

## 🎯 Types de Tests

### 1. **Tests d'Évasion par Nom**
- Fichiers avec noms légitimes mais malveillants
- Extensions trompeuses (.pdf.exe, .docx.exe)
- Noms d'évasion courants (bible.exe, netflix_gratuit.exe)

### 2. **Tests de Types de Fichiers**
- Exécutables déguisés en documents
- Scripts malveillants dans des archives
- Fichiers avec double extensions

### 3. **Tests de Techniques d'Évasion**
- Sandbox évasion
- Antivirus évasion  
- Évasion comportementale

### 4. **Tests de Performance**
- Temps de traitement
- Utilisation mémoire
- Précision de détection

## 🚀 Utilisation Rapide

```bash
# Test d'un fichier unique
python test_single_executable.py "chemin/vers/fichier.exe"

# Test complet multi-fichiers
python test_advanced_detection.py

# Test spécifique d'évasion
python test_evasion_techniques.py

# Test des types de fichiers trompeurs
python test_file_types.py
```

## 📊 Métriques de Test

- **Taux de détection** : % de menaces détectées
- **Taux de faux positifs** : % d'erreurs
- **Temps de traitement** : secondes par fichier
- **Détection d'évasion** : % de techniques détectées
- **Précision globale** : Score F1

## 🔒 Sécurité

⚠️ **IMPORTANT** : Utilisez toujours une machine virtuelle pour les tests !

- Isoler les fichiers de test
- Désactiver l'exécution automatique
- Sauvegarder les données importantes
- Nettoyer après les tests 
#  RansomGuard AI - Système de Détection de Ransomware

##  Hackathon Togo IT Days 2025

Système de détection de ransomware intelligent utilisant l'IA avancée.
##  Installation Rapide

### Prérequis

- **Python 3.12**
- **Node.js** (pour le frontend)
- **Git**

### Installation

```bash
# 1. Cloner le projet
git clone https://github.com/Patrickleondev/Hackathon_au_Togo_IT_Days_2025_EPL_Team.git
cd "Hackathon_au_Togo_IT_Days_2025_EPL_Team"

# 2. Installer les dépendances backend
cd backend
pip install -r requirements.txt

# 3. Installer les dépendances frontend
cd ../frontend
npm install

# 4. Retourner au dossier backend
cd ../backend
```

##  Démarrage Automatique

### Option 1: Démarrage Unifié (Recommandé)

```bash
# Dans le dossier backend
python start_hackathon.py
```

Ce script va automatiquement :
-  Vérifier les dépendances
-  Entraîner les modèles IA
-  Démarrer le backend (port 8000)
-  Démarrer le frontend (port 3000)

### Option 2: Démarrage Manuel

```bash
# 1. Entraîner les modèles
python train_models_for_hackathon.py

# 2. Démarrer le backend
python main.py

# 3. Démarrer le frontend (dans un autre terminal)
cd ../frontend
npm start
```

##  Structure des Modèles

Les modèles sont sauvegardés dans le dossier `backend/models/` :

```
backend/models/
├── frontend_unified_model.pkl     # Modèle principal pour le frontend
├── unified_model_metadata.json    # Métadonnées des modèles
├── random_forest_model.pkl        # Modèle Random Forest
├── svm_model.pkl                 # Modèle SVM
├── neural_network_model.pkl       # Modèle Neural Network
├── distilbert_hackathon/         # Modèle DistilBERT (Hugging Face)
├── roberta_hackathon/            # Modèle RoBERTa (Hugging Face)
├── dialogpt_hackathon/           # Modèle DialoGPT (Hugging Face)
└── codebert_hackathon/           # Modèle CodeBERT (Hugging Face)
```

##  Modèles IA Utilisés

### 1. **Modèles Hugging Face**
- **DistilBERT** : Robustesse et vitesse
- **RoBERTa** : Performance et précision
- **DialoGPT** : Spécialisation sécurité
- **CodeBERT** : Code malveillant

### 2. **Modèles ML Traditionnels**
- **Random Forest** : Classification robuste
- **SVM** : Séparation linéaire/non-linéaire
- **Neural Network** : Apprentissage profond

### 3. **Détecteur d'Évasion**
- **Sandbox évasion** : Détection d'environnements virtuels
- **Antivirus évasion** : Techniques de contournement
- **Évasion comportementale** : Actions suspectes

##  Accès au Système

### Backend API
- **URL** : http://localhost:8000
- **Documentation** : http://localhost:8000/docs
- **Statut** : http://localhost:8000/api/status

### Frontend
- **URL** : http://localhost:3000
- **Interface** : Interface React moderne

##  Configuration

### Variables d'Environnement

Créer un fichier `.env` dans le dossier `backend/` :

```env
# Configuration du serveur
HOST=0.0.0.0
PORT=8000
DEBUG=True

# Configuration des modèles
MODELS_DIR=models/
MAX_FILE_SIZE=100MB
SCAN_TIMEOUT=300

# Configuration de sécurité
ENABLE_REAL_TIME_PROTECTION=True
QUARANTINE_SUSPICIOUS_FILES=True
```

### Configuration Avancée

Modifier `backend/utils/config.py` pour ajuster :
- Seuils de détection
- Types de fichiers analysés
- Paramètres d'entraînement
- Configuration des modèles

##  Tests

### Tests de Détection

```bash
# Test d'un fichier unique
python test_suite/test_single_executable.py "chemin/vers/fichier.exe"

# Test complet multi-fichiers
python test_suite/test_advanced_detection.py

# Test des techniques d'évasion
python test_suite/test_naming_evasion.py

# Test des types de fichiers trompeurs
python test_suite/test_file_types.py
```

### Tests de Performance

```bash
# Test de performance
python test_suite/test_performance.py

# Test du système hybride
python test_suite/test_hybrid_system.py
```

##  API Endpoints

### Statut et Monitoring
- `GET /api/status` - Statut du système
- `GET /api/models/status` - Statut des modèles IA
- `GET /api/monitoring/stats` - Statistiques système

### Détection
- `POST /api/scan` - Lancer un scan
- `GET /api/scan/status` - Statut du scan
- `POST /api/analyze/file` - Analyser un fichier

### Menaces
- `GET /api/threats` - Liste des menaces détectées
- `GET /api/threats/{id}` - Détails d'une menace
- `DELETE /api/threats/{id}` - Supprimer une menace

### Statistiques
- `GET /api/statistics/overview` - Vue d'ensemble
- `GET /api/statistics/detection` - Statistiques de détection
- `GET /api/statistics/performance` - Statistiques de performance

##  Fonctionnalités de Sécurité

### Détection Avancée
-  **Analyse de fichiers** : EXE, PDF, DOCX, etc.
-  **Détection d'évasion** : Noms trompeurs, extensions doubles
-  **Analyse comportementale** : Actions suspectes
-  **Protection temps réel** : Monitoring continu

### Types de Menaces Détectées
-  **Ransomware** : Chiffrement de fichiers
-  **Spyware** : Surveillance clandestine
-  **Backdoors** : Accès non autorisé
-  **Trojans** : Logiciels malveillants déguisés
-  **Virus** : Propagation automatique

### Techniques d'Évasion Détectées
-  **Sandbox évasion** : Détection d'environnements virtuels
-  **Antivirus évasion** : Contournement des protections
-  **Évasion comportementale** : Actions furtives
-  **Évasion par nom** : Noms légitimes trompeurs

##  Performance

### Métriques Attendues
- **Précision** : 
- **Rappel** : 
- **F1-Score** : 
- **Temps de traitement** : < 2 secondes par fichier
- **Taux de faux positifs** : < 3%

### Optimisations
-  **GPU/CPU** : Optimisation automatique
-  **Cache** : Mise en cache des résultats
-  **Asynchrone** : Traitement non-bloquant
-  **Modèles légers** : Optimisés pour le hackathon

##  Dépannage

### Problèmes Courants

#### 1. Erreur de chargement des modèles
```bash
# Vérifier que les modèles existent
ls backend/models/

# Réentraîner les modèles
python train_models_for_hackathon.py
```

#### 2. Erreur de connexion frontend/backend
```bash
# Vérifier que le backend tourne
curl http://localhost:8000/api/status

# Vérifier les ports
netstat -an | grep 8000
netstat -an | grep 3000
```

#### 3. Erreur de dépendances
```bash
# Réinstaller les dépendances
pip install -r requirements.txt --force-reinstall

# Vérifier la version Python
python --version
```

### Logs

Les logs sont disponibles dans :
- **Backend** : Console et fichiers dans `backend/logs/`
- **Frontend** : Console du navigateur (F12)


### Ajout de Nouveaux Modèles

1. **Ajouter le modèle dans `ml_engine/`**
2. **Mettre à jour `train_models_for_hackathon.py`**
3. **Tester avec `test_suite/`**
4. **Documenter dans `docs/`**

##  Documentation Complémentaire

-  **Guide Utilisation** : `docs/GUIDE_UTILISATION.md`
-  **Démarrage Rapide** : `docs/GUIDE_DEMARRAGE_RAPIDE.md`
-  **Système Avancé** : `docs/SYSTEME_AVANCE.md`
-  **Tests** : `test_suite/README.md`

##  Hackathon

### Démonstration
1. **Lancer le système** : `python start_hackathon.py`
2. **Ouvrir l'interface** : http://localhost:3000
3. **Tester la détection** : Uploader un fichier suspect
4. **Montrer les statistiques** : Onglet Statistiques

### Points Clés
-  **Système unifié** : ML + NLP + Évasion
-  **Interface moderne** : React + Tailwind CSS
-  **API robuste** : FastAPI + Documentation
-  **Tests complets** : Suite de tests automatisés
-  **Documentation** : Guides détaillés



**RansomGuard AI** - Protection intelligente contre les ransomware 

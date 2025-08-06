"""
Script de préparation pour GitHub
RansomGuard AI - Hackathon Togo IT Days 2025
"""

import os
import shutil
import subprocess
from pathlib import Path

def clean_project():
    """Nettoyer le projet pour GitHub"""
    print("🧹 Nettoyage du projet pour GitHub...")
    
    # Dossiers à nettoyer
    dirs_to_clean = [
        "backend/models",
        "backend/logs",
        "backend/results",
        "test_suite/results",
        "test_suite/samples",
        "__pycache__",
        "frontend/node_modules",
        "frontend/build",
        "frontend/dist"
    ]
    
    for dir_path in dirs_to_clean:
        if os.path.exists(dir_path):
            print(f"🗑️ Suppression de {dir_path}")
            shutil.rmtree(dir_path)
    
    # Créer les dossiers nécessaires
    os.makedirs("backend/models", exist_ok=True)
    os.makedirs("backend/logs", exist_ok=True)
    os.makedirs("test_suite/results", exist_ok=True)
    
    print("✅ Nettoyage terminé")

def create_placeholder_files():
    """Créer des fichiers placeholder"""
    print("📝 Création des fichiers placeholder...")
    
    # Placeholder pour les modèles
    models_placeholder = """# Dossier des Modèles IA

Ce dossier contiendra les modèles entraînés après exécution de :
```bash
python train_models_for_hackathon.py
```

## Modèles Générés
- frontend_unified_model.pkl
- random_forest_model.pkl
- svm_model.pkl
- neural_network_model.pkl
- distilbert_hackathon/
- roberta_hackathon/
- dialogpt_hackathon/
- codebert_hackathon/
- unified_model_metadata.json

## Instructions
1. Exécuter l'entraînement : `python train_models_for_hackathon.py`
2. Les modèles seront automatiquement générés ici
3. Le système utilisera ces modèles pour la détection
"""
    
    with open("backend/models/README.md", "w", encoding="utf-8") as f:
        f.write(models_placeholder)
    
    # Placeholder pour les logs
    logs_placeholder = """# Dossier des Logs

Les logs du système seront générés ici lors de l'exécution.
"""
    
    with open("backend/logs/README.md", "w", encoding="utf-8") as f:
        f.write(logs_placeholder)
    
    # Placeholder pour les résultats de tests
    test_results_placeholder = """# Dossier des Résultats de Tests

Les résultats des tests seront générés ici lors de l'exécution des scripts de test.
"""
    
    with open("test_suite/results/README.md", "w", encoding="utf-8") as f:
        f.write(test_results_placeholder)
    
    print("✅ Fichiers placeholder créés")

def update_documentation():
    """Mettre à jour la documentation"""
    print("📚 Mise à jour de la documentation...")
    
    # Créer un fichier d'installation rapide
    quick_install = """# 🚀 Installation Rapide

## Prérequis
- Python 3.8+
- Node.js 16+
- Git

## Installation
```bash
# 1. Cloner le projet
git clone <repository_url>
cd "Togo IT Days/backend"

# 2. Installer les dépendances
pip install -r requirements.txt

# 3. Démarrer le système
python start_hackathon.py
```

## Accès
- Frontend: http://localhost:3000
- Backend: http://localhost:8000
- Documentation: http://localhost:8000/docs

## Tests
```bash
python test_suite/test_single_executable.py "fichier.exe"
python test_suite/test_advanced_detection.py
```
"""
    
    with open("INSTALLATION_RAPIDE.md", "w", encoding="utf-8") as f:
        f.write(quick_install)
    
    print("✅ Documentation mise à jour")

def check_git_status():
    """Vérifier le statut Git"""
    print("🔍 Vérification du statut Git...")
    
    try:
        # Vérifier si c'est un repo Git
        result = subprocess.run(['git', 'status'], capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ Repository Git détecté")
            
            # Afficher les fichiers modifiés
            result = subprocess.run(['git', 'status', '--porcelain'], capture_output=True, text=True)
            if result.stdout.strip():
                print("📝 Fichiers modifiés:")
                print(result.stdout)
            else:
                print("✅ Aucun fichier modifié")
        else:
            print("⚠️ Pas de repository Git détecté")
            
    except FileNotFoundError:
        print("⚠️ Git non installé")

def create_deployment_script():
    """Créer un script de déploiement"""
    print("🚀 Création du script de déploiement...")
    
    deploy_script = """#!/bin/bash
# Script de déploiement pour le hackathon

echo "🚀 Déploiement de RansomGuard AI..."

# Vérifier les prérequis
echo "🔍 Vérification des prérequis..."
python --version
node --version
npm --version

# Installer les dépendances
echo "📦 Installation des dépendances..."
pip install -r requirements.txt

# Entraîner les modèles
echo "🧠 Entraînement des modèles..."
python train_models_for_hackathon.py

# Démarrer le système
echo "🎯 Démarrage du système..."
python start_hackathon.py
"""
    
    with open("deploy.sh", "w") as f:
        f.write(deploy_script)
    
    # Rendre le script exécutable (Linux/Mac)
    try:
        os.chmod("deploy.sh", 0o755)
    except:
        pass
    
    print("✅ Script de déploiement créé")

def main():
    """Fonction principale"""
    print("🎯 Préparation du projet pour GitHub")
    print("="*50)
    
    # 1. Nettoyer le projet
    clean_project()
    
    # 2. Créer les fichiers placeholder
    create_placeholder_files()
    
    # 3. Mettre à jour la documentation
    update_documentation()
    
    # 4. Créer le script de déploiement
    create_deployment_script()
    
    # 5. Vérifier le statut Git
    check_git_status()
    
    print("\n" + "="*50)
    print("✅ Projet prêt pour GitHub!")
    print("\n📋 Prochaines étapes:")
    print("1. git add .")
    print("2. git commit -m 'Initial commit - RansomGuard AI Hackathon'")
    print("3. git push origin main")
    print("\n🎯 Pour l'équipe:")
    print("1. git clone <repository_url>")
    print("2. cd 'Togo IT Days/backend'")
    print("3. python start_hackathon.py")
    print("="*50)

if __name__ == "__main__":
    main() 
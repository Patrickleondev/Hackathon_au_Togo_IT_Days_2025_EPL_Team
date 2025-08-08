#!/usr/bin/env python3
"""
Script d'installation des packages requis
RansomGuard AI - Hackathon Togo IT Days 2025
"""

import subprocess
import sys
import os
from pathlib import Path

def install_packages():
    """Installer tous les packages requis"""
    
    print("🚀 Installation des packages requis pour RansomGuard AI")
    print("=" * 60)
    
    # Vérifier si on est dans un environnement virtuel
    if not hasattr(sys, 'real_prefix') and not (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print("⚠️  Attention: Il est recommandé d'utiliser un environnement virtuel")
        response = input("Continuer quand même ? (y/N): ")
        if response.lower() != 'y':
            print("❌ Installation annulée")
            return
    
    # Chemin vers requirements.txt
    requirements_path = Path("backend/requirements.txt")
    
    if not requirements_path.exists():
        print(f"❌ Fichier {requirements_path} non trouvé")
        return
    
    print(f"📦 Installation depuis {requirements_path}")
    
    try:
        # Installer les packages
        result = subprocess.run([
            sys.executable, "-m", "pip", "install", "-r", str(requirements_path)
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Installation réussie !")
            print("\n📋 Packages installés :")
            
            # Afficher les packages installés
            packages = [
                "fastapi", "uvicorn", "pydantic", "sqlalchemy",
                "psutil", "netifaces", "scikit-learn", "numpy", "pandas",
                "torch", "transformers", "datasets", "accelerate",
                "python-multipart", "aiofiles", "requests", "httpx",
                "watchdog", "joblib", "matplotlib", "seaborn",
                "aiohttp", "plotly", "pywin32", "inotify"
            ]
            
            for package in packages:
                try:
                    result = subprocess.run([
                        sys.executable, "-c", f"import {package}; print(f'✅ {package} - OK')"
                    ], capture_output=True, text=True)
                    if result.returncode == 0:
                        print(f"  ✅ {package}")
                    else:
                        print(f"  ❌ {package} - Non installé")
                except:
                    print(f"  ❌ {package} - Erreur")
            
        else:
            print("❌ Erreur lors de l'installation:")
            print(result.stderr)
            
    except Exception as e:
        print(f"❌ Erreur: {e}")
    
    print("\n🎯 Prochaines étapes:")
    print("1. Activer l'environnement virtuel: source venv/bin/activate (Linux/Mac) ou venv\\Scripts\\activate (Windows)")
    print("2. Démarrer le backend: cd backend && python main.py")
    print("3. Démarrer le frontend: cd new_frontend && npm run dev")

if __name__ == "__main__":
    install_packages()

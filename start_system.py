#!/usr/bin/env python3
"""
Script de démarrage unifié pour RansomGuard AI
Hackathon Togo IT Days 2025
"""

import subprocess
import sys
import os
import time
import threading
from pathlib import Path

def print_banner():
    """Afficher la bannière du système"""
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                    RANSOMGUARD AI                            ║
    ║              Protection contre les Ransomware                ║
    ║                Hackathon Togo IT Days 2025                  ║
    ╚══════════════════════════════════════════════════════════════╝
    """)

def check_dependencies():
    """Vérifier les dépendances"""
    print("🔍 Vérification des dépendances...")
    
    # Vérifier Python
    try:
        import numpy
        import sklearn
        import fastapi
        import uvicorn
        print("✅ Backend: Dépendances Python OK")
    except ImportError as e:
        print(f"❌ Backend: Dépendance manquante - {e}")
        return False
    
    # Vérifier Node.js
    try:
        result = subprocess.run(['node', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ Frontend: Node.js OK")
        else:
            print("❌ Frontend: Node.js non trouvé")
            return False
    except FileNotFoundError:
        print("❌ Frontend: Node.js non installé")
        return False
    
    return True

def start_backend():
    """Démarrer le backend"""
    print("🚀 Démarrage du backend FastAPI...")
    backend_dir = Path("backend")
    if not backend_dir.exists():
        print("❌ Dossier backend non trouvé")
        return None
    
    try:
        # Utiliser l'environnement virtuel
        venv_python = backend_dir / "venv" / "Scripts" / "python.exe"
        if venv_python.exists():
            process = subprocess.Popen(
                [str(venv_python), "main.py"],
                cwd=backend_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
        else:
            # Fallback vers Python global
            process = subprocess.Popen(
                [sys.executable, "main.py"],
                cwd=backend_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
        print("✅ Backend démarré sur http://localhost:8000")
        return process
    except Exception as e:
        print(f"❌ Erreur lors du démarrage du backend: {e}")
        return None

def start_frontend():
    """Démarrer le frontend"""
    print("🚀 Démarrage du frontend React...")
    frontend_dir = Path("frontend")
    if not frontend_dir.exists():
        print("❌ Dossier frontend non trouvé")
        return None
    
    try:
        process = subprocess.Popen(
            ["npm", "start"],
            cwd=frontend_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        print("✅ Frontend démarré sur http://localhost:3000")
        return process
    except Exception as e:
        print(f"❌ Erreur lors du démarrage du frontend: {e}")
        return None

def main():
    """Fonction principale"""
    print_banner()
    
    # Vérifier les dépendances
    if not check_dependencies():
        print("❌ Dépendances manquantes. Veuillez installer les dépendances requises.")
        return
    
    print("🎯 Démarrage du système RansomGuard AI...")
    
    # Démarrer le backend
    backend_process = start_backend()
    if not backend_process:
        print("❌ Impossible de démarrer le backend")
        return
    
    # Attendre un peu que le backend démarre
    time.sleep(3)
    
    # Démarrer le frontend
    frontend_process = start_frontend()
    if not frontend_process:
        print("❌ Impossible de démarrer le frontend")
        backend_process.terminate()
        return
    
    print("\n🎉 Système RansomGuard AI démarré avec succès!")
    print("📱 Frontend: http://localhost:3000")
    print("🔧 Backend: http://localhost:8000")
    print("📚 API Docs: http://localhost:8000/docs")
    print("\n💡 Appuyez sur Ctrl+C pour arrêter le système")
    
    try:
        # Attendre que les processus se terminent
        backend_process.wait()
        frontend_process.wait()
    except KeyboardInterrupt:
        print("\n🛑 Arrêt du système...")
        backend_process.terminate()
        frontend_process.terminate()
        print("✅ Système arrêté")

if __name__ == "__main__":
    main()

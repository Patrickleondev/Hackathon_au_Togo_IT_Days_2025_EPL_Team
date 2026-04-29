#!/usr/bin/env python3
"""
Script de démarrage pour RansomGuard AI
Hackathon Togo IT Days 2025
"""

import os
import sys
import subprocess
import time
import webbrowser
from pathlib import Path

def print_banner():
    """Afficher la bannière de démarrage"""
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                    🛡️ RansomGuard AI 🛡️                      ║
    ║                                                              ║
    ║           Protection intelligente contre les ransomware      ║
    ║                    Hackathon TID 2025                       ║
    ╚══════════════════════════════════════════════════════════════╝
    """)

def check_requirements():
    """Vérifier les prérequis"""
    print("🔍 Vérification des prérequis...")
    
    # Vérifier Python
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ requis")
        return False
    
    # Vérifier Node.js
    try:
        result = subprocess.run(['node', '--version'], capture_output=True, text=True)
        if result.returncode != 0:
            print("❌ Node.js requis")
            return False
    except FileNotFoundError:
        print("❌ Node.js requis")
        return False
    
    print("✅ Prérequis satisfaits")
    return True

def install_backend_dependencies():
    """Installer les dépendances backend"""
    print("📦 Installation des dépendances backend...")
    
    try:
        subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'backend/requirements.txt'], check=True)
        print("✅ Dépendances backend installées")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Erreur lors de l'installation des dépendances backend: {e}")
        return False

def install_frontend_dependencies():
    """Installer les dépendances frontend"""
    print("📦 Installation des dépendances frontend...")
    
    try:
        os.chdir('frontend')
        subprocess.run(['npm', 'install'], check=True)
        os.chdir('..')
        print("✅ Dépendances frontend installées")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Erreur lors de l'installation des dépendances frontend: {e}")
        return False

def start_backend():
    """Démarrer le backend"""
    print("🚀 Démarrage du backend...")
    
    try:
        os.chdir('backend')
        process = subprocess.Popen([sys.executable, 'main.py'])
        os.chdir('..')
        
        # Attendre que le backend démarre
        time.sleep(3)
        
        if process.poll() is None:
            print("✅ Backend démarré sur http://localhost:8000")
            return process
        else:
            print("❌ Erreur lors du démarrage du backend")
            return None
    except Exception as e:
        print(f"❌ Erreur lors du démarrage du backend: {e}")
        return None

def start_frontend():
    """Démarrer le frontend"""
    print("🚀 Démarrage du frontend...")
    
    try:
        os.chdir('frontend')
        process = subprocess.Popen(['npm', 'start'])
        os.chdir('..')
        
        # Attendre que le frontend démarre
        time.sleep(5)
        
        if process.poll() is None:
            print("✅ Frontend démarré sur http://localhost:3000")
            return process
        else:
            print("❌ Erreur lors du démarrage du frontend")
            return None
    except Exception as e:
        print(f"❌ Erreur lors du démarrage du frontend: {e}")
        return None

def open_browser():
    """Ouvrir le navigateur"""
    print("🌐 Ouverture du navigateur...")
    
    try:
        webbrowser.open('http://localhost:3000')
        print("✅ Navigateur ouvert")
    except Exception as e:
        print(f"⚠️ Impossible d'ouvrir le navigateur automatiquement: {e}")
        print("🌐 Veuillez ouvrir manuellement: http://localhost:3000")

def main():
    """Fonction principale"""
    print_banner()
    
    # Vérifier les prérequis
    if not check_requirements():
        print("❌ Arrêt du programme")
        return
    
    # Installer les dépendances
    if not install_backend_dependencies():
        print("❌ Arrêt du programme")
        return
    
    if not install_frontend_dependencies():
        print("❌ Arrêt du programme")
        return
    
    # Démarrer les services
    backend_process = start_backend()
    if not backend_process:
        print("❌ Arrêt du programme")
        return
    
    frontend_process = start_frontend()
    if not frontend_process:
        print("❌ Arrêt du programme")
        backend_process.terminate()
        return
    
    # Ouvrir le navigateur
    open_browser()
    
    print("\n🎉 RansomGuard AI est maintenant opérationnel!")
    print("📊 Dashboard: http://localhost:3000")
    print("🔧 API: http://localhost:8000")
    print("📚 Documentation: http://localhost:8000/docs")
    print("\n💡 Pour arrêter l'application, appuyez sur Ctrl+C")
    
    try:
        # Attendre que les processus se terminent
        backend_process.wait()
        frontend_process.wait()
    except KeyboardInterrupt:
        print("\n🛑 Arrêt de l'application...")
        backend_process.terminate()
        frontend_process.terminate()
        print("✅ Application arrêtée")

if __name__ == "__main__":
    main() 
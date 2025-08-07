#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de configuration et démarrage du système RansomGuard AI
Hackathon Togo IT Days 2025

Ce script configure et démarre automatiquement tout le système:
- Backend FastAPI avec ML hybride
- Frontend React
- Monitoring système en temps réel
- Support multilingue
"""

import os
import sys
import subprocess
import time
import signal
import atexit
from pathlib import Path
import asyncio
import logging

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class RansomGuardSystemManager:
    """Gestionnaire principal du système RansomGuard AI"""
    
    def __init__(self):
        self.processes = []
        self.base_dir = Path(__file__).parent
        self.backend_dir = self.base_dir / "backend"
        self.frontend_dir = self.base_dir / "frontend"
        
        # Enregistrer la fonction de nettoyage
        atexit.register(self.cleanup)
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        """Gestionnaire de signaux pour un arrêt propre"""
        logger.info(f"Signal {signum} reçu, arrêt du système...")
        self.cleanup()
        sys.exit(0)
    
    def cleanup(self):
        """Nettoyer les processus en cours"""
        logger.info("🧹 Nettoyage des processus...")
        for process in self.processes:
            try:
                process.terminate()
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            except Exception as e:
                logger.error(f"Erreur lors de l'arrêt d'un processus: {e}")
    
    def check_dependencies(self):
        """Vérifier les dépendances système"""
        logger.info("🔍 Vérification des dépendances...")
        
        # Vérifier Python
        if sys.version_info < (3, 8):
            logger.error("Python 3.8+ requis")
            return False
        
        # Vérifier Node.js pour le frontend
        try:
            result = subprocess.run(['node', '--version'], capture_output=True, text=True)
            if result.returncode != 0:
                logger.error("Node.js non trouvé")
                return False
            logger.info(f"✅ Node.js détecté: {result.stdout.strip()}")
        except FileNotFoundError:
            logger.error("Node.js non installé")
            return False
        
        # Vérifier npm
        try:
            result = subprocess.run(['npm', '--version'], capture_output=True, text=True)
            if result.returncode != 0:
                logger.error("npm non trouvé")
                return False
            logger.info(f"✅ npm détecté: {result.stdout.strip()}")
        except FileNotFoundError:
            logger.error("npm non installé")
            return False
        
        return True
    
    def setup_backend(self):
        """Configurer et installer les dépendances backend"""
        logger.info("🔧 Configuration du backend...")
        
        if not self.backend_dir.exists():
            logger.error("Dossier backend non trouvé")
            return False
        
        # Créer un environnement virtuel si nécessaire
        venv_dir = self.backend_dir / "venv"
        if not venv_dir.exists():
            logger.info("Création de l'environnement virtuel...")
            result = subprocess.run([
                sys.executable, "-m", "venv", str(venv_dir)
            ], cwd=str(self.backend_dir))
            
            if result.returncode != 0:
                logger.error("Erreur lors de la création de l'environnement virtuel")
                return False
        
        # Déterminer l'exécutable pip
        if os.name == 'nt':  # Windows
            pip_exe = venv_dir / "Scripts" / "pip.exe"
            python_exe = venv_dir / "Scripts" / "python.exe"
        else:  # Unix/Linux/Mac
            pip_exe = venv_dir / "bin" / "pip"
            python_exe = venv_dir / "bin" / "python"
        
        # Installer les dépendances
        logger.info("Installation des dépendances backend...")
        result = subprocess.run([
            str(pip_exe), "install", "-r", "requirements.txt"
        ], cwd=str(self.backend_dir))
        
        if result.returncode != 0:
            logger.error("Erreur lors de l'installation des dépendances backend")
            return False
        
        logger.info("✅ Backend configuré avec succès")
        return True
    
    def setup_frontend(self):
        """Configurer et installer les dépendances frontend"""
        logger.info("🔧 Configuration du frontend...")
        
        if not self.frontend_dir.exists():
            logger.error("Dossier frontend non trouvé")
            return False
        
        # Installer les dépendances npm
        logger.info("Installation des dépendances frontend...")
        result = subprocess.run([
            "npm", "install"
        ], cwd=str(self.frontend_dir))
        
        if result.returncode != 0:
            logger.error("Erreur lors de l'installation des dépendances frontend")
            return False
        
        logger.info("✅ Frontend configuré avec succès")
        return True
    
    def start_backend(self):
        """Démarrer le serveur backend"""
        logger.info("🚀 Démarrage du backend...")
        
        # Déterminer l'exécutable Python
        venv_dir = self.backend_dir / "venv"
        if os.name == 'nt':  # Windows
            python_exe = venv_dir / "Scripts" / "python.exe"
        else:  # Unix/Linux/Mac
            python_exe = venv_dir / "bin" / "python"
        
        # Si l'environnement virtuel n'existe pas, utiliser Python système
        if not python_exe.exists():
            python_exe = sys.executable
        
        try:
            process = subprocess.Popen([
                str(python_exe), "main.py"
            ], cwd=str(self.backend_dir))
            
            self.processes.append(process)
            logger.info("✅ Backend démarré sur http://localhost:8000")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors du démarrage du backend: {e}")
            return False
    
    def start_frontend(self):
        """Démarrer le serveur frontend"""
        logger.info("🚀 Démarrage du frontend...")
        
        try:
            process = subprocess.Popen([
                "npm", "start"
            ], cwd=str(self.frontend_dir))
            
            self.processes.append(process)
            logger.info("✅ Frontend démarré sur http://localhost:3000")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors du démarrage du frontend: {e}")
            return False
    
    def wait_for_backend(self, timeout=30):
        """Attendre que le backend soit prêt"""
        import requests
        
        logger.info("⏳ Attente du démarrage du backend...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                response = requests.get("http://localhost:8000/", timeout=5)
                if response.status_code == 200:
                    logger.info("✅ Backend prêt!")
                    return True
            except requests.RequestException:
                time.sleep(2)
        
        logger.error("❌ Timeout: le backend n'a pas démarré")
        return False
    
    def display_status(self):
        """Afficher le statut du système"""
        logger.info("\n" + "="*60)
        logger.info("🛡️  RANSOMGUARD AI - SYSTÈME DÉMARRÉ")
        logger.info("="*60)
        logger.info("🌐 Frontend: http://localhost:3000")
        logger.info("🔧 Backend API: http://localhost:8000")
        logger.info("📖 Documentation API: http://localhost:8000/docs")
        logger.info("="*60)
        logger.info("\n🌍 Langues supportées:")
        logger.info("   • Français (fr)")
        logger.info("   • English (en)")
        logger.info("   • Eʋegbe (ee)")
        logger.info("\n🔒 Fonctionnalités disponibles:")
        logger.info("   • Analyse de fichiers en temps réel")
        logger.info("   • Scan du système et réseau")
        logger.info("   • Détection hybride ML + NLP")
        logger.info("   • Monitoring système temps réel")
        logger.info("   • Interface multilingue")
        logger.info("\n⌨️  Appuyez sur Ctrl+C pour arrêter le système")
        logger.info("="*60)
    
    def run(self):
        """Lancer le système complet"""
        logger.info("🛡️ Démarrage de RansomGuard AI v2.0")
        logger.info("Hackathon Togo IT Days 2025")
        
        # Vérifier les dépendances
        if not self.check_dependencies():
            logger.error("❌ Dépendances manquantes")
            return False
        
        # Configurer le backend
        if not self.setup_backend():
            logger.error("❌ Erreur configuration backend")
            return False
        
        # Configurer le frontend
        if not self.setup_frontend():
            logger.error("❌ Erreur configuration frontend")
            return False
        
        # Démarrer le backend
        if not self.start_backend():
            logger.error("❌ Erreur démarrage backend")
            return False
        
        # Attendre que le backend soit prêt
        if not self.wait_for_backend():
            logger.error("❌ Backend non accessible")
            return False
        
        # Démarrer le frontend
        if not self.start_frontend():
            logger.error("❌ Erreur démarrage frontend")
            return False
        
        # Afficher le statut
        time.sleep(3)  # Laisser le temps au frontend de démarrer
        self.display_status()
        
        # Maintenir le système en marche
        try:
            while True:
                # Vérifier que les processus sont toujours actifs
                for i, process in enumerate(self.processes):
                    if process.poll() is not None:
                        logger.error(f"Processus {i} s'est arrêté")
                        return False
                
                time.sleep(5)
                
        except KeyboardInterrupt:
            logger.info("\n👋 Arrêt demandé par l'utilisateur")
            return True

def main():
    """Point d'entrée principal"""
    try:
        manager = RansomGuardSystemManager()
        success = manager.run()
        
        if success:
            logger.info("✅ Système arrêté proprement")
        else:
            logger.error("❌ Erreur lors de l'exécution")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Erreur fatale: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
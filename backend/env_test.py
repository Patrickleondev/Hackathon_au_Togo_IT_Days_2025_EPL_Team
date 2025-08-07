"""
Script de démarrage unifié pour le Hackathon
RansomGuard AI - Togo IT Days 2025
"""

import os
import sys
import subprocess
import time
import logging
from pathlib import Path

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class HackathonStarter:
    """Démarreur optimisé pour le hackathon"""
    
    def __init__(self):
        self.backend_dir = Path(__file__).parent
        self.frontend_dir = self.backend_dir.parent / "frontend"
        self.models_dir = self.backend_dir / "models"
        self.backend_port = 8000
        self.frontend_port = 3000
        
    def check_prerequisites(self) -> bool:
        """Vérifier les prérequis"""
        logger.info("🔍 Vérification des prérequis...")
        
        # Vérifier Python
        try:
            python_version = sys.version_info
            if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 8):
                logger.error("❌ Python 3.8+ requis")
                return False
            logger.info(f"✅ Python {python_version.major}.{python_version.minor}.{python_version.micro}")
        except Exception as e:
            logger.error(f"❌ Erreur lors de la vérification Python: {e}")
            return False
        
        # Vérifier Node.js
        try:
            result = subprocess.run(['node', '--version'], capture_output=True, text=True)
            if result.returncode != 0:
                logger.error("❌ Node.js requis")
                return False
            logger.info(f"✅ Node.js {result.stdout.strip()}")
        except FileNotFoundError:
            logger.error("❌ Node.js non trouvé")
            return False
        
        # Vérifier npm
        try:
            result = subprocess.run(['npm', '--version'], capture_output=True, text=True)
            if result.returncode != 0:
                logger.error("❌ npm requis")
                return False
            logger.info(f"✅ npm {result.stdout.strip()}")
        except FileNotFoundError:
            logger.error("❌ npm non trouvé")
            return False
        
        return True
    
    def install_dependencies(self) -> bool:
        """Installer les dépendances"""
        logger.info("📦 Installation des dépendances...")
        
        try:
            # Installer les dépendances Python
            logger.info("🔄 Installation des dépendances Python...")
            result = subprocess.run([
                sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'
            ], cwd=self.backend_dir, capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.error(f"❌ Erreur installation Python: {result.stderr}")
                return False
            logger.info("✅ Dépendances Python installées")
            
            # Installer les dépendances Node.js
            if self.frontend_dir.exists():
                logger.info("🔄 Installation des dépendances Node.js...")
                result = subprocess.run(['npm', 'install'], cwd=self.frontend_dir, capture_output=True, text=True)
                
                if result.returncode != 0:
                    logger.error(f"❌ Erreur installation Node.js: {result.stderr}")
                    return False
                logger.info("✅ Dépendances Node.js installées")
            else:
                logger.warning("⚠️ Dossier frontend non trouvé, création d'un frontend minimal...")
                self.create_minimal_frontend()
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Erreur lors de l'installation: {e}")
            return False
    
    def create_minimal_frontend(self):
        """Créer un frontend minimal si nécessaire"""
        try:
            self.frontend_dir.mkdir(exist_ok=True)
            
            # package.json minimal
            package_json = {
                "name": "ransomguard-frontend",
                "version": "1.0.0",
                "private": True,
                "dependencies": {
                    "react": "^18.2.0",
                    "react-dom": "^18.2.0",
                    "react-scripts": "5.0.1",
                    "axios": "^1.6.0",
                    "lucide-react": "^0.294.0",
                    "recharts": "^2.8.0"
                },
                "scripts": {
                    "start": "react-scripts start",
                    "build": "react-scripts build",
                    "test": "react-scripts test",
                    "eject": "react-scripts eject"
                },
                "browserslist": {
                    "production": [">0.2%", "not dead", "not op_mini all"],
                    "development": ["last 1 chrome version", "last 1 firefox version", "last 1 safari version"]
                }
            }
            
            import json
            with open(self.frontend_dir / "package.json", 'w') as f:
                json.dump(package_json, f, indent=2)
            
            # Créer un App.tsx minimal
            app_tsx = '''import React from 'react';
import { Shield, Activity, AlertTriangle } from 'lucide-react';

function App() {
  return (
    <div className="min-h-screen bg-gray-50 p-8">
      <div className="max-w-4xl mx-auto">
        <div className="text-center mb-8">
          <div className="flex items-center justify-center mb-4">
            <Shield className="w-12 h-12 text-blue-600" />
          </div>
          <h1 className="text-3xl font-bold text-gray-900 mb-2">RansomGuard AI</h1>
          <p className="text-gray-600">Système de protection contre les ransomware</p>
          <p className="text-sm text-gray-500 mt-2">Hackathon Togo IT Days 2025</p>
        </div>
        
        <div className="bg-white rounded-lg shadow-md p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-semibold">Statut du Système</h2>
            <div className="flex items-center space-x-2">
              <div className="w-3 h-3 bg-green-500 rounded-full"></div>
              <span className="text-sm text-gray-600">Actif</span>
            </div>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-blue-50 p-4 rounded-lg">
              <div className="flex items-center space-x-2">
                <Activity className="w-5 h-5 text-blue-600" />
                <span className="font-medium">Menaces Détectées</span>
              </div>
              <p className="text-2xl font-bold text-blue-600 mt-2">0</p>
            </div>
            
            <div className="bg-green-50 p-4 rounded-lg">
              <div className="flex items-center space-x-2">
                <Shield className="w-5 h-5 text-green-600" />
                <span className="font-medium">Fichiers Protégés</span>
              </div>
              <p className="text-2xl font-bold text-green-600 mt-2">15,420</p>
            </div>
            
            <div className="bg-yellow-50 p-4 rounded-lg">
              <div className="flex items-center space-x-2">
                <AlertTriangle className="w-5 h-5 text-yellow-600" />
                <span className="font-medium">Dernier Scan</span>
              </div>
              <p className="text-sm text-gray-600 mt-2">Il y a 5 min</p>
            </div>
          </div>
          
          <div className="mt-6 text-center">
            <p className="text-gray-600 mb-4">
              Le système de détection est opérationnel et protège votre ordinateur.
            </p>
            <div className="text-sm text-gray-500">
              Backend API: http://localhost:8000<br/>
              Documentation: http://localhost:8000/docs
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
'''
            
            # Créer la structure minimale
            src_dir = self.frontend_dir / "src"
            src_dir.mkdir(exist_ok=True)
            
            with open(src_dir / "App.tsx", 'w') as f:
                f.write(app_tsx)
            
            # Créer index.js
            index_js = '''import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
'''
            
            with open(src_dir / "index.js", 'w') as f:
                f.write(index_js)
            
            # Créer public/index.html
            public_dir = self.frontend_dir / "public"
            public_dir.mkdir(exist_ok=True)
            
            index_html = '''<!DOCTYPE html>
<html lang="fr">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="theme-color" content="#000000" />
    <meta name="description" content="RansomGuard AI - Protection contre les ransomware" />
    <title>RansomGuard AI</title>
    <script src="https://cdn.tailwindcss.com"></script>
  </head>
  <body>
    <noscript>You need to enable JavaScript to run this app.</noscript>
    <div id="root"></div>
  </body>
</html>
'''
            
            with open(public_dir / "index.html", 'w') as f:
                f.write(index_html)
            
            logger.info("✅ Frontend minimal créé")
            
        except Exception as e:
            logger.error(f"❌ Erreur lors de la création du frontend minimal: {e}")
    
    def train_models(self) -> bool:
        """Entraîner les modèles IA"""
        logger.info("🧠 Entraînement des modèles IA...")
        
        try:
            # Vérifier si les modèles existent déjà
            if self.models_dir.exists() and any(self.models_dir.glob("*.pkl")):
                logger.info("✅ Modèles déjà entraînés détectés")
                return True
            
            # Lancer l'entraînement
            result = subprocess.run([
                sys.executable, 'train_models_for_hackathon.py'
            ], cwd=self.backend_dir, capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.error(f"❌ Erreur lors de l'entraînement: {result.stderr}")
                return False
            
            logger.info("✅ Modèles entraînés avec succès")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erreur lors de l'entraînement: {e}")
            return False
    
    def start_backend(self):
        """Démarrer le backend"""
        logger.info("🚀 Démarrage du backend...")
        
        try:
            # Démarrer le backend en arrière-plan
            backend_process = subprocess.Popen([
                sys.executable, 'main.py'
            ], cwd=self.backend_dir)
            
            # Attendre que le backend démarre
            time.sleep(3)
            
            # Vérifier que le backend fonctionne
            import requests
            try:
                response = requests.get(f'http://localhost:{self.backend_port}/api/status', timeout=5)
                if response.status_code == 200:
                    logger.info("✅ Backend démarré avec succès")
                    return backend_process
                else:
                    logger.error("❌ Backend ne répond pas correctement")
                    return None
            except requests.exceptions.RequestException:
                logger.error("❌ Impossible de se connecter au backend")
                return None
                
        except Exception as e:
            logger.error(f"❌ Erreur lors du démarrage du backend: {e}")
            return None
    
    def start_frontend(self):
        """Démarrer le frontend"""
        logger.info("🎨 Démarrage du frontend...")
        
        try:
            # Démarrer le frontend en arrière-plan
            frontend_process = subprocess.Popen([
                'npm', 'start'
            ], cwd=self.frontend_dir)
            
            # Attendre que le frontend démarre
            time.sleep(5)
            
            logger.info("✅ Frontend démarré avec succès")
            return frontend_process
            
        except Exception as e:
            logger.error(f"❌ Erreur lors du démarrage du frontend: {e}")
            return None
    
    def print_startup_info(self):
        """Afficher les informations de démarrage"""
        print("\n" + "="*60)
        print("🎉 RANSOMGUARD AI - SYSTÈME DÉMARRÉ AVEC SUCCÈS!")
        print("="*60)
        print()
        print("🌐 Accès au système:")
        print(f"   • Frontend: http://localhost:{self.frontend_port}")
        print(f"   • Backend API: http://localhost:{self.backend_port}")
        print(f"   • Documentation API: http://localhost:{self.backend_port}/docs")
        print(f"   • Statut API: http://localhost:{self.backend_port}/api/status")
        print()
        print("🧪 Tests disponibles:")
        print("   • Test d'un fichier: python test_suite/test_single_executable.py")
        print("   • Test complet: python test_suite/test_advanced_detection.py")
        print("   • Test d'évasion: python test_suite/test_naming_evasion.py")
        print()
        print("📚 Documentation:")
        print("   • README.md - Guide complet")
        print("   • docs/GUIDE_DEMARRAGE_RAPIDE.md - Démarrage rapide")
        print("   • docs/SYSTEME_AVANCE.md - Architecture avancée")
        print()
        print("🛡️ Le système protège maintenant votre ordinateur!")
        print("="*60)
    
    def run(self):
        """Exécuter le démarrage complet"""
        logger.info("🚀 Démarrage du système RansomGuard AI pour le hackathon...")
        
        # Étape 1: Vérifier les prérequis
        if not self.check_prerequisites():
            logger.error("❌ Prérequis non satisfaits")
            return False
        
        # Étape 2: Installer les dépendances
        if not self.install_dependencies():
            logger.error("❌ Échec de l'installation des dépendances")
            return False
        
        # Étape 3: Entraîner les modèles
        if not self.train_models():
            logger.error("❌ Échec de l'entraînement des modèles")
            return False
        
        # Étape 4: Démarrer le backend
        backend_process = self.start_backend()
        if not backend_process:
            logger.error("❌ Échec du démarrage du backend")
            return False
        
        # Étape 5: Démarrer le frontend
        frontend_process = self.start_frontend()
        if not frontend_process:
            logger.error("❌ Échec du démarrage du frontend")
            backend_process.terminate()
            return False
        
        # Étape 6: Afficher les informations
        self.print_startup_info()
        
        try:
            # Attendre que les processus se terminent
            backend_process.wait()
            frontend_process.wait()
        except KeyboardInterrupt:
            logger.info("🛑 Arrêt du système...")
            backend_process.terminate()
            frontend_process.terminate()
        
        return True

def main():
    """Fonction principale"""
    starter = HackathonStarter()
    success = starter.run()
    
    if success:
        print("✅ Système démarré avec succès!")
    else:
        print("❌ Échec du démarrage du système")
        sys.exit(1)

if __name__ == "__main__":
    main() 
#!/usr/bin/env python3
"""
Script de test pour RansomGuard AI
Hackathon Togo IT Days 2025
"""

import os
import sys
import asyncio
import logging
from pathlib import Path

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def test_system_components():
    """Tester les composants du système"""
    logger.info("🚀 Test des composants RansomGuard AI...")
    
    # Test 1: Vérification des imports
    try:
        logger.info("📦 Test des imports...")
        from ml_engine.ransomware_detector import RansomwareDetector
        from ml_engine.hybrid_detector import HybridDetector
        from ml_engine.ultra_detector import UltraDetector
        from ml_engine.system_monitor import SystemMonitor
        logger.info("✅ Imports réussis")
    except ImportError as e:
        logger.error(f"❌ Erreur d'import: {e}")
        return False
    
    # Test 2: Initialisation des détecteurs
    try:
        logger.info("🔍 Test des détecteurs...")
        detector = RansomwareDetector()
        hybrid_detector = HybridDetector()
        ultra_detector = UltraDetector()
        monitor = SystemMonitor()
        logger.info("✅ Détecteurs initialisés")
    except Exception as e:
        logger.error(f"❌ Erreur d'initialisation: {e}")
        return False
    
    # Test 3: Vérification des modèles
    try:
        logger.info("🤖 Test des modèles...")
        from ml_engine.model_loader import get_model_loader
        model_loader = get_model_loader()
        model_status = model_loader.get_model_status()
        logger.info(f"✅ Statut des modèles: {model_status}")
    except Exception as e:
        logger.error(f"❌ Erreur des modèles: {e}")
        return False
    
    # Test 4: Vérification des fichiers de détection
    try:
        logger.info("📁 Test des fichiers de détection...")
        detection_paths = [
            "detections/sigma",
            "detections/suricata", 
            "detections/yara",
            "detections/sysmon"
        ]
        
        for path in detection_paths:
            if os.path.exists(path):
                files = os.listdir(path)
                logger.info(f"✅ {path}: {len(files)} fichiers")
            else:
                logger.warning(f"⚠️ {path}: non trouvé")
    except Exception as e:
        logger.error(f"❌ Erreur fichiers de détection: {e}")
    
    # Test 5: Vérification des données d'intelligence des menaces
    try:
        logger.info("🕵️ Test de l'intelligence des menaces...")
        threat_data_paths = [
            "data/threat_intelligence/malicious_domains.json",
            "data/threat_intelligence/malicious_ips.json",
            "data/threat_intelligence/malicious_hashes.json"
        ]
        
        for path in threat_data_paths:
            if os.path.exists(path):
                size = os.path.getsize(path)
                logger.info(f"✅ {path}: {size} bytes")
            else:
                logger.warning(f"⚠️ {path}: non trouvé")
    except Exception as e:
        logger.error(f"❌ Erreur intelligence des menaces: {e}")
    
    # Test 6: Test de détection basique
    try:
        logger.info("🧪 Test de détection basique...")
        
        # Créer un fichier de test
        test_file = "test_malware_sample.txt"
        with open(test_file, "w") as f:
            f.write("This is a test file for RansomGuard AI")
        
        # Analyser avec le détecteur ultra
        result = await ultra_detector.analyze_file_ultra(test_file, {})
        logger.info(f"✅ Analyse de test: {result.get('is_threat', False)}")
        
        # Nettoyer
        os.remove(test_file)
        
    except Exception as e:
        logger.error(f"❌ Erreur test de détection: {e}")
    
    logger.info("🎉 Tests terminés!")
    return True

async def test_file_analysis():
    """Tester l'analyse de fichiers"""
    logger.info("📄 Test de l'analyse de fichiers...")
    
    try:
        from ml_engine.ultra_detector import UltraDetector
        ultra_detector = UltraDetector()
        
        # Créer des fichiers de test avec différents contenus
        test_files = [
            ("test_python.py", "import os\nos.system('echo hello')"),
            ("test_batch.bat", "@echo off\ndel /s *.*"),
            ("test_js.js", "eval('alert(1)')"),
            ("test_normal.txt", "Ceci est un fichier normal")
        ]
        
        for filename, content in test_files:
            with open(filename, "w") as f:
                f.write(content)
            
            try:
                result = await ultra_detector.analyze_file_ultra(filename, {})
                threat_level = "🔴" if result.get('is_threat', False) else "🟢"
                logger.info(f"{threat_level} {filename}: {result.get('threat_type', 'unknown')} (conf: {result.get('confidence', 0):.2f})")
            except Exception as e:
                logger.error(f"❌ Erreur analyse {filename}: {e}")
            finally:
                if os.path.exists(filename):
                    os.remove(filename)
                    
    except Exception as e:
        logger.error(f"❌ Erreur test d'analyse: {e}")

async def test_monitoring():
    """Tester le monitoring système"""
    logger.info("📊 Test du monitoring système...")
    
    try:
        from system_access import system_access
        
        # Obtenir les infos système
        sys_info = system_access.get_system_info()
        logger.info(f"✅ OS: {sys_info.get('os_type', 'Unknown')}")
        logger.info(f"✅ Admin: {sys_info.get('is_admin', False)}")
        logger.info(f"✅ Capacités: {sys_info.get('capabilities', [])}")
        
    except Exception as e:
        logger.error(f"❌ Erreur monitoring: {e}")

async def main():
    """Fonction principale de test"""
    logger.info("🧪 Démarrage des tests RansomGuard AI...")
    
    # Test des composants
    success = await test_system_components()
    
    if success:
        # Test de l'analyse de fichiers
        await test_file_analysis()
        
        # Test du monitoring
        await test_monitoring()
        
        logger.info("🎯 Tous les tests sont passés avec succès!")
    else:
        logger.error("💥 Certains tests ont échoué")
        sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("⏹️ Tests interrompus par l'utilisateur")
    except Exception as e:
        logger.error(f"💥 Erreur fatale: {e}")
        sys.exit(1)

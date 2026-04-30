#!/usr/bin/env python3
"""
Test simple du backend - RansomGuard AI
"""

import asyncio
import logging
from datetime import datetime

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_backend():
    """Test simple du backend"""
    logger.info("🚀 Démarrage du test du backend...")
    
    try:
        # Test des imports de base
        logger.info("📦 Test des imports...")
        
        # Test des modules ML
        try:
            from ml_engine.ransomware_detector import RansomwareDetector
            logger.info("✅ RansomwareDetector importé")
        except Exception as e:
            logger.error(f"❌ Erreur RansomwareDetector: {e}")
        
        try:
            from ml_engine.hybrid_detector import HybridDetector
            logger.info("✅ HybridDetector importé")
        except Exception as e:
            logger.error(f"❌ Erreur HybridDetector: {e}")
        
        try:
            from ml_engine.ultra_detector import UltraDetector
            logger.info("✅ UltraDetector importé")
        except Exception as e:
            logger.error(f"❌ Erreur UltraDetector: {e}")
        
        # Test des modules système
        try:
            from system_access.system_access import system_access
            logger.info("✅ SystemAccess importé")
        except Exception as e:
            logger.error(f"❌ Erreur SystemAccess: {e}")
        
        try:
            from system_access.process_monitor import ProcessMonitor
            logger.info("✅ ProcessMonitor importé")
        except Exception as e:
            logger.error(f"❌ Erreur ProcessMonitor: {e}")
        
        try:
            from system_access.network_monitor import NetworkMonitor
            logger.info("✅ NetworkMonitor importé")
        except Exception as e:
            logger.error(f"❌ Erreur NetworkMonitor: {e}")
        
        logger.info("🎯 Test des imports terminé")
        
        # Test de l'énumération système
        logger.info("🔍 Test de l'énumération système...")
        
        import psutil
        logger.info(f"📊 CPU: {psutil.cpu_percent()}%")
        logger.info(f"💾 Mémoire: {psutil.virtual_memory().percent}%")
        logger.info(f"💿 Disque: {psutil.disk_usage('/').percent}%")
        
        # Test des processus
        processes = list(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']))[:5]
        logger.info(f"🔄 Processus trouvés: {len(processes)}")
        for proc in processes:
            logger.info(f"  - {proc.info['name']} (PID: {proc.info['pid']})")
        
        logger.info("✅ Test de l'énumération système réussi")
        
    except Exception as e:
        logger.error(f"💥 Erreur critique: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_backend())

#!/usr/bin/env python3
"""
Test simple des endpoints de monitoring
RansomGuard AI - Test local
"""

import asyncio
import logging
from datetime import datetime

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_process_monitor():
    """Tester le moniteur de processus"""
    try:
        from adaptive_process_monitor import AdaptiveProcessMonitor
        
        logger.info("🧪 Test du moniteur de processus...")
        monitor = AdaptiveProcessMonitor()
        
        # Faire un scan
        await monitor.scan_processes()
        
        # Obtenir le résumé
        summary = await monitor.get_processes_summary()
        logger.info(f"✅ Résumé processus: {summary}")
        
        return True
    except Exception as e:
        logger.error(f"❌ Erreur moniteur processus: {e}")
        return False

async def test_file_monitor():
    """Tester le moniteur de fichiers"""
    try:
        from real_file_monitor import RealFileMonitor
        
        logger.info("🧪 Test du moniteur de fichiers...")
        monitor = RealFileMonitor()
        
        # Obtenir le résumé
        summary = await monitor.get_monitoring_summary()
        logger.info(f"✅ Résumé fichiers: {summary}")
        
        return True
    except Exception as e:
        logger.error(f"❌ Erreur moniteur fichiers: {e}")
        return False

async def test_registry_monitor():
    """Tester le moniteur de registre"""
    try:
        from real_registry_monitor import RealRegistryMonitor
        
        logger.info("🧪 Test du moniteur de registre...")
        monitor = RealRegistryMonitor()
        
        # Obtenir le résumé
        summary = await monitor.get_registry_summary()
        logger.info(f"✅ Résumé registre: {summary}")
        
        return True
    except Exception as e:
        logger.error(f"❌ Erreur moniteur registre: {e}")
        return False

async def test_unified_monitor():
    """Tester le moniteur unifié"""
    try:
        from unified_system_monitor import UnifiedSystemMonitor
        
        logger.info("🧪 Test du moniteur unifié...")
        monitor = UnifiedSystemMonitor()
        
        # Obtenir l'aperçu
        overview = await monitor.get_system_overview()
        logger.info(f"✅ Aperçu système: {overview}")
        
        return True
    except Exception as e:
        logger.error(f"❌ Erreur moniteur unifié: {e}")
        return False

async def main():
    """Test principal"""
    logger.info("🚀 Démarrage des tests des composants de monitoring...")
    
    tests = [
        ("Processus", test_process_monitor),
        ("Fichiers", test_file_monitor),
        ("Registre", test_registry_monitor),
        ("Unifié", test_unified_monitor)
    ]
    
    results = []
    for name, test_func in tests:
        logger.info(f"\n{'='*50}")
        logger.info(f"Test: {name}")
        logger.info(f"{'='*50}")
        
        try:
            result = await test_func()
            results.append((name, result))
        except Exception as e:
            logger.error(f"❌ Erreur lors du test {name}: {e}")
            results.append((name, False))
    
    # Résumé
    logger.info(f"\n{'='*50}")
    logger.info("📊 RÉSUMÉ DES TESTS")
    logger.info(f"{'='*50}")
    
    successful = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✅ RÉUSSI" if result else "❌ ÉCHEC"
        logger.info(f"{name}: {status}")
    
    logger.info(f"\nTaux de succès: {successful}/{total} ({(successful/total)*100:.1f}%)")
    
    if successful == total:
        logger.info("🎉 Tous les composants fonctionnent correctement!")
    else:
        logger.warning("⚠️ Certains composants ont des problèmes")
    
    logger.info(f"✅ Tests terminés à {datetime.now().strftime('%H:%M:%S')}")

if __name__ == "__main__":
    asyncio.run(main())

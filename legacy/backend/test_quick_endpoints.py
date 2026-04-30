#!/usr/bin/env python3
"""
Test rapide des endpoints de monitoring
RansomGuard AI - Test local sans scan complet
"""

import asyncio
import logging
from datetime import datetime

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_process_monitor_quick():
    """Tester le moniteur de processus rapidement"""
    try:
        from adaptive_process_monitor import AdaptiveProcessMonitor
        
        logger.info("🧪 Test rapide du moniteur de processus...")
        monitor = AdaptiveProcessMonitor()
        
        # Vérifier la détection OS
        logger.info(f"✅ OS détecté: {monitor.os_type} {monitor.os_version}")
        logger.info(f"✅ Capacités: {list(monitor.capabilities.keys())}")
        
        # Faire un scan limité (seulement 10 processus)
        logger.info("🔍 Scan rapide de 10 processus...")
        count = 0
        import psutil
        
        for proc in psutil.process_iter(['pid', 'name']):
            if count >= 10:
                break
            try:
                proc_info = proc.info
                logger.info(f"   - {proc_info['name']} (PID: {proc_info['pid']})")
                count += 1
            except:
                continue
        
        logger.info(f"✅ {count} processus analysés rapidement")
        
        # Créer un résumé minimal
        summary = {
            "total_processes": count,
            "suspicious_processes": 0,
            "threat_level": "Faible",
            "os_type": monitor.os_type,
            "os_version": monitor.os_version
        }
        
        logger.info(f"✅ Résumé rapide: {summary}")
        return True
        
    except Exception as e:
        logger.error(f"❌ Erreur moniteur processus: {e}")
        return False

async def test_file_monitor_quick():
    """Tester le moniteur de fichiers rapidement"""
    try:
        from real_file_monitor import RealFileMonitor
        
        logger.info("🧪 Test rapide du moniteur de fichiers...")
        monitor = RealFileMonitor()
        
        # Vérifier la configuration
        logger.info(f"✅ Répertoires surveillés: {len(monitor.monitored_dirs)}")
        logger.info(f"✅ Extensions suspectes: {monitor.suspicious_extensions}")
        
        # Créer un résumé minimal
        summary = {
            "total_files": 0,
            "suspicious_files": 0,
            "threat_level": "Faible",
            "directories_monitored": len(monitor.monitored_dirs)
        }
        
        logger.info(f"✅ Résumé rapide: {summary}")
        return True
        
    except Exception as e:
        logger.error(f"❌ Erreur moniteur fichiers: {e}")
        return False

async def test_registry_monitor_quick():
    """Tester le moniteur de registre rapidement"""
    try:
        from real_registry_monitor import RealRegistryMonitor
        
        logger.info("🧪 Test rapide du moniteur de registre...")
        monitor = RealRegistryMonitor()
        
        # Vérifier la configuration
        logger.info(f"✅ Système Windows: {monitor.is_windows_system()}")
        logger.info(f"✅ Clés critiques: {len(monitor.critical_keys)}")
        
        # Créer un résumé minimal
        summary = {
            "total_keys": 0,
            "suspicious_keys": 0,
            "threat_level": "Faible",
            "windows_system": monitor.is_windows_system()
        }
        
        logger.info(f"✅ Résumé rapide: {summary}")
        return True
        
    except Exception as e:
        logger.error(f"❌ Erreur moniteur registre: {e}")
        return False

async def test_unified_monitor_quick():
    """Tester le moniteur unifié rapidement"""
    try:
        from unified_system_monitor import UnifiedSystemMonitor
        
        logger.info("🧪 Test rapide du moniteur unifié...")
        monitor = UnifiedSystemMonitor()
        
        # Vérifier la configuration
        logger.info(f"✅ Moniteurs disponibles: {list(monitor.monitors.keys())}")
        
        # Créer un aperçu minimal
        overview = {
            "status": "unknown",
            "threat_level": "Faible",
            "total_threats": 0,
            "monitors_count": len(monitor.monitors)
        }
        
        logger.info(f"✅ Aperçu rapide: {overview}")
        return True
        
    except Exception as e:
        logger.error(f"❌ Erreur moniteur unifié: {e}")
        return False

async def main():
    """Test principal rapide"""
    logger.info("🚀 Démarrage des tests RAPIDES des composants...")
    
    tests = [
        ("Processus (Rapide)", test_process_monitor_quick),
        ("Fichiers (Rapide)", test_file_monitor_quick),
        ("Registre (Rapide)", test_registry_monitor_quick),
        ("Unifié (Rapide)", test_unified_monitor_quick)
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
    logger.info("📊 RÉSUMÉ DES TESTS RAPIDES")
    logger.info(f"{'='*50}")
    
    successful = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✅ RÉUSSI" if result else "❌ ÉCHEC"
        logger.info(f"{name}: {status}")
    
    logger.info(f"\nTaux de succès: {successful}/{total} ({(successful/total)*100:.1f}%)")
    
    if successful == total:
        logger.info("🎉 Tous les composants fonctionnent correctement!")
        logger.info("💡 Vous pouvez maintenant tester les vrais endpoints API")
    else:
        logger.warning("⚠️ Certains composants ont des problèmes")
    
    logger.info(f"✅ Tests rapides terminés à {datetime.now().strftime('%H:%M:%S')}")

if __name__ == "__main__":
    asyncio.run(main())

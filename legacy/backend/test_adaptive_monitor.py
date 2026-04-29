#!/usr/bin/env python3
"""
Test rapide du moniteur de processus adaptatif
RansomGuard AI - Test sans boucle infinie
"""

import asyncio
import logging
from adaptive_process_monitor import AdaptiveProcessMonitor

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_adaptive_monitor():
    """Test rapide du moniteur adaptatif"""
    monitor = AdaptiveProcessMonitor()
    
    logger.info("🧪 Test rapide du moniteur adaptatif...")
    
    # Faire un seul scan au lieu de démarrer la surveillance
    await monitor.scan_processes()
    
    # Obtenir le résumé
    summary = await monitor.get_processes_summary()
    logger.info(f"📊 Résumé: {summary}")
    
    # Afficher les processus suspects détectés
    if monitor.suspicious_processes:
        logger.info("🚨 Processus suspects détectés:")
        for proc in monitor.suspicious_processes:
            logger.info(f"  - {proc.name} (PID: {proc.pid}) - Score: {proc.threat_score:.2f}")
    else:
        logger.info("✅ Aucun processus suspect détecté")
    
    # Afficher quelques processus normaux
    if monitor.processes:
        normal_processes = [p for p in monitor.processes.values() if not p.is_suspicious][:5]
        logger.info("📋 Exemples de processus normaux:")
        for proc in normal_processes:
            logger.info(f"  - {proc.name} (PID: {proc.pid}) - CPU: {proc.cpu_percent:.1f}% - RAM: {proc.memory_percent:.1f}%")
    
    logger.info("✅ Test terminé avec succès!")

async def main():
    await test_adaptive_monitor()

if __name__ == "__main__":
    asyncio.run(main())

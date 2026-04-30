#!/usr/bin/env python3
"""
Test des nouveaux endpoints API de monitoring
RansomGuard AI - Vérification complète
"""

import asyncio
import aiohttp
import json
import logging
from datetime import datetime

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
BASE_URL = "http://localhost:8000"
ENDPOINTS_TO_TEST = [
    "/api/monitoring/processes",
    "/api/monitoring/files", 
    "/api/monitoring/registry",
    "/api/monitoring/unified",
    "/api/monitoring/behavior",
    "/api/health/monitoring",
    "/api/reports/scans"
]

async def test_endpoint(session: aiohttp.ClientSession, endpoint: str):
    """Tester un endpoint spécifique"""
    try:
        logger.info(f"🧪 Test de l'endpoint: {endpoint}")
        
        async with session.get(f"{BASE_URL}{endpoint}") as response:
            if response.status == 200:
                try:
                    data = await response.json()
                    logger.info(f"✅ {endpoint}: Status {response.status}")
                    logger.info(f"   Réponse: {json.dumps(data, indent=2, ensure_ascii=False)}")
                    return True
                except json.JSONDecodeError as e:
                    logger.error(f"❌ {endpoint}: Erreur JSON - {e}")
                    logger.error(f"   Contenu reçu: {await response.text()}")
                    return False
            else:
                logger.error(f"❌ {endpoint}: Status {response.status}")
                logger.error(f"   Erreur: {await response.text()}")
                return False
                
    except Exception as e:
        logger.error(f"❌ {endpoint}: Erreur de connexion - {e}")
        return False

async def test_post_endpoints(session: aiohttp.ClientSession):
    """Tester les endpoints POST"""
    try:
        logger.info("🧪 Test des endpoints POST...")
        
        # Test démarrage monitoring processus
        async with session.post(f"{BASE_URL}/api/monitoring/processes/start") as response:
            if response.status == 200:
                data = await response.json()
                logger.info(f"✅ POST /api/monitoring/processes/start: {data}")
            else:
                logger.error(f"❌ POST /api/monitoring/processes/start: Status {response.status}")
        
        # Test démarrage monitoring unifié
        async with session.post(f"{BASE_URL}/api/monitoring/unified/start") as response:
            if response.status == 200:
                data = await response.json()
                logger.info(f"✅ POST /api/monitoring/unified/start: {data}")
            else:
                logger.error(f"❌ POST /api/monitoring/unified/start: Status {response.status}")
                
    except Exception as e:
        logger.error(f"❌ Erreur test endpoints POST: {e}")

async def main():
    """Test principal de tous les endpoints"""
    logger.info("🚀 Démarrage des tests des endpoints API...")
    
    async with aiohttp.ClientSession() as session:
        # Tester tous les endpoints GET
        results = []
        for endpoint in ENDPOINTS_TO_TEST:
            result = await test_endpoint(session, endpoint)
            results.append(result)
            await asyncio.sleep(0.5)  # Pause entre les tests
        
        # Tester les endpoints POST
        await test_post_endpoints(session)
        
        # Résumé des tests
        successful_tests = sum(results)
        total_tests = len(results)
        
        logger.info(f"\n📊 Résumé des tests:")
        logger.info(f"   Tests réussis: {successful_tests}/{total_tests}")
        logger.info(f"   Taux de succès: {(successful_tests/total_tests)*100:.1f}%")
        
        if successful_tests == total_tests:
            logger.info("🎉 Tous les endpoints fonctionnent correctement!")
        else:
            logger.warning("⚠️ Certains endpoints ont des problèmes")
            
        logger.info(f"✅ Tests terminés à {datetime.now().strftime('%H:%M:%S')}")

if __name__ == "__main__":
    asyncio.run(main())

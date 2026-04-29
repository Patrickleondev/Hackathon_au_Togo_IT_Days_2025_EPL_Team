#!/usr/bin/env python3
"""
Test des endpoints HTTP corrigés
"""

import asyncio
import aiohttp
import json
from datetime import datetime

async def test_endpoint(session, url, name):
    """Tester un endpoint spécifique"""
    try:
        print(f"🔍 Test de {name}...")
        async with session.get(url) as response:
            if response.status == 200:
                data = await response.json()
                print(f"   ✅ {name}: {response.status}")
                print(f"      Status: {data.get('status', 'N/A')}")
                if 'data' in data:
                    print(f"      Données: {len(data['data'])} champs")
                return True
            else:
                print(f"   ❌ {name}: {response.status}")
                text = await response.text()
                print(f"      Erreur: {text[:100]}...")
                return False
    except Exception as e:
        print(f"   ❌ {name}: Erreur - {e}")
        return False

async def main():
    """Test principal des endpoints"""
    print("🚀 Test des endpoints HTTP corrigés...")
    print("=" * 60)
    
    base_url = "http://localhost:8000"
    
    async with aiohttp.ClientSession() as session:
        endpoints = [
            (f"{base_url}/api/health", "Health Check"),
            (f"{base_url}/api/monitoring/processes", "Processes Monitoring"),
            (f"{base_url}/api/monitoring/files", "Files Monitoring"),
            (f"{base_url}/api/monitoring/registry", "Registry Monitoring"),
            (f"{base_url}/api/monitoring/behavior", "Behavior Monitoring"),
            (f"{base_url}/api/health/monitoring", "Monitoring Health")
        ]
        
        results = []
        for url, name in endpoints:
            result = await test_endpoint(session, url, name)
            results.append(result)
            print()
        
        # Résumé
        print("=" * 60)
        print("📊 RÉSUMÉ DES TESTS HTTP:")
        success_count = sum(results)
        total_count = len(results)
        
        if success_count == total_count:
            print("✅ TOUS LES ENDPOINTS FONCTIONNENT!")
        else:
            print(f"⚠️  {success_count}/{total_count} endpoints fonctionnent")
            print("❌ Certains endpoints ont des problèmes")
        
        return success_count == total_count

if __name__ == "__main__":
    try:
        success = asyncio.run(main())
        if success:
            print("\n🎉 Tests terminés avec succès!")
        else:
            print("\n⚠️  Tests terminés avec des erreurs")
    except KeyboardInterrupt:
        print("\n🛑 Tests interrompus par l'utilisateur")
    except Exception as e:
        print(f"\n❌ Erreur fatale: {e}")
        import traceback
        traceback.print_exc()

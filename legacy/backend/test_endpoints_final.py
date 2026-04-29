#!/usr/bin/env python3
"""
Test final des endpoints avec moniteurs système
"""

import asyncio
import sys
from api_endpoints import (
    get_system_monitoring_status,
    safe_get_process_summary,
    safe_get_file_summary,
    safe_get_registry_summary
)

async def test_endpoints_final():
    """Test final des endpoints"""
    print("🚀 Test final des endpoints avec moniteurs système...")
    print("=" * 60)
    
    try:
        # Test 1: Statut des moniteurs système
        print("1️⃣ Statut des moniteurs système...")
        status = get_system_monitoring_status()
        print(f"   📊 Statut: {status}")
        
        # Test 2: Résumé des processus
        print("\n2️⃣ Résumé des processus...")
        process_summary = safe_get_process_summary()
        print(f"   📊 Résumé: {process_summary}")
        
        # Test 3: Résumé des fichiers
        print("\n3️⃣ Résumé des fichiers...")
        file_summary = safe_get_file_summary()
        print(f"   📊 Résumé: {file_summary}")
        
        # Test 4: Résumé du registre
        print("\n4️⃣ Résumé du registre...")
        registry_summary = safe_get_registry_summary()
        print(f"   📊 Résumé: {registry_summary}")
        
        print("\n" + "=" * 60)
        print("📊 RÉSUMÉ FINAL:")
        
        # Vérifier que les données sont récupérées
        has_process_data = process_summary.get("total_processes", 0) > 0
        has_file_data = file_summary.get("total_monitored_directories", 0) > 0
        has_registry_data = registry_summary.get("total_keys", 0) > 0
        
        print(f"   Processus: {'✅' if has_process_data else '❌'} ({process_summary.get('total_processes', 0)})")
        print(f"   Fichiers: {'✅' if has_file_data else '❌'} ({file_summary.get('total_monitored_directories', 0)})")
        print(f"   Registre: {'✅' if has_registry_data else '❌'} ({registry_summary.get('total_keys', 0)})")
        
        total_data = sum([has_process_data, has_file_data, has_registry_data])
        if total_data >= 2:
            print("   🎉 Les endpoints récupèrent maintenant les données!")
        else:
            print("   ⚠️ Certains endpoints n'ont toujours pas de données")
        
        return total_data >= 2
        
    except Exception as e:
        print(f"❌ Erreur: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    try:
        success = asyncio.run(test_endpoints_final())
        if success:
            print("\n🎉 Test réussi! Les endpoints fonctionnent maintenant.")
        else:
            print("\n⚠️ Test partiellement réussi.")
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ Erreur fatale: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

#!/usr/bin/env python3
"""
Test des moniteurs système utilisés par les endpoints
"""

import asyncio
import sys
from api_endpoints import (
    system_file_monitor, system_process_monitor, 
    system_registry_monitor, system_network_monitor,
    get_system_monitoring_status
)

async def test_system_monitors():
    """Tester les moniteurs système"""
    print("🚀 Test des moniteurs système...")
    print("=" * 50)
    
    try:
        # Test 1: Statut général
        print("1️⃣ Statut général des moniteurs...")
        status = get_system_monitoring_status()
        print(f"   📊 Statut: {status}")
        
        # Test 2: Moniteur de fichiers
        print("\n2️⃣ Moniteur de fichiers système...")
        if hasattr(system_file_monitor, 'monitored_paths'):
            paths = system_file_monitor.monitored_paths
            print(f"   ✅ Chemins surveillés: {len(paths)}")
            for path in paths[:3]:  # Afficher les 3 premiers
                print(f"      - {path}")
        else:
            print("   ❌ Attribut 'monitored_paths' non trouvé")
        
        # Test 3: Moniteur de processus
        print("\n3️⃣ Moniteur de processus système...")
        if hasattr(system_process_monitor, 'processes'):
            processes = system_process_monitor.processes
            print(f"   ✅ Processus surveillés: {len(processes)}")
            if processes:
                print(f"      Premier processus: {processes[0]}")
        else:
            print("   ❌ Attribut 'processes' non trouvé")
        
        # Test 4: Moniteur de registre
        print("\n4️⃣ Moniteur de registre système...")
        if system_registry_monitor and hasattr(system_registry_monitor, 'monitored_keys'):
            keys = system_registry_monitor.monitored_keys
            print(f"   ✅ Clés surveillées: {len(keys)}")
        elif system_registry_monitor:
            print("   ⚠️ Moniteur disponible mais pas d'attribut 'monitored_keys'")
        else:
            print("   ❌ Moniteur de registre non disponible")
        
        # Test 5: Moniteur réseau
        print("\n5️⃣ Moniteur réseau système...")
        if hasattr(system_network_monitor, 'interfaces'):
            interfaces = system_network_monitor.interfaces
            print(f"   ✅ Interfaces surveillées: {len(interfaces)}")
        else:
            print("   ❌ Attribut 'interfaces' non trouvé")
        
        print("\n" + "=" * 50)
        print("📊 RÉSUMÉ:")
        active_count = sum(1 for monitor in status.values() if monitor.get('active', False))
        print(f"   Moniteurs actifs: {active_count}/{len(status)}")
        
        if active_count > 0:
            print("   ✅ Les moniteurs système sont disponibles!")
        else:
            print("   ❌ Aucun moniteur système n'est actif")
        
        return active_count > 0
        
    except Exception as e:
        print(f"❌ Erreur: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    try:
        success = asyncio.run(test_system_monitors())
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"❌ Erreur fatale: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

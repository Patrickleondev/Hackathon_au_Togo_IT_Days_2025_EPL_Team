#!/usr/bin/env python3
"""
Test rapide des endpoints problématiques
"""

import asyncio
import sys
from api_endpoints import process_monitor, file_monitor, registry_monitor

async def quick_test():
    """Test rapide des composants"""
    print("🚀 Test rapide des composants...")
    
    try:
        # Test 1: Process Monitor
        print("1️⃣ Test Process Monitor...")
        summary = await process_monitor.get_processes_summary()
        print(f"   ✅ Résumé: {summary['total_processes']} processus")
        
        # Test 2: File Monitor
        print("2️⃣ Test File Monitor...")
        summary = file_monitor.get_monitoring_summary()
        print(f"   ✅ Résumé: {summary['total_monitored_directories']} dossiers")
        
        # Test 3: Registry Monitor
        print("3️⃣ Test Registry Monitor...")
        is_windows = registry_monitor.is_windows_system()
        summary = registry_monitor.get_registry_summary()
        print(f"   ✅ Windows: {is_windows}, Clés: {summary['total_registry_keys']}")
        
        print("✅ Tous les tests ont réussi!")
        return True
        
    except Exception as e:
        print(f"❌ Erreur: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(quick_test())
    sys.exit(0 if success else 1)

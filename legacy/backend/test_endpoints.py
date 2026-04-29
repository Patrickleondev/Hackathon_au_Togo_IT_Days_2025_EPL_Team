#!/usr/bin/env python3
"""
Script de test pour vérifier les endpoints problématiques
"""

import asyncio
import sys
import traceback
from api_endpoints import process_monitor, file_monitor, registry_monitor

async def test_process_monitor():
    """Tester le moniteur de processus"""
    print("🔍 Test du moniteur de processus...")
    try:
        # Test 1: get_processes_summary
        print("  - Test get_processes_summary...")
        summary = await process_monitor.get_processes_summary()
        print(f"    ✅ Résultat: {summary}")
        
        # Test 2: Vérifier les attributs
        print("  - Test des attributs...")
        print(f"    - monitoring_active: {process_monitor.monitoring_active}")
        print(f"    - os_type: {process_monitor.os_type}")
        print(f"    - os_version: {process_monitor.os_version}")
        print(f"    - capabilities: {process_monitor.capabilities}")
        
        return True
    except Exception as e:
        print(f"    ❌ Erreur: {e}")
        traceback.print_exc()
        return False

async def test_file_monitor():
    """Tester le moniteur de fichiers"""
    print("🔍 Test du moniteur de fichiers...")
    try:
        # Test 1: get_monitoring_summary
        print("  - Test get_monitoring_summary...")
        summary = file_monitor.get_monitoring_summary()
        print(f"    ✅ Résultat: {summary}")
        
        # Test 2: Vérifier les attributs
        print("  - Test des attributs...")
        print(f"    - monitoring_active: {file_monitor.monitoring_active}")
        print(f"    - monitored_dirs: {len(file_monitor.monitored_dirs)}")
        print(f"    - suspicious_extensions: {file_monitor.suspicious_extensions}")
        
        return True
    except Exception as e:
        print(f"    ❌ Erreur: {e}")
        traceback.print_exc()
        return False

async def test_registry_monitor():
    """Tester le moniteur de registre"""
    print("🔍 Test du moniteur de registre...")
    try:
        # Test 1: is_windows_system
        print("  - Test is_windows_system...")
        is_windows = registry_monitor.is_windows_system()
        print(f"    ✅ Résultat: {is_windows}")
        
        # Test 2: get_registry_summary
        print("  - Test get_registry_summary...")
        summary = registry_monitor.get_registry_summary()
        print(f"    ✅ Résultat: {summary}")
        
        # Test 3: Vérifier les attributs
        print("  - Test des attributs...")
        print(f"    - monitoring_active: {registry_monitor.monitoring_active}")
        print(f"    - critical_keys: {len(registry_monitor.critical_keys)}")
        
        return True
    except Exception as e:
        print(f"    ❌ Erreur: {e}")
        traceback.print_exc()
        return False

async def test_behavior_monitoring():
    """Tester le monitoring du comportement"""
    print("🔍 Test du monitoring du comportement...")
    try:
        # Test: Analyser les processus suspects
        print("  - Test analyse comportement...")
        suspicious_count = len(process_monitor.suspicious_processes)
        print(f"    ✅ Processus suspects: {suspicious_count}")
        
        # Test: Vérifier les processus
        processes_count = len(process_monitor.processes)
        print(f"    ✅ Total processus: {processes_count}")
        
        return True
    except Exception as e:
        print(f"    ❌ Erreur: {e}")
        traceback.print_exc()
        return False

async def main():
    """Fonction principale de test"""
    print("🚀 Démarrage des tests des endpoints...")
    print("=" * 50)
    
    results = []
    
    # Test du moniteur de processus
    results.append(await test_process_monitor())
    print()
    
    # Test du moniteur de fichiers
    results.append(await test_file_monitor())
    print()
    
    # Test du moniteur de registre
    results.append(await test_registry_monitor())
    print()
    
    # Test du monitoring du comportement
    results.append(await test_behavior_monitoring())
    print()
    
    # Résumé
    print("=" * 50)
    print("📊 RÉSUMÉ DES TESTS:")
    success_count = sum(results)
    total_count = len(results)
    
    if success_count == total_count:
        print("✅ TOUS LES TESTS ONT RÉUSSI!")
    else:
        print(f"⚠️  {success_count}/{total_count} tests ont réussi")
        print("❌ Certains composants ont des problèmes")
    
    return success_count == total_count

if __name__ == "__main__":
    try:
        success = asyncio.run(main())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n🛑 Tests interrompus par l'utilisateur")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Erreur fatale: {e}")
        traceback.print_exc()
        sys.exit(1)

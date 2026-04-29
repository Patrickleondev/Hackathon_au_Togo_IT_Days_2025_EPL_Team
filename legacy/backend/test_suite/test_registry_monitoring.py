"""
Tests pour la surveillance du registre Windows
Vérification des fonctionnalités de détection et de monitoring
"""

import unittest
import asyncio
import tempfile
import os
import sys
import json
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

# Ajouter le chemin du backend
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from system_access.registry_monitor import RegistryMonitor
from system_access.os_detector import OSType

class TestRegistryMonitor(unittest.TestCase):
    """Tests pour la classe RegistryMonitor"""
    
    def setUp(self):
        """Configuration initiale pour chaque test"""
        self.registry_monitor = RegistryMonitor()
        
    def test_initialization(self):
        """Test de l'initialisation du moniteur de registre"""
        self.assertIsInstance(self.registry_monitor, RegistryMonitor)
        self.assertFalse(self.registry_monitor.is_monitoring)
        self.assertEqual(len(self.registry_monitor.registry_callbacks), 0)
        self.assertGreater(len(self.registry_monitor.critical_keys), 0)
        
    def test_critical_keys_definition(self):
        """Test que les clés critiques sont bien définies"""
        critical_keys = self.registry_monitor.critical_keys
        
        # Vérifier que les clés de persistence sont présentes
        persistence_keys = [
            'Run', 'RunOnce', 'RunServices', 'Winlogon',
            'Image File Execution Options', 'Browser Helper Objects'
        ]
        
        for key in persistence_keys:
            self.assertTrue(
                any(key in critical_key for critical_key in critical_keys),
                f"Clé critique '{key}' manquante"
            )
    
    def test_add_callback(self):
        """Test de l'ajout de callbacks"""
        callback = Mock()
        self.registry_monitor.add_callback(callback)
        
        self.assertIn(callback, self.registry_monitor.registry_callbacks)
        self.assertEqual(len(self.registry_monitor.registry_callbacks), 1)
    
    def test_add_monitored_key(self):
        """Test de l'ajout de clés à surveiller"""
        test_key = r"HKEY_CURRENT_USER\Software\Test\Key"
        
        self.registry_monitor.add_monitored_key(test_key)
        self.assertIn(test_key, self.registry_monitor.monitored_keys)
    
    def test_compare_registry_states(self):
        """Test de la comparaison d'états de registre"""
        old_state = {
            'values': {'key1': {'value': 'old_value', 'type': 1}},
            'subkeys': ['subkey1']
        }
        
        new_state = {
            'values': {
                'key1': {'value': 'new_value', 'type': 1},
                'key2': {'value': 'new_key', 'type': 1}
            },
            'subkeys': ['subkey1', 'subkey2']
        }
        
        changes = self.registry_monitor._compare_registry_states(old_state, new_state)
        
        # Vérifier que les changements sont détectés
        change_types = [change['type'] for change in changes]
        self.assertIn('value_modified', change_types)
        self.assertIn('value_added', change_types)
        self.assertIn('subkey_added', change_types)
    
    def test_suspicious_change_detection(self):
        """Test de la détection de changements suspects"""
        # Test avec une clé de persistence
        key_path = r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"
        change = {
            'type': 'value_added',
            'name': 'suspicious_app',
            'value': 'powershell.exe -Command "Invoke-Expression"'
        }
        
        is_suspicious = self.registry_monitor._is_suspicious_change(key_path, change)
        self.assertTrue(is_suspicious, "Changement avec PowerShell suspect non détecté")
        
        # Test avec une clé normale
        normal_key = r"HKEY_CURRENT_USER\Software\Normal\App"
        normal_change = {
            'type': 'value_added',
            'name': 'normal_setting',
            'value': 'normal_value'
        }
        
        is_suspicious = self.registry_monitor._is_suspicious_change(normal_key, normal_change)
        self.assertFalse(is_suspicious, "Changement normal détecté comme suspect")
    
    def test_get_monitoring_stats(self):
        """Test de la récupération des statistiques de monitoring"""
        # Ajouter quelques événements simulés
        self.registry_monitor.registry_history['test_key'] = [
            {
                'timestamp': datetime.now().isoformat(),
                'key_path': 'test_key',
                'change': {'type': 'value_added', 'name': 'test'},
                'suspicious': True
            }
        ]
        
        stats = self.registry_monitor.get_monitoring_stats()
        
        self.assertIsInstance(stats, dict)
        self.assertIn('is_monitoring', stats)
        self.assertIn('monitored_keys_count', stats)
        self.assertIn('total_events', stats)
        self.assertIn('suspicious_events', stats)
        self.assertEqual(stats['suspicious_events'], 1)
    
    @patch('system_access.registry_monitor.system_access.os_type', OSType.WINDOWS)
    @patch('system_access.registry_monitor.winreg')
    @patch('system_access.registry_monitor.win32api')
    @patch('system_access.registry_monitor.win32con')
    @patch('system_access.registry_monitor.win32event')
    def test_windows_specific_functionality(self, mock_win32event, mock_win32con, mock_win32api, mock_winreg):
        """Test des fonctionnalités spécifiques à Windows"""
        # Mock des modules Windows
        mock_winreg.HKEY_CURRENT_USER = 0x80000001
        mock_winreg.HKEY_LOCAL_MACHINE = 0x80000002
        mock_winreg.KEY_READ = 0x20019
        mock_winreg.KEY_NOTIFY = 0x0010
        
        mock_win32con.REG_NOTIFY_CHANGE_NAME = 0x00000001
        mock_win32con.REG_NOTIFY_CHANGE_ATTRIBUTES = 0x00000002
        mock_win32con.REG_NOTIFY_CHANGE_LAST_SET = 0x00000004
        mock_win32con.REG_NOTIFY_CHANGE_SECURITY = 0x00000008
        mock_win32con.WAIT_OBJECT_0 = 0
        
        # Mock de l'événement
        mock_event = Mock()
        mock_win32event.CreateEvent.return_value = mock_event
        
        # Mock de la clé de registre
        mock_key = Mock()
        mock_winreg.OpenKey.return_value = mock_key
        
        # Mock de l'énumération des valeurs
        mock_winreg.EnumValue.side_effect = [
            ('value1', 'data1', 1),
            ('value2', 'data2', 1),
            WindowsError()  # Fin de l'énumération
        ]
        
        # Mock de l'énumération des sous-clés
        mock_winreg.EnumKey.side_effect = [
            'subkey1',
            'subkey2',
            WindowsError()  # Fin de l'énumération
        ]
        
        # Test de la capture d'état
        state = asyncio.run(self.registry_monitor._capture_registry_state(
            mock_winreg.HKEY_CURRENT_USER, 'test\\subkey'
        ))
        
        self.assertIn('values', state)
        self.assertIn('subkeys', state)
        self.assertEqual(len(state['values']), 2)
        self.assertEqual(len(state['subkeys']), 2)
    
    def test_non_windows_os(self):
        """Test du comportement sur les OS non-Windows"""
        with patch('system_access.registry_monitor.system_access.os_type', OSType.LINUX):
            monitor = RegistryMonitor()
            
            # Sur Linux, la surveillance ne devrait pas être disponible
            self.assertFalse(monitor.registry_available)
    
    def test_error_handling(self):
        """Test de la gestion des erreurs"""
        # Test avec des données invalides
        invalid_state = None
        valid_state = {'values': {}, 'subkeys': []}
        
        # La comparaison devrait gérer les états invalides
        try:
            changes = self.registry_monitor._compare_registry_states(invalid_state, valid_state)
            # Si on arrive ici, c'est que l'erreur est gérée
            self.assertIsInstance(changes, list)
        except Exception as e:
            self.fail(f"La gestion d'erreur a échoué: {e}")

class TestRegistryMonitoringIntegration(unittest.TestCase):
    """Tests d'intégration pour la surveillance du registre"""
    
    def setUp(self):
        """Configuration pour les tests d'intégration"""
        self.registry_monitor = RegistryMonitor()
    
    def test_full_monitoring_workflow(self):
        """Test du workflow complet de surveillance"""
        # 1. Ajouter un callback
        callback_called = False
        callback_data = None
        
        def test_callback(event):
            nonlocal callback_called, callback_data
            callback_called = True
            callback_data = event
        
        self.registry_monitor.add_callback(test_callback)
        
        # 2. Ajouter une clé à surveiller
        test_key = r"HKEY_CURRENT_USER\Software\Test\Monitoring"
        self.registry_monitor.add_monitored_key(test_key)
        
        # 3. Simuler un événement
        test_event = {
            'timestamp': datetime.now().isoformat(),
            'key_path': test_key,
            'change': {
                'type': 'value_added',
                'name': 'test_value',
                'value': 'test_data'
            },
            'suspicious': False
        }
        
        # 4. Traiter l'événement
        asyncio.run(self.registry_monitor._handle_registry_changes(test_key, [test_event['change']]))
        
        # 5. Vérifier que le callback a été appelé
        self.assertTrue(callback_called, "Le callback n'a pas été appelé")
        self.assertIsNotNone(callback_data, "Les données du callback sont nulles")
        
        # 6. Vérifier l'historique
        history = self.registry_monitor.get_registry_history(test_key)
        self.assertGreater(len(history), 0, "L'historique est vide")
    
    def test_suspicious_pattern_detection(self):
        """Test de la détection de patterns suspects"""
        suspicious_patterns = [
            'powershell.exe -Command "Invoke-Expression"',
            'cmd.exe /c "certutil -decode"',
            'wscript.exe suspicious.vbs',
            'rundll32.exe malicious.dll',
            'http://malicious.com/payload.exe',
            'C:\\temp\\suspicious.bat'
        ]
        
        key_path = r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"
        
        for pattern in suspicious_patterns:
            change = {
                'type': 'value_added',
                'name': 'suspicious_entry',
                'value': pattern
            }
            
            is_suspicious = self.registry_monitor._is_suspicious_change(key_path, change)
            self.assertTrue(is_suspicious, f"Pattern suspect non détecté: {pattern}")

if __name__ == '__main__':
    # Configuration pour les tests asynchrones
    unittest.main()

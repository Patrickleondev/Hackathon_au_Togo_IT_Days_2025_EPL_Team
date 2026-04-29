"""
Module d'accès système privilégié pour RansomGuard AI
"""

from .os_detector import SystemAccessManager, OSType, system_access
from .file_monitor import FileSystemMonitor
from .process_monitor import ProcessMonitor
from .network_monitor import NetworkMonitor

# Import conditionnel du RegistryMonitor avec gestion d'erreur robuste
try:
    from .registry_monitor import RegistryMonitor
    REGISTRY_MONITOR_AVAILABLE = True
except ImportError as e:
    import logging
    logger = logging.getLogger(__name__)
    logger.warning(f"RegistryMonitor non disponible: {e}")
    RegistryMonitor = None
    REGISTRY_MONITOR_AVAILABLE = False
    
try:
    from .log_collector import SystemLogCollector
    LOG_COLLECTOR_AVAILABLE = True
except ImportError as e:
    import logging
    logger = logging.getLogger(__name__)
    logger.warning(f"SystemLogCollector non disponible: {e}")
    SystemLogCollector = None
    LOG_COLLECTOR_AVAILABLE = False

__all__ = [
    'SystemAccessManager',
    'OSType', 
    'system_access',
    'FileSystemMonitor',
    'ProcessMonitor',
    'NetworkMonitor',
    'RegistryMonitor',
    'SystemLogCollector',
    'REGISTRY_MONITOR_AVAILABLE',
    'LOG_COLLECTOR_AVAILABLE'
]

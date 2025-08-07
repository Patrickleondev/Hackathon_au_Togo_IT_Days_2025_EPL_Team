"""
Configuration de l'application RansomGuard AI
Hackathon Togo IT Days 2025
"""

import os
from typing import Optional
from pydantic import BaseModel

class Settings:
    """Configuration de l'application"""
    
    def __init__(self):
        # Informations de base
        self.APP_NAME: str = "RansomGuard AI"
        self.APP_VERSION: str = "1.0.0"
        self.APP_DESCRIPTION: str = "Protection intelligente contre les ransomware avec IA"
        
        # Configuration du serveur
        self.HOST: str = "0.0.0.0"
        self.PORT: int = 8000
        self.DEBUG: bool = False
        
        # Configuration de la base de données
        self.DATABASE_URL: str = "sqlite:///./ransomguard.db"
        
        # Configuration de sécurité
        self.SECRET_KEY: str = "your-secret-key-here-change-in-production"
        self.ALGORITHM: str = "HS256"
        self.ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
        
        # Configuration IA/ML
        self.MODEL_PATH: str = "models/"
        self.CONFIDENCE_THRESHOLD: float = 0.7
        self.MAX_FILE_SIZE: int = 100 * 1024 * 1024  # 100MB
        self.SCAN_TIMEOUT: int = 300  # 5 minutes
        
        # Configuration du monitoring
        self.MONITORING_INTERVAL: int = 1  # secondes
        self.MAX_PROCESS_HISTORY: int = 100
        self.MAX_FILE_HISTORY: int = 50
        self.MAX_NETWORK_HISTORY: int = 1000
        
        # Configuration des alertes
        self.ALERT_RETENTION_DAYS: int = 30
        self.MAX_ALERTS_PER_HOUR: int = 100
        
        # Configuration des scans
        self.QUICK_SCAN_LIMIT: int = 1000
        self.FULL_SCAN_LIMIT: int = 10000
        self.CUSTOM_SCAN_LIMIT: int = 5000
        
        # Configuration des langues
        self.DEFAULT_LANGUAGE: str = "fr"
        self.SUPPORTED_LANGUAGES: list = ["fr", "en", "es"]
        
        # Configuration des logs
        self.LOG_LEVEL: str = "INFO"
        self.LOG_FILE: str = "logs/ransomguard.log"
        self.LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        
        # Configuration des performances
        self.MAX_CONCURRENT_SCANS: int = 3
        self.MAX_CONCURRENT_DOWNLOADS: int = 5
        self.CACHE_TTL: int = 3600  # 1 heure
        
        # Configuration de la quarantaine
        self.QUARANTINE_DIR: str = "quarantine/"
        self.QUARANTINE_MAX_SIZE: int = 1024 * 1024 * 1024  # 1GB
        
        # Configuration des modèles IA
        self.ENABLE_RANDOM_FOREST: bool = True
        self.ENABLE_SVM: bool = True
        self.ENABLE_NEURAL_NETWORK: bool = True
        
        # Configuration des métriques
        self.ENABLE_METRICS: bool = True
        self.METRICS_INTERVAL: int = 60  # secondes
        
        # Configuration de l'optimisation énergétique
        self.LOW_POWER_MODE: bool = False
        self.CPU_THROTTLE_THRESHOLD: float = 0.8
        self.MEMORY_THROTTLE_THRESHOLD: float = 0.9

# Instance globale des paramètres
settings = Settings()

# Configuration des chemins
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
LOGS_DIR = os.path.join(BASE_DIR, "logs")
MODELS_DIR = os.path.join(BASE_DIR, settings.MODEL_PATH)
QUARANTINE_DIR = os.path.join(BASE_DIR, settings.QUARANTINE_DIR)

# Création des dossiers nécessaires
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

# Configuration des langues
TRANSLATIONS = {
    "fr": {
        "app_name": "RansomGuard AI",
        "dashboard": "Tableau de bord",
        "threats": "Menaces détectées",
        "scan": "Scanner le système",
        "statistics": "Statistiques",
        "settings": "Paramètres",
        "protection_active": "Protection active",
        "system_protected": "Système protégé",
        "threat_detected": "Menace détectée",
        "scan_complete": "Scan terminé",
        "quarantine_success": "Mise en quarantaine réussie",
        "error_occurred": "Une erreur s'est produite",
        "loading": "Chargement...",
        "no_threats": "Aucune menace détectée",
        "start_scan": "Démarrer le scan",
        "stop_scan": "Arrêter le scan",
        "quick_scan": "Scan rapide",
        "full_scan": "Scan complet",
        "custom_scan": "Scan personnalisé",
        "high_severity": "Élevée",
        "medium_severity": "Moyenne",
        "low_severity": "Faible",
        "ransomware": "Ransomware",
        "malware": "Malware",
        "spyware": "Spyware",
        "other": "Autre"
    },
    "en": {
        "app_name": "RansomGuard AI",
        "dashboard": "Dashboard",
        "threats": "Detected Threats",
        "scan": "Scan System",
        "statistics": "Statistics",
        "settings": "Settings",
        "protection_active": "Protection Active",
        "system_protected": "System Protected",
        "threat_detected": "Threat Detected",
        "scan_complete": "Scan Complete",
        "quarantine_success": "Quarantine Successful",
        "error_occurred": "An error occurred",
        "loading": "Loading...",
        "no_threats": "No threats detected",
        "start_scan": "Start Scan",
        "stop_scan": "Stop Scan",
        "quick_scan": "Quick Scan",
        "full_scan": "Full Scan",
        "custom_scan": "Custom Scan",
        "high_severity": "High",
        "medium_severity": "Medium",
        "low_severity": "Low",
        "ransomware": "Ransomware",
        "malware": "Malware",
        "spyware": "Spyware",
        "other": "Other"
    },
    "es": {
        "app_name": "RansomGuard AI",
        "dashboard": "Panel de control",
        "threats": "Amenazas detectadas",
        "scan": "Escanear sistema",
        "statistics": "Estadísticas",
        "settings": "Configuración",
        "protection_active": "Protección activa",
        "system_protected": "Sistema protegido",
        "threat_detected": "Amenaza detectada",
        "scan_complete": "Escaneo completo",
        "quarantine_success": "Cuarentena exitosa",
        "error_occurred": "Ocurrió un error",
        "loading": "Cargando...",
        "no_threats": "No se detectaron amenazas",
        "start_scan": "Iniciar escaneo",
        "stop_scan": "Detener escaneo",
        "quick_scan": "Escaneo rápido",
        "full_scan": "Escaneo completo",
        "custom_scan": "Escaneo personalizado",
        "high_severity": "Alta",
        "medium_severity": "Media",
        "low_severity": "Baja",
        "ransomware": "Ransomware",
        "malware": "Malware",
        "spyware": "Spyware",
        "other": "Otro"
    }
}

def get_translation(key: str, language: str = "fr") -> str:
    """Obtenir une traduction"""
    return TRANSLATIONS.get(language, TRANSLATIONS["fr"]).get(key, key)

def get_supported_languages() -> list:
    """Obtenir la liste des langues supportées"""
    return list(TRANSLATIONS.keys())

# Configuration des métriques par défaut
DEFAULT_METRICS = {
    "detection_rate": 0.95,
    "false_positive_rate": 0.02,
    "scan_speed": 1000,  # fichiers par seconde
    "memory_usage": 200,  # MB
    "cpu_usage": 5.0,  # %
    "response_time": 100,  # ms
}

# Configuration des seuils d'alerte
ALERT_THRESHOLDS = {
    "cpu_usage": 90.0,
    "memory_usage": 90.0,
    "disk_usage": 95.0,
    "network_connections": 1000,
    "file_access_frequency": 10,
    "process_activity": 5,
}

# Configuration des patterns de détection
DETECTION_PATTERNS = {
    "suspicious_extensions": [
        ".encrypted", ".locked", ".crypto", ".ransom",
        ".bitcoin", ".wallet", ".miner", ".cryptominer"
    ],
    "suspicious_names": [
        "readme", "decrypt", "pay", "bitcoin", "wallet",
        "ransom", "encrypt", "crypto", "lock", "unlock"
    ],
    "suspicious_processes": [
        "encrypt", "crypt", "lock", "ransom", "wanna", "crypto",
        "bitcoin", "wallet", "miner", "cryptominer"
    ],
    "suspicious_ports": [22, 23, 3389, 5900, 8080, 4444, 6667],
    "suspicious_ips": [
        "192.168.1.100",  # Exemple
        "10.0.0.1"  # Exemple
    ]
}

# Configuration des modèles IA
AI_MODELS_CONFIG = {
    "random_forest": {
        "n_estimators": 100,
        "max_depth": 10,
        "random_state": 42,
        "n_jobs": -1
    },
    "svm": {
        "kernel": "rbf",
        "probability": True,
        "random_state": 42
    },
    "neural_network": {
        "layers": [64, 32, 16],
        "dropout": [0.3, 0.2],
        "activation": "relu",
        "optimizer": "adam",
        "loss": "binary_crossentropy",
        "metrics": ["accuracy"]
    }
}

# Configuration des caractéristiques
FEATURE_CONFIG = {
    "file_features": [
        "file_entropy", "file_size", "file_extension",
        "encryption_indicators", "file_access_frequency",
        "file_creation_time", "file_modification_time"
    ],
    "process_features": [
        "process_cpu_usage", "process_memory_usage",
        "network_connections", "registry_changes"
    ],
    "system_features": [
        "cpu_usage", "memory_usage", "disk_usage",
        "network_io", "active_processes"
    ]
} 
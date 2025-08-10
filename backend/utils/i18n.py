# -*- coding: utf-8 -*-
"""
Module d'internationalisation pour RansomGuard AI
Support pour Français, Anglais et Ewe
"""

from typing import Dict, Any
import os
import json

class I18nManager:
    """Gestionnaire d'internationalisation"""
    
    def __init__(self):
        self.current_language = "en"  # Langue par défaut passée à l'anglais
        self.translations = {}
        self.load_translations()
    
    def load_translations(self):
        """Charger les traductions depuis les dictionnaires"""
        
        # Traductions françaises
        self.translations["fr"] = {
            "system": {
                "status": "Statut",
                "active": "Actif",
                "inactive": "Inactif",
                "threats_detected": "Menaces détectées",
                "files_protected": "Fichiers protégés",
                "last_scan": "Dernier scan",
                "cpu_usage": "Utilisation CPU",
                "memory_usage": "Utilisation mémoire",
                "hybrid_system": "Système hybride"
            },
            "threats": {
                "ransomware_detected": "Ransomware détecté",
                "suspicious_executable": "Exécutable suspect",
                "file_signature_mismatch": "Signature de fichier incorrecte",
                "suspicious_network_activity": "Activité réseau suspecte",
                "suspicious_behavior": "Comportement suspect",
                "encrypted_content": "Contenu chiffré",
                "threat_detected": "Menace détectée par l'IA",
                "suspicious_activity": "Activité suspecte détectée",
                "severity_low": "Faible",
                "severity_medium": "Moyen",
                "severity_high": "Élevé",
                "quarantined": "Mis en quarantaine",
                "detected": "Détecté",
                "monitoring": "Surveillance"
            },
            "scan": {
                "quick_scan": "Scan rapide",
                "full_scan": "Scan complet",
                "network_scan": "Scan réseau",
                "scan_started": "Scan démarré avec succès",
                "scan_completed": "Scan terminé",
                "scan_running": "Scan en cours",
                "files_scanned": "fichiers scannés",
                "threats_found": "menaces trouvées"
            },
            "analysis": {
                "file_analysis": "Analyse de fichier",
                "threat_detected": "Menace détectée",
                "no_threat": "Aucune menace",
                "confidence": "Confiance",
                "file_size": "Taille du fichier",
                "file_type": "Type de fichier",
                "entropy": "Entropie",
                "analysis_method": "Méthode d'analyse"
            },
            "ui": {
                "dashboard": "Tableau de bord",
                "threats": "Menaces",
                "scan": "Scanner",
                "settings": "Paramètres",
                "statistics": "Statistiques",
                "upload_file": "Télécharger un fichier",
                "language": "Langue",
                "save": "Enregistrer",
                "cancel": "Annuler",
                "delete": "Supprimer",
                "refresh": "Actualiser"
            }
        }
        
        # Traductions anglaises
        self.translations["en"] = {
            "system": {
                "status": "Status",
                "active": "Active",
                "inactive": "Inactive",
                "threats_detected": "Threats detected",
                "files_protected": "Files protected",
                "last_scan": "Last scan",
                "cpu_usage": "CPU usage",
                "memory_usage": "Memory usage",
                "hybrid_system": "Hybrid system"
            },
            "threats": {
                "ransomware_detected": "Ransomware detected",
                "suspicious_executable": "Suspicious executable",
                "file_signature_mismatch": "File signature mismatch",
                "suspicious_network_activity": "Suspicious network activity",
                "suspicious_behavior": "Suspicious behavior",
                "encrypted_content": "Encrypted content",
                "threat_detected": "Threat detected by AI",
                "suspicious_activity": "Suspicious activity detected",
                "severity_low": "Low",
                "severity_medium": "Medium",
                "severity_high": "High",
                "quarantined": "Quarantined",
                "detected": "Detected",
                "monitoring": "Monitoring"
            },
            "scan": {
                "quick_scan": "Quick scan",
                "full_scan": "Full scan",
                "network_scan": "Network scan",
                "scan_started": "Scan started successfully",
                "scan_completed": "Scan completed",
                "scan_running": "Scan running",
                "files_scanned": "files scanned",
                "threats_found": "threats found"
            },
            "analysis": {
                "file_analysis": "File analysis",
                "threat_detected": "Threat detected",
                "no_threat": "No threat",
                "confidence": "Confidence",
                "file_size": "File size",
                "file_type": "File type",
                "entropy": "Entropy",
                "analysis_method": "Analysis method"
            },
            "ui": {
                "dashboard": "Dashboard",
                "threats": "Threats",
                "scan": "Scan",
                "settings": "Settings",
                "statistics": "Statistics",
                "upload_file": "Upload file",
                "language": "Language",
                "save": "Save",
                "cancel": "Cancel",
                "delete": "Delete",
                "refresh": "Refresh"
            }
        }
        
        # Traductions Ewe (langue du Togo)
        self.translations["ee"] = {
            "system": {
                "status": "Nɔnɔme",
                "active": "Le dɔwɔm",
                "inactive": "Mele dɔwɔm o",
                "threats_detected": "Ŋutasẽ siwo wokpɔ",
                "files_protected": "Nyatakakadzraɖoƒe siwo woŋlɔ",
                "last_scan": "Nudidi mamlea",
                "cpu_usage": "CPU zazã",
                "memory_usage": "Memory zazã",
                "hybrid_system": "System wowɔɖeka"
            },
            "threats": {
                "ransomware_detected": "Wokpɔ ransomware",
                "suspicious_executable": "Nyatakakadzraɖoƒe vɔ̃ɖi",
                "file_signature_mismatch": "Nyatakakadzraɖoƒe dzesi mesɔ o",
                "suspicious_network_activity": "Network dɔwɔna vɔ̃ɖi",
                "suspicious_behavior": "Nuwɔna vɔ̃ɖi",
                "encrypted_content": "Nu siwo woɣla",
                "threat_detected": "AI kpɔ ŋutasẽ",
                "suspicious_activity": "Wokpɔ nuwɔna vɔ̃ɖi",
                "severity_low": "Ɖe bɔbɔe",
                "severity_medium": "Titina",
                "severity_high": "Kɔkɔ",
                "quarantined": "Woɖe ɖe aga",
                "detected": "Wokpɔe",
                "monitoring": "Wole ŋku lém"
            },
            "scan": {
                "quick_scan": "Nudidi kabakaba",
                "full_scan": "Nudidi bliboa",
                "network_scan": "Network nudidi",
                "scan_started": "Nudidi dze egɔme nyuie",
                "scan_completed": "Nudidi wu enu",
                "scan_running": "Nudidi le edzi yim",
                "files_scanned": "nyatakakadzraɖoƒe siwo wodidi",
                "threats_found": "ŋutasẽ siwo wokpɔ"
            },
            "analysis": {
                "file_analysis": "Nyatakakadzraɖoƒe dzodzro",
                "threat_detected": "Wokpɔ ŋutasẽ",
                "no_threat": "Ŋutasẽ aɖeke meli o",
                "confidence": "Dzideƒo",
                "file_size": "Nyatakakadzraɖoƒe lolome",
                "file_type": "Nyatakakadzraɖoƒe ƒomevi",
                "entropy": "Entropy",
                "analysis_method": "Dzodzro ƒomevi"
            },
            "ui": {
                "dashboard": "Nudzodzro teƒe",
                "threats": "Ŋutasẽwo",
                "scan": "Didi",
                "settings": "Ɖoɖowo",
                "statistics": "Akɔntabuwo",
                "upload_file": "Nyatakakadzraɖoƒe dɔdɔ",
                "language": "Gbe",
                "save": "Dzra ɖo",
                "cancel": "Gbe",
                "delete": "Tutui",
                "refresh": "Yeyee"
            }
        }
    
    def set_language(self, language_code: str):
        """Changer la langue actuelle"""
        if language_code in self.translations:
            self.current_language = language_code
            return True
        return False
    
    def get_language(self) -> str:
        """Obtenir la langue actuelle"""
        return self.current_language
    
    def t(self, key: str, **kwargs) -> str:
        """Traduire une clé dans la langue actuelle"""
        try:
            # Séparer la clé en parties (ex: "system.status")
            keys = key.split(".")
            translation = self.translations[self.current_language]
            
            for k in keys:
                translation = translation[k]
            
            # Remplacer les placeholders si des kwargs sont fournis
            if kwargs:
                return translation.format(**kwargs)
            
            return translation
        except (KeyError, TypeError):
            # Retourner la clé si la traduction n'existe pas
            return key
    
    def get_available_languages(self) -> Dict[str, str]:
        """Obtenir la liste des langues disponibles"""
        return {
            "fr": "Français",
            "en": "English", 
            "ee": "Eʋegbe"
        }
    
    def translate_threat_type(self, threat_type: str) -> str:
        """Traduire un type de menace"""
        threat_key = f"threats.{threat_type}"
        return self.t(threat_key)
    
    def translate_severity(self, severity: str) -> str:
        """Traduire un niveau de sévérité"""
        severity_key = f"threats.severity_{severity}"
        return self.t(severity_key)

# Instance globale du gestionnaire
i18n = I18nManager()
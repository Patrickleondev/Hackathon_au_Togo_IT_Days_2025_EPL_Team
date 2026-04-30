#!/usr/bin/env python3
"""
Générateur de rapports de scan détaillés pour RansomGuard AI
Permet aux utilisateurs de lire les détails des scans qu'ils ont lancés
"""

import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ScanReportGenerator:
    def __init__(self, reports_dir: str = "scan_reports"):
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(exist_ok=True)
        self.current_scan_id = None
        
    def generate_scan_id(self) -> str:
        """Génère un ID unique pour le scan"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"scan_{timestamp}"
    
    def create_scan_report(self, scan_type: str, target: str = "system") -> str:
        """Crée un nouveau rapport de scan"""
        self.current_scan_id = self.generate_scan_id()
        report_file = self.reports_dir / f"{self.current_scan_id}.json"
        
        initial_report = {
            "scan_id": self.current_scan_id,
            "scan_type": scan_type,
            "target": target,
            "start_time": datetime.now().isoformat(),
            "status": "running",
            "progress": 0,
            "results": {},
            "threats_detected": [],
            "recommendations": [],
            "system_info": self._get_system_info(),
            "scan_configuration": self._get_default_scan_config()
        }
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(initial_report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"📄 Nouveau rapport de scan créé: {report_file}")
        return self.current_scan_id
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Récupère les informations système"""
        try:
            import platform
            import psutil
            
            return {
                "platform": platform.platform(),
                "python_version": sys.version,
                "cpu_count": psutil.cpu_count(),
                "memory_total": f"{psutil.virtual_memory().total / (1024**3):.2f} GB",
                "disk_usage": self._get_disk_usage(),
                "timestamp": datetime.now().isoformat()
            }
        except ImportError:
            return {
                "platform": "Unknown",
                "python_version": sys.version,
                "timestamp": datetime.now().isoformat()
            }
    
    def _get_disk_usage(self) -> Dict[str, str]:
        """Récupère l'utilisation du disque"""
        try:
            import psutil
            
            disk_usage = {}
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disk_usage[partition.device] = {
                        "total": f"{usage.total / (1024**3):.2f} GB",
                        "used": f"{usage.used / (1024**3):.2f} GB",
                        "free": f"{usage.free / (1024**3):.2f} GB",
                        "percent": f"{usage.percent:.1f}%"
                    }
                except PermissionError:
                    continue
            
            return disk_usage
        except ImportError:
            return {}
    
    def _get_default_scan_config(self) -> Dict[str, Any]:
        """Configuration par défaut du scan"""
        return {
            "scan_depth": "comprehensive",
            "include_system_files": True,
            "include_hidden_files": True,
            "max_file_size": "100MB",
            "scan_timeout": 3600,
            "ml_models_enabled": True,
            "real_time_monitoring": True
        }
    
    def update_scan_progress(self, progress: int, status: str = None):
        """Met à jour le progrès du scan"""
        if not self.current_scan_id:
            logger.warning("⚠️ Aucun scan en cours")
            return
        
        report_file = self.reports_dir / f"{self.current_scan_id}.json"
        
        try:
            with open(report_file, 'r', encoding='utf-8') as f:
                report = json.load(f)
            
            report["progress"] = progress
            if status:
                report["status"] = status
            report["last_update"] = datetime.now().isoformat()
            
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            logger.error(f"❌ Erreur lors de la mise à jour du progrès: {e}")
    
    def add_scan_results(self, component: str, results: Dict[str, Any]):
        """Ajoute les résultats d'un composant au rapport"""
        if not self.current_scan_id:
            logger.warning("⚠️ Aucun scan en cours")
            return
        
        report_file = self.reports_dir / f"{self.current_scan_id}.json"
        
        try:
            with open(report_file, 'r', encoding='utf-8') as f:
                report = json.load(f)
            
            if "results" not in report:
                report["results"] = {}
            
            report["results"][component] = {
                "timestamp": datetime.now().isoformat(),
                "data": results
            }
            
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            logger.error(f"❌ Erreur lors de l'ajout des résultats: {e}")
    
    def add_threat_detected(self, threat: Dict[str, Any]):
        """Ajoute une menace détectée au rapport"""
        if not self.current_scan_id:
            logger.warning("⚠️ Aucun scan en cours")
            return
        
        report_file = self.reports_dir / f"{self.current_scan_id}.json"
        
        try:
            with open(report_file, 'r', encoding='utf-8') as f:
                report = json.load(f)
            
            if "threats_detected" not in report:
                report["threats_detected"] = []
            
            threat["detection_time"] = datetime.now().isoformat()
            threat["scan_id"] = self.current_scan_id
            report["threats_detected"].append(threat)
            
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            logger.error(f"❌ Erreur lors de l'ajout de la menace: {e}")
    
    def add_recommendation(self, recommendation: Dict[str, Any]):
        """Ajoute une recommandation au rapport"""
        if not self.current_scan_id:
            logger.warning("⚠️ Aucun scan en cours")
            return
        
        report_file = self.reports_dir / f"{self.current_scan_id}.json"
        
        try:
            with open(report_file, 'r', encoding='utf-8') as f:
                report = json.load(f)
            
            if "recommendations" not in report:
                report["recommendations"] = []
            
            recommendation["timestamp"] = datetime.now().isoformat()
            recommendation["scan_id"] = self.current_scan_id
            report["recommendations"].append(recommendation)
            
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            logger.error(f"❌ Erreur lors de l'ajout de la recommandation: {e}")
    
    def finalize_scan_report(self, final_status: str = "completed"):
        """Finalise le rapport de scan"""
        if not self.current_scan_id:
            logger.warning("⚠️ Aucun scan en cours")
            return
        
        report_file = self.reports_dir / f"{self.current_scan_id}.json"
        
        try:
            with open(report_file, 'r', encoding='utf-8') as f:
                report = json.load(f)
            
            report["status"] = final_status
            report["end_time"] = datetime.now().isoformat()
            report["duration"] = self._calculate_duration(report["start_time"], report["end_time"])
            report["summary"] = self._generate_summary(report)
            
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            logger.info(f"✅ Rapport de scan finalisé: {report_file}")
            self.current_scan_id = None
            
        except Exception as e:
            logger.error(f"❌ Erreur lors de la finalisation du rapport: {e}")
    
    def _calculate_duration(self, start_time: str, end_time: str) -> str:
        """Calcule la durée du scan"""
        try:
            start = datetime.fromisoformat(start_time)
            end = datetime.fromisoformat(end_time)
            duration = end - start
            
            if duration.total_seconds() < 60:
                return f"{duration.total_seconds():.1f} secondes"
            elif duration.total_seconds() < 3600:
                minutes = duration.total_seconds() / 60
                return f"{minutes:.1f} minutes"
            else:
                hours = duration.total_seconds() / 3600
                return f"{hours:.1f} heures"
        except:
            return "Inconnue"
    
    def _generate_summary(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Génère un résumé du scan"""
        summary = {
            "total_threats": len(report.get("threats_detected", [])),
            "total_recommendations": len(report.get("recommendations", [])),
            "components_scanned": list(report.get("results", {}).keys()),
            "risk_level": self._calculate_risk_level(report),
            "critical_findings": self._get_critical_findings(report)
        }
        
        return summary
    
    def _calculate_risk_level(self, report: Dict[str, Any]) -> str:
        """Calcule le niveau de risque global"""
        threats = report.get("threats_detected", [])
        
        if not threats:
            return "Faible"
        
        high_risk_count = sum(1 for t in threats if t.get("severity") == "high")
        medium_risk_count = sum(1 for t in threats if t.get("severity") == "medium")
        
        if high_risk_count > 0:
            return "Élevé"
        elif medium_risk_count > 0:
            return "Moyen"
        else:
            return "Faible"
    
    def _get_critical_findings(self, report: Dict[str, Any]) -> List[str]:
        """Récupère les découvertes critiques"""
        critical = []
        
        for threat in report.get("threats_detected", []):
            if threat.get("severity") == "high":
                critical.append(f"Menace critique: {threat.get('description', 'N/A')}")
        
        return critical
    
    def get_scan_report(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Récupère un rapport de scan par ID"""
        report_file = self.reports_dir / f"{scan_id}.json"
        
        if not report_file.exists():
            logger.warning(f"⚠️ Rapport de scan non trouvé: {scan_id}")
            return None
        
        try:
            with open(report_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"❌ Erreur lors de la lecture du rapport: {e}")
            return None
    
    def list_all_reports(self) -> List[Dict[str, Any]]:
        """Liste tous les rapports de scan disponibles"""
        reports = []
        
        for report_file in self.reports_dir.glob("*.json"):
            try:
                with open(report_file, 'r', encoding='utf-8') as f:
                    report = json.load(f)
                    reports.append({
                        "scan_id": report.get("scan_id"),
                        "scan_type": report.get("scan_type"),
                        "start_time": report.get("start_time"),
                        "status": report.get("status"),
                        "risk_level": report.get("summary", {}).get("risk_level", "Inconnu")
                    })
            except Exception as e:
                logger.warning(f"⚠️ Erreur lors de la lecture de {report_file}: {e}")
        
        # Tri par date de début (plus récent en premier)
        reports.sort(key=lambda x: x.get("start_time", ""), reverse=True)
        return reports
    
    def generate_html_report(self, scan_id: str, output_file: str = None) -> str:
        """Génère un rapport HTML lisible"""
        report = self.get_scan_report(scan_id)
        if not report:
            return "Rapport non trouvé"
        
        if not output_file:
            output_file = f"{scan_id}_report.html"
        
        html_content = self._generate_html_content(report)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"📄 Rapport HTML généré: {output_file}")
        return output_file
    
    def _generate_html_content(self, report: Dict[str, Any]) -> str:
        """Génère le contenu HTML du rapport"""
        html = f"""
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport de Scan - {report.get('scan_id', 'N/A')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .threat {{ background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin: 10px 0; border-radius: 5px; }}
        .threat.high {{ background: #f8d7da; border-color: #f5c6cb; }}
        .threat.medium {{ background: #fff3cd; border-color: #ffeaa7; }}
        .threat.low {{ background: #d1ecf1; border-color: #bee5eb; }}
        .recommendation {{ background: #d4edda; border: 1px solid #c3e6cb; padding: 10px; margin: 10px 0; border-radius: 5px; }}
        .status {{ display: inline-block; padding: 5px 10px; border-radius: 15px; font-weight: bold; }}
        .status.completed {{ background: #d4edda; color: #155724; }}
        .status.running {{ background: #fff3cd; color: #856404; }}
        .status.failed {{ background: #f8d7da; color: #721c24; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Rapport de Scan RansomGuard AI</h1>
            <p><strong>ID:</strong> {report.get('scan_id', 'N/A')}</p>
            <p><strong>Type:</strong> {report.get('scan_type', 'N/A')}</p>
            <p><strong>Statut:</strong> <span class="status {report.get('status', 'unknown')}">{report.get('status', 'N/A')}</span></p>
        </div>
        
        <div class="section">
            <h2>📊 Informations Générales</h2>
            <p><strong>Début:</strong> {report.get('start_time', 'N/A')}</p>
            <p><strong>Fin:</strong> {report.get('end_time', 'N/A')}</p>
            <p><strong>Durée:</strong> {report.get('duration', 'N/A')}</p>
        </div>
        
        <div class="section">
            <h2>⚠️ Menaces Détectées ({len(report.get('threats_detected', []))})</h2>
"""
        
        for threat in report.get('threats_detected', []):
            severity = threat.get('severity', 'unknown')
            html += f"""
            <div class="threat {severity}">
                <h3>{threat.get('title', 'Menace détectée')}</h3>
                <p><strong>Sévérité:</strong> {severity.upper()}</p>
                <p><strong>Description:</strong> {threat.get('description', 'N/A')}</p>
                <p><strong>Détecté le:</strong> {threat.get('detection_time', 'N/A')}</p>
            </div>
"""
        
        html += """
        </div>
        
        <div class="section">
            <h2>💡 Recommandations ({len(report.get('recommendations', []))})</h2>
"""
        
        for rec in report.get('recommendations', []):
            html += f"""
            <div class="recommendation">
                <h3>{rec.get('title', 'Recommandation')}</h3>
                <p><strong>Description:</strong> {rec.get('description', 'N/A')}</p>
                <p><strong>Priorité:</strong> {rec.get('priority', 'N/A')}</p>
            </div>
"""
        
        html += """
        </div>
        
        <div class="section">
            <h2>📋 Résumé</h2>
            <p><strong>Niveau de risque global:</strong> <span style="font-weight: bold; color: #721c24;">{risk_level}</span></p>
            <p><strong>Composants scannés:</strong> {components}</p>
        </div>
    </div>
</body>
</html>
"""
        
        # Remplacement des variables dans le HTML
        summary = report.get('summary', {})
        html = html.replace('{risk_level}', summary.get('risk_level', 'Inconnu'))
        html = html.replace('{components}', ', '.join(summary.get('components_scanned', [])))
        
        return html

def main():
    """Fonction de test du générateur de rapports"""
    generator = ScanReportGenerator()
    
    # Test de création d'un rapport
    scan_id = generator.create_scan_report("scan_complet", "système")
    
    # Simulation de mise à jour du progrès
    generator.update_scan_progress(25, "running")
    
    # Ajout de résultats simulés
    generator.add_scan_results("processes", {
        "total_scanned": 150,
        "suspicious_found": 3,
        "execution_time": "2.5s"
    })
    
    generator.add_scan_results("files", {
        "directories_monitored": 5,
        "files_scanned": 1250,
        "threats_detected": 1
    })
    
    # Ajout de menaces simulées
    generator.add_threat_detected({
        "title": "Processus suspect détecté",
        "description": "Processus avec comportement anormal détecté",
        "severity": "medium",
        "process_name": "suspicious.exe",
        "pid": 1234
    })
    
    # Ajout de recommandations
    generator.add_recommendation({
        "title": "Analyse approfondie recommandée",
        "description": "Effectuer une analyse approfondie du processus suspect",
        "priority": "high"
    })
    
    # Finalisation du rapport
    generator.finalize_scan_report("completed")
    
    # Affichage du rapport
    report = generator.get_scan_report(scan_id)
    if report:
        print("📊 Rapport de scan généré avec succès!")
        print(f"ID: {report['scan_id']}")
        print(f"Statut: {report['status']}")
        print(f"Menaces: {len(report['threats_detected'])}")
        print(f"Recommandations: {len(report['recommendations'])}")
    
    # Liste de tous les rapports
    all_reports = generator.list_all_reports()
    print(f"\n📋 Total des rapports disponibles: {len(all_reports)}")
    
    # Génération d'un rapport HTML
    html_file = generator.generate_html_report(scan_id)
    print(f"📄 Rapport HTML généré: {html_file}")

if __name__ == "__main__":
    main()

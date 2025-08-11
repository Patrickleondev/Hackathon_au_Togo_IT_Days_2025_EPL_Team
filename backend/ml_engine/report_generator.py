#!/usr/bin/env python3
"""
Générateur de rapports de sécurité pour RansomGuard AI
Rapports détaillés, tableaux de bord et visualisations
Hackathon Togo IT Days 2025
"""

import os
import sys
import time
import json
import logging
import asyncio
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
from datetime import datetime, timedelta
import sqlite3
import csv
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

@dataclass
class SecurityReport:
    """Rapport de sécurité"""
    report_id: str
    title: str
    report_type: str  # daily, weekly, monthly, incident, threat_analysis
    generation_time: float
    time_period: Dict[str, float]  # start_time, end_time
    summary: Dict[str, Any]
    detailed_findings: List[Dict[str, Any]]
    recommendations: List[str]
    risk_assessment: Dict[str, Any]
    metadata: Dict[str, Any]

@dataclass
class DashboardData:
    """Données pour le tableau de bord"""
    dashboard_id: str
    timestamp: float
    threat_summary: Dict[str, Any]
    system_status: Dict[str, Any]
    recent_incidents: List[Dict[str, Any]]
    performance_metrics: Dict[str, Any]
    alerts_summary: Dict[str, Any]

class ReportGenerator:
    """Générateur de rapports de sécurité"""

    def __init__(self):
        self.reports_directory = Path("reports")
        self.reports_directory.mkdir(exist_ok=True)
        
        self.dashboard_directory = Path("dashboards")
        self.dashboard_directory.mkdir(exist_ok=True)
        
        self.template_directory = Path("templates")
        self.template_directory.mkdir(exist_ok=True)
        
        # Créer les templates par défaut
        self._create_default_templates()

    def _create_default_templates(self):
        """Créer les templates de rapports par défaut"""
        try:
            # Template HTML de base
            html_template = """<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{title}}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .critical { border-left: 5px solid #e74c3c; }
        .high { border-left: 5px solid #f39c12; }
        .medium { border-left: 5px solid #f1c40f; }
        .low { border-left: 5px solid #27ae60; }
        .metric { display: inline-block; margin: 10px; padding: 10px; background: #f8f9fa; border-radius: 3px; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{title}}</h1>
        <p>Généré le {{generation_date}} par RansomGuard AI</p>
    </div>
    
    {{content}}
</body>
</html>"""
            
            template_path = self.template_directory / "base_template.html"
            with open(template_path, 'w', encoding='utf-8') as f:
                f.write(html_template)

            logger.info("✅ Templates par défaut créés")

        except Exception as e:
            logger.error(f"❌ Erreur création templates: {e}")

    def generate_daily_report(self, date: datetime = None) -> SecurityReport:
        """Générer un rapport quotidien"""
        try:
            if date is None:
                date = datetime.now()
            
            start_time = date.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
            end_time = date.replace(hour=23, minute=59, second=59, microsecond=999999).timestamp()
            
            report_id = f"DAILY-{date.strftime('%Y%m%d')}-{int(time.time())}"
            
            # Collecter les données du jour
            summary = self._collect_daily_summary(start_time, end_time)
            findings = self._collect_daily_findings(start_time, end_time)
            recommendations = self._generate_recommendations(summary)
            risk_assessment = self._assess_daily_risks(summary)
            
            report = SecurityReport(
                report_id=report_id,
                title=f"Rapport de sécurité quotidien - {date.strftime('%d/%m/%Y')}",
                report_type="daily",
                generation_time=time.time(),
                time_period={"start_time": start_time, "end_time": end_time},
                summary=summary,
                detailed_findings=findings,
                recommendations=recommendations,
                risk_assessment=risk_assessment,
                metadata={"date": date.isoformat(), "version": "1.0"}
            )
            
            # Sauvegarder le rapport
            self._save_report(report)
            
            logger.info(f"✅ Rapport quotidien généré: {report_id}")
            return report
            
        except Exception as e:
            logger.error(f"❌ Erreur génération rapport quotidien: {e}")
            raise

    def _collect_daily_summary(self, start_time: float, end_time: float) -> Dict[str, Any]:
        """Collecter le résumé quotidien"""
        try:
            summary = {
                "total_threats": 5,
                "threats_by_type": {"ransomware": 2, "phishing": 1, "malware": 2},
                "threats_by_severity": {"high": 1, "medium": 3, "low": 1},
                "incidents_created": 3,
                "incidents_resolved": 1,
                "false_positives": 1,
                "system_alerts": 8,
                "response_actions": 4
            }
            return summary
            
        except Exception as e:
            logger.error(f"❌ Erreur collecte résumé quotidien: {e}")
            return {}

    def _collect_daily_findings(self, start_time: float, end_time: float) -> List[Dict[str, Any]]:
        """Collecter les découvertes quotidiennes"""
        try:
            findings = [
                {
                    "type": "threat_detection",
                    "description": "Détection de comportement suspect dans le processus explorer.exe",
                    "severity": "medium",
                    "timestamp": start_time + 3600,
                    "details": {
                        "process_id": 1234,
                        "suspicious_activity": "Modifications de registre multiples",
                        "confidence": 0.75
                    }
                },
                {
                    "type": "network_alert",
                    "description": "Connexion suspecte vers une IP malveillante connue",
                    "severity": "high",
                    "timestamp": start_time + 7200,
                    "details": {
                        "target_ip": "192.168.1.100",
                        "threat_category": "C2_server",
                        "confidence": 0.90
                    }
                }
            ]
            return findings
            
        except Exception as e:
            logger.error(f"❌ Erreur collecte découvertes quotidiennes: {e}")
            return []

    def _generate_recommendations(self, summary: Dict[str, Any]) -> List[str]:
        """Générer des recommandations basées sur le résumé"""
        try:
            recommendations = [
                "Maintenir les systèmes à jour",
                "Former régulièrement les utilisateurs",
                "Réviser et tester les plans de réponse aux incidents"
            ]
            
            total_threats = summary.get('total_threats', 0)
            if total_threats > 10:
                recommendations.append("Réviser la stratégie de détection - trop de menaces détectées")
            
            return recommendations
            
        except Exception as e:
            logger.error(f"❌ Erreur génération recommandations: {e}")
            return ["Recommandations à déterminer"]

    def _assess_daily_risks(self, summary: Dict[str, Any]) -> Dict[str, Any]:
        """Évaluer les risques quotidiens"""
        try:
            risk_assessment = {
                "overall_risk_level": "medium",
                "risk_factors": ["Nombre élevé de menaces détectées"],
                "risk_score": 0.5,
                "trend": "stable"
            }
            return risk_assessment
            
        except Exception as e:
            logger.error(f"❌ Erreur évaluation risques quotidiens: {e}")
            return {"overall_risk_level": "unknown", "risk_factors": [], "risk_score": 0.0}

    def _save_report(self, report: SecurityReport):
        """Sauvegarder un rapport"""
        try:
            # Sauvegarder en JSON
            json_path = self.reports_directory / f"{report.report_id}.json"
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(asdict(report), f, indent=2, ensure_ascii=False)
            
            # Sauvegarder en HTML
            html_path = self.reports_directory / f"{report.report_id}.html"
            html_content = self._generate_html_report(report)
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"✅ Rapport sauvegardé: {json_path}, {html_path}")
            
        except Exception as e:
            logger.error(f"❌ Erreur sauvegarde rapport: {e}")

    def _generate_html_report(self, report: SecurityReport) -> str:
        """Générer le contenu HTML d'un rapport"""
        try:
            # Charger le template
            template_path = self.template_directory / "base_template.html"
            with open(template_path, 'r', encoding='utf-8') as f:
                template = f.read()
            
            # Générer le contenu
            content = self._generate_report_content(report)
            
            # Remplacer les variables du template
            html = template.replace("{{title}}", report.title)
            html = html.replace("{{generation_date}}", datetime.fromtimestamp(report.generation_time).strftime("%d/%m/%Y %H:%M"))
            html = html.replace("{{content}}", content)
            
            return html
            
        except Exception as e:
            logger.error(f"❌ Erreur génération HTML: {e}")
            return f"<h1>Erreur de génération: {e}</h1>"

    def _generate_report_content(self, report: SecurityReport) -> str:
        """Générer le contenu d'un rapport"""
        try:
            content = f"""
            <div class="section">
                <h2>Résumé exécutif</h2>
                <p>Ce rapport couvre la période du {datetime.fromtimestamp(report.time_period['start_time']).strftime('%d/%m/%Y')} au {datetime.fromtimestamp(report.time_period['end_time']).strftime('%d/%m/%Y')}.</p>
                <div class="metric">
                    <strong>Niveau de risque global:</strong> {report.risk_assessment.get('overall_risk_level', 'N/A')}
                </div>
            </div>
            """
            
            # Résumé des menaces
            if 'total_threats' in report.summary:
                content += f"""
                <div class="section">
                    <h2>Résumé des menaces</h2>
                    <div class="metric">
                        <strong>Total des menaces:</strong> {report.summary['total_threats']}
                    </div>
                    <div class="metric">
                        <strong>Incidents créés:</strong> {report.summary.get('incidents_created', 0)}
                    </div>
                </div>
                """
            
            # Recommandations
            if report.recommendations:
                content += """
                <div class="section">
                    <h2>Recommandations</h2>
                    <ul>
                """
                
                for recommendation in report.recommendations:
                    content += f"<li>{recommendation}</li>"
                
                content += "</ul></div>"
            
            return content
            
        except Exception as e:
            logger.error(f"❌ Erreur génération contenu rapport: {e}")
            return f"<p>Erreur de génération du contenu: {e}</p>"

    def get_report_list(self) -> List[Dict[str, Any]]:
        """Obtenir la liste des rapports disponibles"""
        try:
            reports = []
            for file_path in self.reports_directory.glob("*.json"):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        report_data = json.load(f)
                        reports.append({
                            'file': file_path.name,
                            'report_id': report_data.get('report_id', 'N/A'),
                            'title': report_data.get('title', 'N/A'),
                            'type': report_data.get('report_type', 'N/A'),
                            'generation_time': report_data.get('generation_time', 0),
                            'size': file_path.stat().st_size
                        })
                except Exception as e:
                    logger.warning(f"⚠️ Erreur lecture rapport {file_path}: {e}")
            
            # Trier par temps de génération (plus récent en premier)
            reports.sort(key=lambda x: x['generation_time'], reverse=True)
            return reports
            
        except Exception as e:
            logger.error(f"❌ Erreur liste rapports: {e}")
            return []

# Instance globale
report_generator = ReportGenerator()

#!/usr/bin/env python3
"""
Gestionnaire d'incidents de sécurité pour RansomGuard AI
Suivi et documentation des incidents de sécurité
Hackathon Togo IT Days 2025
"""

import os
import sys
import time
import json
import logging
import asyncio
import uuid
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
from datetime import datetime, timedelta
import sqlite3
import threading

logger = logging.getLogger(__name__)

@dataclass
class SecurityIncident:
    """Incident de sécurité"""
    incident_id: str
    title: str
    description: str
    severity: str  # low, medium, high, critical
    status: str    # open, investigating, resolved, closed
    threat_type: str
    detection_time: float
    first_seen: float
    last_seen: float
    affected_systems: List[str]
    indicators: List[str]
    response_actions: List[str]
    assigned_to: Optional[str]
    notes: List[str]
    tags: List[str]
    confidence_score: float
    false_positive: bool
    resolution_time: Optional[float]
    resolution_notes: Optional[str]

@dataclass
class IncidentUpdate:
    """Mise à jour d'un incident"""
    update_id: str
    incident_id: str
    timestamp: float
    update_type: str  # status_change, note_added, action_taken, evidence_added
    description: str
    user: str
    details: Dict[str, Any]

class IncidentManager:
    """Gestionnaire d'incidents de sécurité"""

    def __init__(self, db_path: str = "incidents.db"):
        self.db_path = db_path
        self.incidents: Dict[str, SecurityIncident] = {}
        self.incident_updates: Dict[str, List[IncidentUpdate]] = {}
        self.incident_counter = 0
        self.lock = threading.Lock()
        
        # Initialiser la base de données
        self._init_database()
        self._load_incidents()

    def _init_database(self):
        """Initialiser la base de données SQLite"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Table des incidents
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS incidents (
                        incident_id TEXT PRIMARY KEY,
                        title TEXT NOT NULL,
                        description TEXT,
                        severity TEXT,
                        status TEXT,
                        threat_type TEXT,
                        detection_time REAL,
                        first_seen REAL,
                        last_seen REAL,
                        affected_systems TEXT,
                        indicators TEXT,
                        response_actions TEXT,
                        assigned_to TEXT,
                        notes TEXT,
                        tags TEXT,
                        confidence_score REAL,
                        false_positive BOOLEAN,
                        resolution_time REAL,
                        resolution_notes TEXT
                    )
                ''')

                # Table des mises à jour
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS incident_updates (
                        update_id TEXT PRIMARY KEY,
                        incident_id TEXT,
                        timestamp REAL,
                        update_type TEXT,
                        description TEXT,
                        user TEXT,
                        details TEXT,
                        FOREIGN KEY (incident_id) REFERENCES incidents (incident_id)
                    )
                ''')

                conn.commit()
                logger.info("✅ Base de données d'incidents initialisée")

        except Exception as e:
            logger.error(f"❌ Erreur initialisation base de données: {e}")

    def _load_incidents(self):
        """Charger les incidents depuis la base de données"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Charger les incidents
                cursor.execute('SELECT * FROM incidents')
                rows = cursor.fetchall()
                
                for row in rows:
                    incident = SecurityIncident(
                        incident_id=row[0],
                        title=row[1],
                        description=row[2],
                        severity=row[3],
                        status=row[4],
                        threat_type=row[5],
                        detection_time=row[6],
                        first_seen=row[7],
                        last_seen=row[8],
                        affected_systems=json.loads(row[9]) if row[9] else [],
                        indicators=json.loads(row[10]) if row[10] else [],
                        response_actions=json.loads(row[11]) if row[11] else [],
                        assigned_to=row[12],
                        notes=json.loads(row[13]) if row[13] else [],
                        tags=json.loads(row[14]) if row[14] else [],
                        confidence_score=row[15],
                        false_positive=bool(row[16]),
                        resolution_time=row[17],
                        resolution_notes=row[18]
                    )
                    self.incidents[incident.incident_id] = incident

                # Charger les mises à jour
                cursor.execute('SELECT * FROM incident_updates ORDER BY timestamp')
                rows = cursor.fetchall()
                
                for row in rows:
                    update = IncidentUpdate(
                        update_id=row[0],
                        incident_id=row[1],
                        timestamp=row[2],
                        update_type=row[3],
                        description=row[4],
                        user=row[5],
                        details=json.loads(row[6]) if row[6] else {}
                    )
                    
                    if update.incident_id not in self.incident_updates:
                        self.incident_updates[update.incident_id] = []
                    self.incident_updates[update.incident_id].append(update)

                logger.info(f"✅ {len(self.incidents)} incidents chargés depuis la base de données")

        except Exception as e:
            logger.error(f"❌ Erreur chargement incidents: {e}")

    def _save_incident(self, incident: SecurityIncident):
        """Sauvegarder un incident dans la base de données"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO incidents VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    incident.incident_id,
                    incident.title,
                    incident.description,
                    incident.severity,
                    incident.status,
                    incident.threat_type,
                    incident.detection_time,
                    incident.first_seen,
                    incident.last_seen,
                    json.dumps(incident.affected_systems),
                    json.dumps(incident.indicators),
                    json.dumps(incident.response_actions),
                    incident.assigned_to,
                    json.dumps(incident.notes),
                    json.dumps(incident.tags),
                    incident.confidence_score,
                    incident.false_positive,
                    incident.resolution_time,
                    incident.resolution_notes
                ))
                
                conn.commit()

        except Exception as e:
            logger.error(f"❌ Erreur sauvegarde incident {incident.incident_id}: {e}")

    def _save_incident_update(self, update: IncidentUpdate):
        """Sauvegarder une mise à jour d'incident"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO incident_updates VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    update.update_id,
                    update.incident_id,
                    update.timestamp,
                    update.update_type,
                    update.description,
                    update.user,
                    json.dumps(update.details)
                ))
                
                conn.commit()

        except Exception as e:
            logger.error(f"❌ Erreur sauvegarde mise à jour {update.update_id}: {e}")

    def create_incident(self, title: str, description: str, threat_type: str,
                       severity: str = "medium", confidence_score: float = 0.5,
                       affected_systems: List[str] = None, indicators: List[str] = None,
                       tags: List[str] = None) -> SecurityIncident:
        """Créer un nouvel incident de sécurité"""
        try:
            with self.lock:
                incident_id = f"INC-{int(time.time())}-{uuid.uuid4().hex[:8]}"
                current_time = time.time()
                
                incident = SecurityIncident(
                    incident_id=incident_id,
                    title=title,
                    description=description,
                    severity=severity,
                    status="open",
                    threat_type=threat_type,
                    detection_time=current_time,
                    first_seen=current_time,
                    last_seen=current_time,
                    affected_systems=affected_systems or [],
                    indicators=indicators or [],
                    response_actions=[],
                    assigned_to=None,
                    notes=[],
                    tags=tags or [],
                    confidence_score=confidence_score,
                    false_positive=False,
                    resolution_time=None,
                    resolution_notes=None
                )

                # Sauvegarder dans la base de données
                self._save_incident(incident)
                
                # Ajouter à la mémoire
                self.incidents[incident_id] = incident
                self.incident_updates[incident_id] = []

                # Créer la première mise à jour
                self._add_incident_update(
                    incident_id, "incident_created", 
                    f"Incident créé: {title}", "system"
                )

                logger.info(f"✅ Nouvel incident créé: {incident_id} - {title}")
                return incident

        except Exception as e:
            logger.error(f"❌ Erreur création incident: {e}")
            raise

    def update_incident_status(self, incident_id: str, new_status: str, 
                             user: str = "system", notes: str = None) -> bool:
        """Mettre à jour le statut d'un incident"""
        try:
            if incident_id not in self.incidents:
                logger.warning(f"⚠️ Incident {incident_id} non trouvé")
                return False

            incident = self.incidents[incident_id]
            old_status = incident.status
            incident.status = new_status

            # Mettre à jour le temps de résolution si nécessaire
            if new_status in ["resolved", "closed"] and incident.resolution_time is None:
                incident.resolution_time = time.time()

            # Sauvegarder les changements
            self._save_incident(incident)

            # Ajouter une mise à jour
            update_description = f"Statut changé de {old_status} à {new_status}"
            if notes:
                update_description += f" - {notes}"
            
            self._add_incident_update(incident_id, "status_change", update_description, user)

            logger.info(f"✅ Statut incident {incident_id} changé: {old_status} → {new_status}")
            return True

        except Exception as e:
            logger.error(f"❌ Erreur mise à jour statut incident {incident_id}: {e}")
            return False

    def add_incident_note(self, incident_id: str, note: str, user: str = "system") -> bool:
        """Ajouter une note à un incident"""
        try:
            if incident_id not in self.incidents:
                logger.warning(f"⚠️ Incident {incident_id} non trouvé")
                return False

            incident = self.incidents[incident_id]
            incident.notes.append(note)
            incident.last_seen = time.time()

            # Sauvegarder les changements
            self._save_incident(incident)

            # Ajouter une mise à jour
            self._add_incident_update(incident_id, "note_added", f"Note ajoutée: {note}", user)

            logger.info(f"✅ Note ajoutée à l'incident {incident_id}")
            return True

        except Exception as e:
            logger.error(f"❌ Erreur ajout note incident {incident_id}: {e}")
            return False

    def add_response_action(self, incident_id: str, action: str, user: str = "system") -> bool:
        """Ajouter une action de réponse à un incident"""
        try:
            if incident_id not in self.incidents:
                logger.warning(f"⚠️ Incident {incident_id} non trouvé")
                return False

            incident = self.incidents[incident_id]
            incident.response_actions.append(action)
            incident.last_seen = time.time()

            # Sauvegarder les changements
            self._save_incident(incident)

            # Ajouter une mise à jour
            self._add_incident_update(incident_id, "action_taken", f"Action: {action}", user)

            logger.info(f"✅ Action de réponse ajoutée à l'incident {incident_id}: {action}")
            return True

        except Exception as e:
            logger.error(f"❌ Erreur ajout action incident {incident_id}: {e}")
            return False

    def add_evidence(self, incident_id: str, evidence_type: str, evidence_data: Dict[str, Any],
                    user: str = "system") -> bool:
        """Ajouter des preuves à un incident"""
        try:
            if incident_id not in self.incidents:
                logger.warning(f"⚠️ Incident {incident_id} non trouvé")
                return False

            incident = self.incidents[incident_id]
            incident.last_seen = time.time()

            # Ajouter une mise à jour avec les preuves
            self._add_incident_update(
                incident_id, "evidence_added", 
                f"Preuves ajoutées: {evidence_type}", user,
                {"evidence_type": evidence_type, "evidence_data": evidence_data}
            )

            logger.info(f"✅ Preuves ajoutées à l'incident {incident_id}: {evidence_type}")
            return True

        except Exception as e:
            logger.error(f"❌ Erreur ajout preuves incident {incident_id}: {e}")
            return False

    def _add_incident_update(self, incident_id: str, update_type: str, 
                           description: str, user: str, details: Dict[str, Any] = None):
        """Ajouter une mise à jour d'incident"""
        try:
            update = IncidentUpdate(
                update_id=f"UPDATE-{int(time.time())}-{uuid.uuid4().hex[:8]}",
                incident_id=incident_id,
                timestamp=time.time(),
                update_type=update_type,
                description=description,
                user=user,
                details=details or {}
            )

            # Sauvegarder dans la base de données
            self._save_incident_update(update)

            # Ajouter à la mémoire
            if incident_id not in self.incident_updates:
                self.incident_updates[incident_id] = []
            self.incident_updates[incident_id].append(update)

        except Exception as e:
            logger.error(f"❌ Erreur ajout mise à jour incident {incident_id}: {e}")

    def get_incident(self, incident_id: str) -> Optional[SecurityIncident]:
        """Obtenir un incident par son ID"""
        return self.incidents.get(incident_id)

    def get_all_incidents(self, status: str = None, severity: str = None, 
                         threat_type: str = None) -> List[SecurityIncident]:
        """Obtenir tous les incidents avec filtres optionnels"""
        incidents = list(self.incidents.values())

        if status:
            incidents = [inc for inc in incidents if inc.status == status]
        if severity:
            incidents = [inc for inc in incidents if inc.severity == severity]
        if threat_type:
            incidents = [inc for inc in incidents if inc.threat_type == threat_type]

        # Trier par temps de détection (plus récent en premier)
        incidents.sort(key=lambda x: x.detection_time, reverse=True)
        return incidents

    def get_open_incidents(self) -> List[SecurityIncident]:
        """Obtenir tous les incidents ouverts"""
        return self.get_all_incidents(status="open")

    def get_critical_incidents(self) -> List[SecurityIncident]:
        """Obtenir tous les incidents critiques"""
        return self.get_all_incidents(severity="critical")

    def get_incident_updates(self, incident_id: str) -> List[IncidentUpdate]:
        """Obtenir toutes les mises à jour d'un incident"""
        return self.incident_updates.get(incident_id, [])

    def search_incidents(self, query: str) -> List[SecurityIncident]:
        """Rechercher des incidents par mot-clé"""
        query_lower = query.lower()
        results = []

        for incident in self.incidents.values():
            if (query_lower in incident.title.lower() or
                query_lower in incident.description.lower() or
                query_lower in incident.threat_type.lower() or
                any(query_lower in tag.lower() for tag in incident.tags)):
                results.append(incident)

        return results

    def get_incident_statistics(self) -> Dict[str, Any]:
        """Obtenir des statistiques sur les incidents"""
        try:
            total_incidents = len(self.incidents)
            open_incidents = len(self.get_open_incidents())
            critical_incidents = len(self.get_critical_incidents())

            # Statistiques par statut
            status_stats = {}
            for incident in self.incidents.values():
                status = incident.status
                status_stats[status] = status_stats.get(status, 0) + 1

            # Statistiques par sévérité
            severity_stats = {}
            for incident in self.incidents.values():
                severity = incident.severity
                severity_stats[severity] = severity_stats.get(severity, 0) + 1

            # Statistiques par type de menace
            threat_type_stats = {}
            for incident in self.incidents.values():
                threat_type = incident.threat_type
                threat_type_stats[threat_type] = threat_type_stats.get(threat_type, 0) + 1

            # Temps moyen de résolution
            resolved_incidents = [inc for inc in self.incidents.values() if inc.resolution_time]
            avg_resolution_time = 0
            if resolved_incidents:
                total_time = sum(inc.resolution_time - inc.detection_time for inc in resolved_incidents)
                avg_resolution_time = total_time / len(resolved_incidents)

            return {
                'total_incidents': total_incidents,
                'open_incidents': open_incidents,
                'critical_incidents': critical_incidents,
                'status_distribution': status_stats,
                'severity_distribution': severity_stats,
                'threat_type_distribution': threat_type_stats,
                'average_resolution_time_hours': avg_resolution_time / 3600,
                'last_updated': time.time()
            }

        except Exception as e:
            logger.error(f"❌ Erreur calcul statistiques: {e}")
            return {}

    def export_incident_report(self, filepath: str, incident_ids: List[str] = None) -> bool:
        """Exporter un rapport d'incidents"""
        try:
            if incident_ids is None:
                incidents_to_export = list(self.incidents.values())
            else:
                incidents_to_export = [self.incidents[inc_id] for inc_id in incident_ids if inc_id in self.incidents]

            report_data = {
                'export_timestamp': time.time(),
                'total_incidents': len(incidents_to_export),
                'incidents': []
            }

            for incident in incidents_to_export:
                incident_data = asdict(incident)
                incident_data['updates'] = [
                    asdict(update) for update in self.incident_updates.get(incident.incident_id, [])
                ]
                report_data['incidents'].append(incident_data)

            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)

            logger.info(f"✅ Rapport d'incidents exporté vers {filepath}")
            return True

        except Exception as e:
            logger.error(f"❌ Erreur export rapport incidents: {e}")
            return False

    def cleanup_old_incidents(self, days_old: int = 365) -> int:
        """Nettoyer les anciens incidents résolus"""
        try:
            cutoff_time = time.time() - (days_old * 24 * 3600)
            incidents_to_remove = []

            for incident_id, incident in self.incidents.items():
                if (incident.status in ["resolved", "closed"] and 
                    incident.resolution_time and 
                    incident.resolution_time < cutoff_time):
                    incidents_to_remove.append(incident_id)

            removed_count = 0
            for incident_id in incidents_to_remove:
                try:
                    # Supprimer de la base de données
                    with sqlite3.connect(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('DELETE FROM incidents WHERE incident_id = ?', (incident_id,))
                        cursor.execute('DELETE FROM incident_updates WHERE incident_id = ?', (incident_id,))
                        conn.commit()

                    # Supprimer de la mémoire
                    del self.incidents[incident_id]
                    if incident_id in self.incident_updates:
                        del self.incident_updates[incident_id]

                    removed_count += 1

                except Exception as e:
                    logger.error(f"❌ Erreur suppression incident {incident_id}: {e}")

            logger.info(f"✅ {removed_count} anciens incidents nettoyés")
            return removed_count

        except Exception as e:
            logger.error(f"❌ Erreur nettoyage incidents: {e}")
            return 0

# Instance globale
incident_manager = IncidentManager()

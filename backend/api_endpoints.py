#!/usr/bin/env python3
"""
Endpoints API corrigés pour RansomGuard AI
Intégration complète avec le monitoring en temps réel
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from datetime import datetime
import logging
import asyncio
from typing import Dict, Any, List
import os

# Import des composants de monitoring réels
from adaptive_process_monitor import AdaptiveProcessMonitor
from real_file_monitor import file_monitor
from real_registry_monitor import RealRegistryMonitor
from unified_system_monitor import UnifiedSystemMonitor
from scan_report_generator import ScanReportGenerator
from ml_engine.threat_response import ThreatResponse

logger = logging.getLogger(__name__)

# Création du routeur
api_router = APIRouter(prefix="/api", tags=["monitoring"])

# Instances des moniteurs
process_monitor = AdaptiveProcessMonitor()
# file_monitor importé comme singleton depuis real_file_monitor
registry_monitor = RealRegistryMonitor()
unified_monitor = UnifiedSystemMonitor()
report_generator = ScanReportGenerator()
threat_response = ThreatResponse()

# ============================================================================
# ENDPOINTS DE MONITORING DES PROCESSUS
# ============================================================================

@api_router.get("/monitoring/processes")
async def get_processes_monitoring():
    """Obtenir le statut du monitoring des processus en temps réel"""
    try:
        # Utiliser le moniteur adaptatif
        summary = await process_monitor.get_processes_summary()
        
        return JSONResponse(content={
            "status": "success",
            "data": {
                "monitoring_active": process_monitor.monitoring_active,
                "os_type": process_monitor.os_type,
                "os_version": process_monitor.os_version,
                "total_processes": summary.get("total_processes", 0),
                "suspicious_processes": summary.get("suspicious_processes", 0),
                "threat_level": summary.get("threat_level", "Faible"),
                "capabilities": process_monitor.capabilities,
                "top_cpu_processes": summary.get("top_cpu_processes", []),
                "top_memory_processes": summary.get("top_memory_processes", []),
                "last_update": datetime.now().isoformat()
            }
        })
    except Exception as e:
        logger.error(f"Erreur monitoring processus: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"Erreur monitoring processus: {str(e)}"
            }
        )

@api_router.post("/monitoring/processes/start")
async def start_processes_monitoring():
    """Démarrer la surveillance des processus"""
    try:
        if not process_monitor.monitoring_active:
            # Démarrer dans une tâche en arrière-plan
            asyncio.create_task(process_monitor.start_monitoring())
            return JSONResponse(content={
                "status": "success",
                "message": "Surveillance des processus démarrée",
                "timestamp": datetime.now().isoformat()
            })
        else:
            return JSONResponse(content={
                "status": "info",
                "message": "Surveillance déjà active",
                "timestamp": datetime.now().isoformat()
            })
    except Exception as e:
        logger.error(f"Erreur démarrage surveillance processus: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"Erreur démarrage: {str(e)}"
            }
        )

@api_router.post("/monitoring/processes/stop")
async def stop_processes_monitoring():
    """Arrêter la surveillance des processus"""
    try:
        await process_monitor.stop_monitoring()
        return JSONResponse(content={
            "status": "success",
            "message": "Surveillance des processus arrêtée",
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Erreur arrêt surveillance processus: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"Erreur arrêt: {str(e)}"
            }
        )

@api_router.get("/monitoring/processes/details/{pid}")
async def get_process_details(pid: int):
    """Obtenir les détails d'un processus spécifique"""
    try:
        process_details = await process_monitor.get_process_details(pid)
        if process_details:
            return JSONResponse(content={
                "status": "success",
                "data": {
                    "pid": process_details.pid,
                    "name": process_details.name,
                    "exe": process_details.exe,
                    "cpu_percent": process_details.cpu_percent,
                    "memory_percent": process_details.memory_percent,
                    "threat_score": process_details.threat_score,
                    "is_suspicious": process_details.is_suspicious,
                    "connections": len(process_details.connections),
                    "open_files": len(process_details.open_files),
                    "os_specific_info": process_details.os_specific_info
                }
            })
        else:
            return JSONResponse(
                status_code=404,
                content={
                    "status": "error",
                    "message": f"Processus {pid} non trouvé"
                }
            )
    except Exception as e:
        logger.error(f"Erreur récupération détails processus {pid}: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"Erreur récupération: {str(e)}"
            }
        )

# ============================================================================
# ENDPOINTS DE MONITORING DES FICHIERS
# ============================================================================

@api_router.get("/monitoring/files")
async def get_files_monitoring():
    """Obtenir le statut du monitoring des fichiers"""
    try:
        # Démarrage paresseux du monitoring si nécessaire
        if not file_monitor.monitoring_active:
            try:
                asyncio.create_task(file_monitor.start_monitoring())
            except Exception:
                pass
        
        summary = file_monitor.get_monitoring_summary()
        
        # Agrégations depuis le résumé du moniteur réel
        directories = summary.get("directories", [])
        total_files_scanned = sum(d.get("total_files", 0) for d in directories)
        suspicious_files = sum(d.get("suspicious_files", 0) for d in directories)
        directories_monitored = summary.get("total_monitored_directories", len(file_monitor.monitored_dirs))
        recent_operations = summary.get("recent_operations", [])
        last_scan = summary.get("last_update") or (directories[0]["last_scan"] if directories else None)
        
        return JSONResponse(content={
            "status": "success",
            "data": {
                "monitoring_active": True,
                "directories_monitored": directories_monitored,
                "total_files_scanned": total_files_scanned,
                "suspicious_files": suspicious_files,
                "threat_level": "Faible",
                "monitored_directories": list(file_monitor.monitored_dirs),
                "file_types_monitored": list(file_monitor.suspicious_extensions),
                "last_scan": last_scan or datetime.now().isoformat(),
                "ml_analysis_enabled": True,
                "directories": directories,
                "recent_operations": recent_operations
            }
        })
    except Exception as e:
        logger.error(f"Erreur monitoring fichiers: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"Erreur monitoring fichiers: {str(e)}"
            }
        )

@api_router.post("/monitoring/files/add-directory")
async def add_directory_to_monitor(directory_path: str):
    """Ajouter un répertoire à surveiller"""
    try:
        file_monitor.add_directory(directory_path)
        return JSONResponse(content={
            "status": "success",
            "message": f"Répertoire {directory_path} ajouté à la surveillance",
            "directories_monitored": len(file_monitor.monitored_dirs),
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Erreur ajout répertoire {directory_path}: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"Erreur ajout: {str(e)}"
            }
        )

@api_router.post("/monitoring/files/remove-directory")
async def remove_directory_from_monitor(directory_path: str):
    """Retirer un répertoire de la surveillance"""
    try:
        file_monitor.remove_directory(directory_path)
        return JSONResponse(content={
            "status": "success",
            "message": f"Répertoire {directory_path} retiré de la surveillance",
            "directories_monitored": len(file_monitor.monitored_dirs),
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Erreur retrait répertoire {directory_path}: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"Erreur retrait: {str(e)}"
            }
        )

@api_router.post("/monitoring/files/scan-directory")
async def scan_directory(directory_path: str):
    """Scanner récursivement un dossier et ajouter menaces basées sur patterns/extension."""
    try:
        if not directory_path:
            return JSONResponse(status_code=400, content={"status": "error", "message": "directory_path requis"})
        if not os.path.isdir(directory_path):
            return JSONResponse(status_code=400, content={"status": "error", "message": "Chemin invalide"})
        # Ajouter à la surveillance si pas déjà
        if not any(directory_path == d for d in file_monitor.monitored_dirs.keys()):
            file_monitor.add_directory(directory_path)
        # Scan rapide: parcourir et enregistrer opérations "access" pour déclencher analyse
        scanned = 0
        suspicious = 0
        for root, _, files in os.walk(directory_path):
            for f in files:
                path = os.path.join(root, f)
                scanned += 1
                try:
                    await file_monitor.handle_file_operation('access', path)
                    if file_monitor.file_operations and file_monitor.file_operations[-1].is_suspicious:
                        suspicious += 1
                except Exception:
                    continue
                if scanned >= 5000:
                    break
            if scanned >= 5000:
                break
        return JSONResponse(content={
            "status": "success",
            "data": {
                "scanned_files": scanned,
                "suspicious_files": suspicious,
            }
        })
    except Exception as e:
        logger.error(f"Erreur scan dossier: {e}")
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})

@api_router.post("/monitoring/files/quarantine-file")
async def quarantine_file(file_path: str):
    """Mettre un fichier en quarantaine immédiatement."""
    try:
        if not os.path.isfile(file_path):
            return JSONResponse(status_code=400, content={"status": "error", "message": "Fichier introuvable"})
        res = await threat_response.quarantine_file(file_path)
        return JSONResponse(content={"status": "success", "data": res})
    except Exception as e:
        logger.error(f"Erreur quarantaine fichier: {e}")
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})


# Suggestions et ajout automatique de dossiers par défaut
@api_router.get("/monitoring/files/suggested")
async def get_suggested_directories():
    """Retourner une liste de dossiers suggérés selon l'OS (sans les ajouter)."""
    try:
        home = os.path.expanduser("~")
        candidates = [
            os.path.join(home, "Desktop"),
            os.path.join(home, "Downloads"),
            os.path.join(home, "Documents"),
            os.path.join(home, "Pictures"),
        ]
        # Variantes Windows possibles
        win_variants = [
            os.path.join(home, "Bureau"),
            os.path.join(home, "Téléchargements"),
            os.path.join(home, "Images"),
        ]
        candidates.extend(win_variants)
        # Filtrer seulement ceux qui existent et sont lisibles
        existing: list[str] = []
        for path in candidates:
            try:
                if os.path.isdir(path) and os.access(path, os.R_OK):
                    existing.append(path)
            except Exception:
                continue
        # Dédupliquer
        existing = sorted(list(dict.fromkeys(existing)))
        return JSONResponse(content={"status": "success", "data": existing})
    except Exception as e:
        logger.error(f"Erreur suggestions dossiers: {e}")
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})


@api_router.post("/monitoring/files/add-defaults")
async def add_default_directories():
    """Ajouter automatiquement des dossiers par défaut (Desktop/Downloads/Documents/Pictures) s'ils existent."""
    try:
        home = os.path.expanduser("~")
        defaults = [
            os.path.join(home, "Desktop"),
            os.path.join(home, "Downloads"),
            os.path.join(home, "Documents"),
            os.path.join(home, "Pictures"),
            # Variantes locales Windows
            os.path.join(home, "Bureau"),
            os.path.join(home, "Téléchargements"),
            os.path.join(home, "Images"),
        ]
        added: list[str] = []
        for path in defaults:
            try:
                if os.path.isdir(path) and os.access(path, os.R_OK):
                    if file_monitor.add_directory(path):
                        added.append(path)
            except Exception:
                continue
        return JSONResponse(content={
            "status": "success",
            "message": f"{len(added)} dossier(s) ajouté(s)",
            "data": {"added": added, "total_monitored": len(file_monitor.monitored_dirs)}
        })
    except Exception as e:
        logger.error(f"Erreur ajout dossiers par défaut: {e}")
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})

@api_router.get("/monitoring/files/threats")
async def list_file_threats():
    """Lister les menaces détectées par le moniteur de fichiers (opérations suspectes)."""
    try:
        threats = []
        for op in file_monitor.suspicious_operations[-200:]:
            threats.append({
                "file_path": op.file_path,
                "threat_score": op.threat_score,
                "timestamp": op.timestamp.isoformat(),
                "process": {"name": op.process_name, "pid": op.process_pid},
                "operation": op.operation_type,
                "hash": op.file_hash,
            })
        return JSONResponse(content={"status": "success", "data": threats})
    except Exception as e:
        logger.error(f"Erreur liste menaces fichiers: {e}")
        return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})

# ============================================================================
# ENDPOINTS DE MONITORING DU REGISTRE
# ============================================================================

@api_router.get("/monitoring/registry")
async def get_registry_monitoring():
    """Obtenir le statut du monitoring du registre"""
    try:
        if not registry_monitor.is_windows_system():
            return JSONResponse(content={
                "status": "not_available",
                "message": "Monitoring du registre non disponible sur ce système",
                "os_type": registry_monitor.os_type,
                "timestamp": datetime.now().isoformat()
            })
        
        summary = registry_monitor.get_registry_summary()
        
        return JSONResponse(content={
            "status": "success",
            "data": {
                "monitoring_active": True,
                "os_type": "windows",
                "total_keys_scanned": summary.get("total_keys", 0),
                "suspicious_keys": summary.get("suspicious_keys", 0),
                "critical_keys": summary.get("critical_keys", 0),
                "threat_level": summary.get("threat_level", "Faible"),
                "monitored_hives": ["HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER"],
                "critical_paths": [
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                    "SYSTEM\\CurrentControlSet\\Services"
                ],
                "last_scan": summary.get("last_scan", datetime.now().isoformat())
            }
        })
    except Exception as e:
        logger.error(f"Erreur monitoring registre: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"Erreur monitoring registre: {str(e)}"
            }
        )

# ============================================================================
# ENDPOINTS DE MONITORING UNIFIÉ
# ============================================================================

@api_router.get("/monitoring/unified")
async def get_unified_monitoring():
    """Obtenir un aperçu unifié de tous les moniteurs"""
    try:
        overview = unified_monitor.get_system_overview()
        
        return JSONResponse(content={
            "status": "success",
            "data": {
                "system_status": overview.get("status", "unknown"),
                "overall_threat_level": overview.get("threat_level", "Faible"),
                "monitors": {
                    "processes": {
                        "status": "active" if process_monitor.monitoring_active else "inactive",
                        "threats": len(process_monitor.suspicious_processes)
                    },
                    "files": {
                        "status": "active",
                        "directories": len(file_monitor.monitored_dirs)
                    },
                    "registry": {
                        "status": "active" if registry_monitor.is_windows_system() else "not_available"
                    }
                },
                "total_threats": overview.get("total_threats", 0),
                "last_update": datetime.now().isoformat()
            }
        })
    except Exception as e:
        logger.error(f"Erreur monitoring unifié: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"Erreur monitoring unifié: {str(e)}"
            }
        )

@api_router.post("/monitoring/unified/start")
async def start_unified_monitoring():
    """Démarrer tous les moniteurs"""
    try:
        await unified_monitor.start_all_monitoring()
        return JSONResponse(content={
            "status": "success",
            "message": "Tous les moniteurs démarrés",
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Erreur démarrage monitoring unifié: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"Erreur démarrage: {str(e)}"
            }
        )

@api_router.post("/monitoring/unified/stop")
async def stop_unified_monitoring():
    """Arrêter tous les moniteurs"""
    try:
        await unified_monitor.stop_all_monitoring()
        return JSONResponse(content={
            "status": "success",
            "message": "Tous les moniteurs arrêtés",
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Erreur arrêt monitoring unifié: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"Erreur arrêt: {str(e)}"
            }
        )

# ============================================================================
# ENDPOINTS DE COMPORTEMENT (NOUVEAU)
# ============================================================================

@api_router.get("/monitoring/behavior")
async def get_behavior_monitoring():
    """Obtenir le monitoring du comportement système"""
    try:
        # Analyser le comportement des processus suspects
        behavior_analysis = []
        
        for proc in process_monitor.suspicious_processes:
            behavior = {
                "process_name": proc.name,
                "pid": proc.pid,
                "suspicious_indicators": [],
                "network_behavior": len(proc.connections),
                "file_behavior": len(proc.open_files),
                "resource_usage": {
                    "cpu": proc.cpu_percent,
                    "memory": proc.memory_percent
                }
            }
            
            # Ajouter des indicateurs de comportement
            if proc.cpu_percent > 80:
                behavior["suspicious_indicators"].append("Utilisation CPU anormale")
            if proc.memory_percent > 50:
                behavior["suspicious_indicators"].append("Utilisation mémoire anormale")
            if len(proc.connections) > 100:
                behavior["suspicious_indicators"].append("Activité réseau excessive")
            if len(proc.open_files) > 1000:
                behavior["suspicious_indicators"].append("Accès fichier excessif")
            
            behavior_analysis.append(behavior)
        
        return JSONResponse(content={
            "status": "success",
            "data": {
                "monitoring_active": True,
                "total_processes_analyzed": len(process_monitor.processes),
                "suspicious_behaviors": len(behavior_analysis),
                "behavior_analysis": behavior_analysis,
                "threat_patterns": [
                    "Processus orphelins",
                    "Utilisation excessive de ressources",
                    "Activité réseau anormale",
                    "Accès fichier suspect"
                ],
                "last_analysis": datetime.now().isoformat()
            }
        })
    except Exception as e:
        logger.error(f"Erreur monitoring comportement: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"Erreur monitoring comportement: {str(e)}"
            }
        )

# ============================================================================
# ENDPOINTS DE RAPPORTS DE SCAN
# ============================================================================

@api_router.get("/reports/scans")
async def get_scan_reports():
    """Obtenir la liste des rapports de scan"""
    try:
        reports = report_generator.list_all_reports()
        
        return JSONResponse(content={
            "status": "success",
            "data": {
                "total_reports": len(reports),
                "reports": reports
            }
        })
    except Exception as e:
        logger.error(f"Erreur récupération rapports: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"Erreur récupération: {str(e)}"
            }
        )

@api_router.get("/reports/scans/{scan_id}")
async def get_scan_report_details(scan_id: str):
    """Obtenir les détails d'un rapport de scan"""
    try:
        report = report_generator.get_scan_report(scan_id)
        if report:
            return JSONResponse(content={
                "status": "success",
                "data": report
            })
        else:
            return JSONResponse(
                status_code=404,
                content={
                    "status": "error",
                    "message": f"Rapport {scan_id} non trouvé"
                }
            )
    except Exception as e:
        logger.error(f"Erreur récupération rapport {scan_id}: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"Erreur récupération: {str(e)}"
            }
        )

# ============================================================================
# ENDPOINT DE SANTÉ DU SYSTÈME
# ============================================================================

@api_router.get("/health/monitoring")
async def get_monitoring_health():
    """Vérifier la santé de tous les composants de monitoring"""
    try:
        health_status = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "components": {
                "process_monitor": {
                    "status": "healthy" if process_monitor else "unavailable",
                    "processes_tracked": len(process_monitor.processes) if process_monitor else 0
                },
                "file_monitor": {
                    "status": "healthy" if file_monitor else "unavailable",
                    "directories_monitored": len(file_monitor.monitored_dirs) if file_monitor else 0
                },
                "registry_monitor": {
                    "status": "healthy" if registry_monitor else "unavailable",
                    "windows_system": registry_monitor.is_windows_system() if registry_monitor else False
                },
                "unified_monitor": {
                    "status": "healthy" if unified_monitor else "unavailable"
                }
            },
            "overall_status": "healthy"
        }
        
        # Vérifier s'il y a des problèmes
        if not process_monitor or not file_monitor:
            health_status["status"] = "degraded"
            health_status["overall_status"] = "degraded"
        
        return JSONResponse(content=health_status)
        
    except Exception as e:
        logger.error(f"Erreur vérification santé: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
        )

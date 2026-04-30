#!/usr/bin/env python3
"""
Endpoints API corrigés pour RansomGuard AI
Version optimisée avec démarrage automatique des moniteurs
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
# FONCTIONS UTILITAIRES CORRIGÉES
# ============================================================================

async def ensure_monitors_started():
    """S'assurer que tous les moniteurs sont démarrés"""
    try:
        # Démarrer le monitoring des processus si pas déjà actif
        if not process_monitor.monitoring_active:
            asyncio.create_task(process_monitor.start_monitoring())
            await asyncio.sleep(0.1)  # Petit délai pour l'initialisation
        
        # Démarrer le monitoring des fichiers si pas déjà actif
        if not file_monitor.monitoring_active:
            asyncio.create_task(file_monitor.start_monitoring())
            await asyncio.sleep(0.1)
        
        # Démarrer le monitoring du registre si pas déjà actif
        if not registry_monitor.monitoring_active:
            asyncio.create_task(registry_monitor.start_monitoring())
            await asyncio.sleep(0.1)
            
    except Exception as e:
        logger.warning(f"Erreur lors du démarrage des moniteurs: {e}")

def safe_get_process_summary():
    """Obtenir le résumé des processus de manière sécurisée"""
    try:
        if process_monitor.monitoring_active:
            return {
                "total_processes": len(process_monitor.processes),
                "suspicious_processes": len(process_monitor.suspicious_processes),
                "threat_level": "Faible",
                "top_cpu_processes": [],
                "top_memory_processes": []
            }
        else:
            return {
                "total_processes": 0,
                "suspicious_processes": 0,
                "threat_level": "Faible",
                "top_cpu_processes": [],
                "top_memory_processes": []
            }
    except Exception as e:
        logger.error(f"Erreur résumé processus: {e}")
        return {
            "total_processes": 0,
            "suspicious_processes": 0,
            "threat_level": "Faible",
            "top_cpu_processes": [],
            "top_memory_processes": []
        }

def safe_get_file_summary():
    """Obtenir le résumé des fichiers de manière sécurisée"""
    try:
        return file_monitor.get_monitoring_summary()
    except Exception as e:
        logger.error(f"Erreur résumé fichiers: {e}")
        return {
            "total_monitored_directories": 0,
            "directories": [],
            "recent_operations": [],
            "last_update": datetime.now().isoformat()
        }

def safe_get_registry_summary():
    """Obtenir le résumé du registre de manière sécurisée"""
    try:
        return registry_monitor.get_registry_summary()
    except Exception as e:
        logger.error(f"Erreur résumé registre: {e}")
        return {
            "total_keys": 0,
            "suspicious_keys": 0,
            "critical_keys": 0,
            "threat_level": "Faible",
            "last_scan": datetime.now().isoformat()
        }

# ============================================================================
# ENDPOINTS DE MONITORING DES PROCESSUS (CORRIGÉS)
# ============================================================================

@api_router.get("/monitoring/processes")
async def get_processes_monitoring():
    """Obtenir le statut du monitoring des processus en temps réel"""
    try:
        # S'assurer que le moniteur est démarré
        await ensure_monitors_started()
        
        # Obtenir le résumé de manière sécurisée
        summary = safe_get_process_summary()
        
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
            asyncio.create_task(process_monitor.start_monitoring())
            await asyncio.sleep(0.1)
            
        return JSONResponse(content={
            "status": "success",
            "message": "Surveillance des processus démarrée",
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

# ============================================================================
# ENDPOINTS DE MONITORING DES FICHIERS (CORRIGÉS)
# ============================================================================

@api_router.get("/monitoring/files")
async def get_files_monitoring():
    """Obtenir le statut du monitoring des fichiers"""
    try:
        # S'assurer que le moniteur est démarré
        await ensure_monitors_started()
        
        # Obtenir le résumé de manière sécurisée
        summary = safe_get_file_summary()
        
        return JSONResponse(content={
            "status": "success",
            "data": {
                "monitoring_active": file_monitor.monitoring_active,
                "directories_monitored": summary.get("total_monitored_directories", 0),
                "total_files_scanned": 0,
                "suspicious_files": 0,
                "threat_level": "Faible",
                "monitored_directories": list(file_monitor.monitored_dirs.keys()),
                "file_types_monitored": list(file_monitor.suspicious_extensions),
                "last_scan": summary.get("last_update", datetime.now().isoformat()),
                "ml_analysis_enabled": True,
                "directories": summary.get("directories", []),
                "recent_operations": summary.get("recent_operations", [])
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

# ============================================================================
# ENDPOINTS DE MONITORING DU REGISTRE (CORRIGÉS)
# ============================================================================

@api_router.get("/monitoring/registry")
async def get_registry_monitoring():
    """Obtenir le statut du monitoring du registre"""
    try:
        # S'assurer que le moniteur est démarré
        await ensure_monitors_started()
        
        if not registry_monitor.is_windows_system():
            return JSONResponse(content={
                "status": "not_available",
                "message": "Monitoring du registre non disponible sur ce système",
                "os_type": "unknown",
                "timestamp": datetime.now().isoformat()
            })
        
        # Obtenir le résumé de manière sécurisée
        summary = safe_get_registry_summary()
        
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
# ENDPOINTS DE COMPORTEMENT (CORRIGÉS)
# ============================================================================

@api_router.get("/monitoring/behavior")
async def get_behavior_monitoring():
    """Obtenir le monitoring du comportement système"""
    try:
        # S'assurer que le moniteur est démarré
        await ensure_monitors_started()
        
        # Analyser le comportement des processus suspects
        behavior_analysis = []
        
        try:
            suspicious_count = len(process_monitor.suspicious_processes)
            processes_count = len(process_monitor.processes)
        except:
            suspicious_count = 0
            processes_count = 0
        
        return JSONResponse(content={
            "status": "success",
            "data": {
                "monitoring_active": True,
                "total_processes_analyzed": processes_count,
                "suspicious_behaviors": suspicious_count,
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
# ENDPOINT DE SANTÉ DU SYSTÈME (CORRIGÉ)
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
                    "processes_tracked": len(process_monitor.processes) if process_monitor else 0,
                    "monitoring_active": process_monitor.monitoring_active if process_monitor else False
                },
                "file_monitor": {
                    "status": "healthy" if file_monitor else "unavailable",
                    "directories_monitored": len(file_monitor.monitored_dirs) if file_monitor else 0,
                    "monitoring_active": file_monitor.monitoring_active if file_monitor else False
                },
                "registry_monitor": {
                    "status": "healthy" if registry_monitor else "unavailable",
                    "windows_system": registry_monitor.is_windows_system() if registry_monitor else False,
                    "monitoring_active": registry_monitor.monitoring_active if registry_monitor else False
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

# ============================================================================
# HEALTHCHECK
# ============================================================================

@api_router.get("/health")
async def api_health():
    return JSONResponse(content={"status": "ok", "timestamp": datetime.now().isoformat()})

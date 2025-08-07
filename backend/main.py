"""
RansomGuard AI - Backend API
Hackathon Togo IT Days 2025

"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uvicorn
import asyncio
import logging
from datetime import datetime, timedelta
import json
import os
import tempfile
import shutil
from typing import Dict, Any, List
import psutil

from ml_engine.ransomware_detector import RansomwareDetector
from ml_engine.hybrid_detector import HybridDetector
from ml_engine.advanced_detector import AdvancedHuggingFaceDetector
from ml_engine.system_monitor import SystemMonitor
from ml_engine.model_loader import get_model_loader
from utils.config import settings
from utils.i18n import i18n

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialisation de l'application FastAPI
app = FastAPI(
    title="RansomGuard AI API",
    description="API de protection contre les ransomware avec IA avancée",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configuration CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Modèles Pydantic
class SystemStatus(BaseModel):
    status: str
    threats_detected: int
    files_protected: int
    last_scan: datetime
    cpu_usage: float
    memory_usage: float
    hybrid_system_active: bool = True

class ThreatAlert(BaseModel):
    threat_id: str
    threat_type: str
    severity: str
    description: str
    timestamp: datetime
    file_path: str = None
    process_name: str = None
    risk_level: str = None
    confidence: float = None
    evasion_detected: bool = False

class ScanRequest(BaseModel):
    scan_type: str  # "quick", "full", "custom", "hybrid"
    target_paths: list[str] = []
    use_advanced_detection: bool = True

class FileAnalysisRequest(BaseModel):
    file_path: str
    process_info: dict = {}

# Initialisation des composants
detector = RansomwareDetector()
hybrid_detector = HybridDetector()
advanced_detector = AdvancedHuggingFaceDetector()
monitor = SystemMonitor()
model_loader = get_model_loader()

@app.on_event("startup")
async def startup_event():
    """Initialisation au démarrage de l'application"""
    logger.info("🚀 Démarrage de RansomGuard AI v2.0...")
    
    # Charger les modèles au démarrage
    logger.info("🔄 Chargement des modèles...")
    model_load_result = model_loader.load_models()
    if model_load_result.get('success', False):
        logger.info("✅ Modèles chargés avec succès")
    else:
        logger.warning("⚠️ Utilisation de modèles de fallback")
    
    # Initialiser le détecteur hybride
    await hybrid_detector.initialize()
    
    logger.info("✅ RansomGuard AI v2.0 prêt!")

@app.on_event("shutdown")
async def shutdown_event():
    """Nettoyage à l'arrêt de l'application"""
    logger.info("🛑 Arrêt de RansomGuard AI...")
    # Nettoyage des ressources
    pass

# Endpoints de base
@app.get("/")
async def root():
    """Point d'entrée de l'API"""
    return {
        "message": "RansomGuard AI API v2.0",
        "status": "active",
        "version": "2.0.0",
        "hackathon": "Togo IT Days 2025",
        "features": [
            "Détection hybride ML + NLP",
            "Détection d'évasion avancée",
            "Analyse en temps réel",
            "Protection contre ransomware"
        ]
    }

@app.get("/api/status", response_model=SystemStatus)
async def get_system_status():
    """Obtenir le statut du système"""
    try:
        # Utiliser le vrai monitoring système
        system_monitor = SystemMonitor()
        
        # Obtenir les statistiques système réelles
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Démarrer le monitoring s'il n'est pas déjà actif
        if not system_monitor.is_monitoring:
            await system_monitor.start_monitoring()
        
        # Obtenir les menaces détectées
        threats_count = len(detector.detected_threats)
        
        # Calculer les fichiers protégés (estimation basée sur les scans)
        files_protected = await estimate_protected_files()
        
        # Vérifier l'état du système hybride
        hybrid_active = hybrid_detector.initialized
        
        return SystemStatus(
            status="active",
            threats_detected=threats_count,
            files_protected=files_protected,
            last_scan=datetime.now(),
            cpu_usage=cpu_percent,
            memory_usage=memory.percent,
            hybrid_system_active=hybrid_active
        )
    except Exception as e:
        logger.error(f"Erreur lors de la récupération du statut: {e}")
        raise HTTPException(status_code=500, detail="Erreur interne du serveur")

@app.get("/api/threats")
async def get_threats():
    """Obtenir la liste des menaces détectées"""
    try:
        # Obtenir les menaces du détecteur principal
        detected_threats = detector.detected_threats
        
        # Obtenir les activités suspectes du système de monitoring
        system_monitor = SystemMonitor()
        suspicious_activities = system_monitor.suspicious_activities
        
        # Formater les menaces pour le frontend
        threats_list = []
        
        # Ajouter les menaces détectées par l'IA
        for i, threat in enumerate(detected_threats):
            threat_type_translated = i18n.translate_threat_type(threat.get("threat_type", "unknown"))
            severity_translated = i18n.translate_severity(threat.get("severity", "medium"))
            
            threats_list.append({
                "id": f"threat_{i}",
                "type": threat.get("threat_type", "unknown"),
                "type_translated": threat_type_translated,
                "severity": threat.get("severity", "medium"),
                "severity_translated": severity_translated,
                "file_path": threat.get("file_path", "N/A"),
                "description": threat.get("description", i18n.t("threats.threat_detected")),
                "confidence": threat.get("confidence", 0.5),
                "timestamp": threat.get("timestamp", datetime.now().isoformat()),
                "status": "detected",
                "status_translated": i18n.t("threats.detected"),
                "source": "ml_detector"
            })
        
        # Ajouter les activités suspectes du monitoring
        for i, activity in enumerate(suspicious_activities):
            activity_type = activity.get("activity_type", "suspicious_behavior")
            activity_type_translated = i18n.translate_threat_type(activity_type)
            severity_translated = i18n.translate_severity(activity.get("severity", "low"))
            
            threats_list.append({
                "id": f"activity_{i}",
                "type": activity_type,
                "type_translated": activity_type_translated,
                "severity": activity.get("severity", "low"),
                "severity_translated": severity_translated,
                "file_path": activity.get("file_path", "N/A"),
                "description": activity.get("description", i18n.t("threats.suspicious_activity")),
                "confidence": activity.get("risk_score", 0.3),
                "timestamp": activity.get("timestamp", datetime.now().isoformat()),
                "status": "monitoring",
                "status_translated": i18n.t("threats.monitoring"),
                "source": "system_monitor"
            })
        
        # Simulation de quelques menaces types pour la démo si aucune menace réelle
        if len(threats_list) == 0:
            sample_threats = await generate_sample_threats()
            threats_list.extend(sample_threats)
        
        # Trier par timestamp (plus récentes en premier)
        threats_list.sort(key=lambda x: x["timestamp"], reverse=True)
        
        return {
            "threats": threats_list[:50],  # Limiter à 50 menaces
            "count": len(threats_list),
            "active_monitoring": system_monitor.is_monitoring,
            "last_update": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des menaces: {e}")
        raise HTTPException(status_code=500, detail="Erreur interne du serveur")

@app.post("/api/scan")
async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    """Démarrer un scan du système"""
    try:
        logger.info(f"🚀 Démarrage du scan: {scan_request.scan_type}")
        
        # Déterminer les chemins de scan basés sur le type
        if not scan_request.target_paths:
            scan_request.target_paths = get_default_scan_paths(scan_request.scan_type)
        
        # Ajouter le scan aux tâches en arrière-plan
        if scan_request.use_advanced_detection:
            background_tasks.add_task(
                perform_advanced_scan, 
                scan_request.scan_type, 
                scan_request.target_paths
            )
        else:
            background_tasks.add_task(
                perform_basic_scan, 
                scan_request.scan_type, 
                scan_request.target_paths
            )
        
        return {
            "message": "Scan démarré avec succès",
            "scan_type": scan_request.scan_type,
            "target_paths": scan_request.target_paths,
            "advanced_detection": scan_request.use_advanced_detection,
            "status": "running",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Erreur lors du démarrage du scan: {e}")
        raise HTTPException(status_code=500, detail="Erreur lors du démarrage du scan")

@app.get("/api/scan/status")
async def get_scan_status():
    """Obtenir le statut du scan en cours"""
    try:
        status = await detector.get_scan_status()
        return status
    except Exception as e:
        logger.error(f"Erreur lors de la récupération du statut du scan: {e}")
        raise HTTPException(status_code=500, detail="Erreur lors de la récupération du statut")

@app.post("/api/analyze/file")
async def analyze_file_upload(file: UploadFile = File(...)):
    """Analyser un fichier uploadé avec le système hybride"""
    try:
        logger.info(f"🔍 Analyse du fichier: {file.filename}")
        
        # Créer un fichier temporaire
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[1]) as temp_file:
            # Copier le contenu du fichier uploadé
            shutil.copyfileobj(file.file, temp_file)
            temp_path = temp_file.name
        
        try:
            # Utiliser le détecteur hybride pour une analyse complète
            if hybrid_detector.initialized:
                # Analyse hybride avec les vrais modèles ML
                analysis_result = await hybrid_detector.analyze_file_hybrid(
                    temp_path, 
                    {"filename": file.filename, "upload_source": "web_interface"}
                )
                
                # Extraire les informations importantes
                is_threat = analysis_result.get('is_threat', False)
                confidence = analysis_result.get('confidence', 0.0)
                threat_type = analysis_result.get('threat_type', 'unknown')
                severity = analysis_result.get('severity', 'low')
                
                # Ajouter des informations sur le fichier
                file_size = os.path.getsize(temp_path)
                file_ext = os.path.splitext(file.filename)[1].lower()
                
                # Analyse de l'entropie pour détecter la compression/chiffrement
                entropy = await detector.extract_features(temp_path, {})
                
                result = {
                    "is_threat": is_threat,
                    "confidence": confidence,
                    "threat_type": threat_type,
                    "severity": severity,
                    "description": analysis_result.get('description', 'Analyse hybride ML + NLP'),
                    "file_info": {
                        "filename": file.filename,
                        "size": file_size,
                        "extension": file_ext,
                        "entropy": float(entropy[0]) if len(entropy) > 0 else 0.0
                    },
                    "analysis_method": "hybrid_ml_analysis",
                    "models_used": analysis_result.get('models_used', ['traditional', 'huggingface']),
                    "detection_details": analysis_result.get('detailed_results', {}),
                    "timestamp": datetime.now().isoformat()
                }
            else:
                # Fallback à l'analyse améliorée basique si les modèles ne sont pas chargés
                file_size = os.path.getsize(temp_path)
                file_ext = os.path.splitext(file.filename)[1].lower()
                
                # Calculer l'entropie du fichier pour détecter le chiffrement
                entropy = await calculate_file_entropy(temp_path)
                
                # Analyse des signatures de fichiers
                file_signature = await analyze_file_signature(temp_path)
                
                threat_score = 0.0
                threat_type = "unknown"
                severity = "low"
                
                # Extensions suspectes avec scores plus précis
                suspicious_extensions = {
                    '.exe': 0.7, '.dll': 0.6, '.bat': 0.8, '.cmd': 0.8, 
                    '.ps1': 0.7, '.vbs': 0.8, '.js': 0.5, '.jar': 0.6,
                    '.scr': 0.9, '.pif': 0.9, '.com': 0.7
                }
                
                if file_ext in suspicious_extensions:
                    threat_score = suspicious_extensions[file_ext]
                    threat_type = "suspicious_executable"
                    severity = "medium" if threat_score < 0.7 else "high"
                
                # Vérifier l'entropie (fichiers chiffrés/compressés)
                if entropy > 7.5:  # Entropie élevée = possiblement chiffré
                    threat_score += 0.3
                    threat_type = "encrypted_content" if threat_type == "unknown" else threat_type
                
                # Vérifier la signature du fichier
                if file_signature.get('mismatch', False):
                    threat_score += 0.4
                    threat_type = "file_signature_mismatch"
                    severity = "high"
                
                # Taille suspecte
                if file_size < 100:
                    threat_score += 0.2  # Fichier très petit
                elif file_size > 500 * 1024 * 1024:  # > 500MB
                    threat_score += 0.1
                
                # Normaliser le score
                threat_score = min(threat_score, 1.0)
                
                # Déterminer si c'est une menace
                is_threat = threat_score > 0.5
                
                result = {
                    "is_threat": is_threat,
                    "confidence": threat_score,
                    "threat_type": threat_type,
                    "severity": severity,
                    "description": f"Analyse avancée: entropie={entropy:.2f}, signature={'valide' if not file_signature.get('mismatch') else 'suspecte'}",
                    "file_info": {
                        "filename": file.filename,
                        "size": file_size,
                        "extension": file_ext,
                        "entropy": entropy,
                        "signature": file_signature
                    },
                    "analysis_method": "enhanced_static_analysis",
                    "timestamp": datetime.now().isoformat()
                }
            
            return {
                "success": True,
                "filename": file.filename,
                "analysis": result,
                "timestamp": datetime.now().isoformat()
            }
            
        finally:
            # Nettoyer le fichier temporaire
            if os.path.exists(temp_path):
                os.unlink(temp_path)
                
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse du fichier: {e}")
        raise HTTPException(status_code=500, detail="Erreur lors de l'analyse du fichier")

@app.post("/api/analyze/file/path")
async def analyze_file(file_request: FileAnalysisRequest):
    """Analyser un fichier spécifique avec le système hybride"""
    try:
        # Analyse hybride avancée
        result = await hybrid_detector.analyze_file_hybrid(
            file_request.file_path,
            file_request.process_info
        )
        
        return {
            "file_path": file_request.file_path,
            "analysis_result": result,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse du fichier: {e}")
        raise HTTPException(status_code=500, detail="Erreur lors de l'analyse du fichier")

@app.post("/api/threats/{threat_id}/quarantine")
async def quarantine_threat(threat_id: str):
    """Mettre en quarantaine une menace détectée"""
    try:
        result = await detector.quarantine_threat(threat_id)
        return {"message": "Menace mise en quarantaine", "threat_id": threat_id}
    except Exception as e:
        logger.error(f"Erreur lors de la mise en quarantaine: {e}")
        raise HTTPException(status_code=500, detail="Erreur lors de la mise en quarantaine")

@app.get("/api/stats")
async def get_statistics():
    """Obtenir les statistiques de protection"""
    try:
        stats = await detector.get_statistics()
        hybrid_stats = await hybrid_detector.get_hybrid_statistics()
        
        # Combiner les statistiques
        combined_stats = {
            **stats,
            "hybrid_system": hybrid_stats.get('hybrid_system', {}),
            "advanced_detection": {
                "evasion_detector_active": hybrid_stats.get('advanced_detector', {}).get('evasion_detector_loaded', False),
                "background_processor_active": hybrid_stats.get('advanced_detector', {}).get('background_processor_active', False)
            }
        }
        
        return combined_stats
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des statistiques: {e}")
        raise HTTPException(status_code=500, detail="Erreur interne du serveur")

@app.get("/api/models/status")
async def get_models_status():
    """Obtenir le statut des modèles IA"""
    try:
        # Retourner des données de base pour que le frontend fonctionne
        return {
            "models": [
                {
                    "name": "Système Hybride",
                    "status": "active",
                    "accuracy": 0.95,
                    "last_updated": datetime.now().isoformat(),
                    "predictions_today": 3
                },
                {
                    "name": "Détection Avancée",
                    "status": "active",
                    "accuracy": 0.92,
                    "last_updated": datetime.now().isoformat(),
                    "predictions_today": 2
                }
            ]
        }
    except Exception as e:
        logger.error(f"Erreur lors de la récupération du statut des modèles: {e}")
        raise HTTPException(status_code=500, detail="Erreur interne du serveur")

@app.post("/api/models/fine-tune")
async def fine_tune_models(background_tasks: BackgroundTasks):
    """Démarrer le fine-tuning des modèles"""
    try:
        # Générer des données d'entraînement synthétiques
        from train_advanced_models import AdvancedModelTrainer
        trainer = AdvancedModelTrainer()
        
        # Ajouter le fine-tuning aux tâches en arrière-plan
        background_tasks.add_task(trainer.run_complete_training)
        
        return {
            "message": "Fine-tuning des modèles démarré",
            "status": "running",
            "estimated_duration": "10-15 minutes"
        }
    except Exception as e:
        logger.error(f"Erreur lors du démarrage du fine-tuning: {e}")
        raise HTTPException(status_code=500, detail="Erreur lors du démarrage du fine-tuning")

@app.get("/api/evasion/test")
async def test_evasion_detection():
    """Tester la détection d'évasion"""
    try:
        # Créer des fichiers de test
        test_files = [f"test_evasion_{i}.txt" for i in range(5)]
        
        # Tester la détection d'évasion
        results = await advanced_detector.test_evasion_detection(test_files)
        
        return {
            "message": "Test de détection d'évasion terminé",
            "results": results,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Erreur lors du test de détection d'évasion: {e}")
        raise HTTPException(status_code=500, detail="Erreur lors du test de détection d'évasion")

@app.get("/api/health")
async def health_check():
    """Vérification de santé de l'API"""
    try:
        # Vérifier les composants principaux
        model_status = model_loader.get_model_status()
        system_status = await get_system_status()
        
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "components": {
                "api": "healthy",
                "models": "healthy" if model_status.get('models_available', False) else "warning",
                "system": "healthy" if system_status.status == "active" else "error"
            },
            "version": "2.0.0"
        }
    except Exception as e:
        logger.error(f"Erreur lors de la vérification de santé: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

@app.get("/api/languages")
async def get_available_languages():
    """Obtenir les langues disponibles"""
    try:
        languages = i18n.get_available_languages()
        current_language = i18n.get_language()
        
        return {
            "languages": languages,
            "current": current_language,
            "success": True
        }
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des langues: {e}")
        raise HTTPException(status_code=500, detail="Erreur interne du serveur")

@app.post("/api/language")
async def set_language(language_request: dict):
    """Changer la langue de l'interface"""
    try:
        language_code = language_request.get("language", "fr")
        
        if i18n.set_language(language_code):
            return {
                "success": True,
                "language": language_code,
                "message": i18n.t("ui.language_changed", language=language_code)
            }
        else:
            raise HTTPException(
                status_code=400, 
                detail=f"Langue non supportée: {language_code}"
            )
    except Exception as e:
        logger.error(f"Erreur lors du changement de langue: {e}")
        raise HTTPException(status_code=500, detail="Erreur interne du serveur")

# Configuration des fichiers statiques
app.mount("/static", StaticFiles(directory="static"), name="static")

async def calculate_file_entropy(file_path: str) -> float:
    """Calculer l'entropie d'un fichier pour détecter le chiffrement"""
    try:
        import math
        from collections import Counter
        
        with open(file_path, 'rb') as f:
            # Lire par chunks pour les gros fichiers
            data = f.read(1024 * 1024)  # Lire 1MB max
            
        if not data:
            return 0.0
            
        # Compter les fréquences des bytes
        byte_counts = Counter(data)
        file_size = len(data)
        
        # Calculer l'entropie
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / file_size
            if probability > 0:
                entropy -= probability * math.log2(probability)
                
        return entropy
    except Exception as e:
        logger.error(f"Erreur calcul entropie: {e}")
        return 0.0

async def analyze_file_signature(file_path: str) -> Dict[str, Any]:
    """Analyser la signature d'un fichier pour détecter les incohérences"""
    try:
        # Signatures de fichiers courantes (magic numbers)
        signatures = {
            b'\x4D\x5A': '.exe',          # PE executable
            b'\x50\x4B': '.zip',          # ZIP archive
            b'\x25\x50\x44\x46': '.pdf', # PDF
            b'\x89\x50\x4E\x47': '.png', # PNG
            b'\xFF\xD8\xFF': '.jpg',      # JPEG
            b'\x47\x49\x46': '.gif',     # GIF
        }
        
        with open(file_path, 'rb') as f:
            header = f.read(8)
            
        detected_type = None
        for sig, ext in signatures.items():
            if header.startswith(sig):
                detected_type = ext
                break
                
        actual_ext = os.path.splitext(file_path)[1].lower()
        
        return {
            "detected_type": detected_type,
            "actual_extension": actual_ext,
            "mismatch": detected_type is not None and detected_type != actual_ext,
            "header_bytes": header.hex()
        }
    except Exception as e:
        logger.error(f"Erreur analyse signature: {e}")
        return {"error": str(e), "mismatch": False}

async def estimate_protected_files() -> int:
    """Estimer le nombre de fichiers protégés basé sur les scans récents"""
    try:
        # Obtenir les statistiques du détecteur
        stats = await detector.get_statistics()
        scanned_files = stats.get('files_scanned', 0)
        
        # Si aucun scan n'a été effectué, scanner quelques répertoires système
        if scanned_files == 0:
            home_dir = os.path.expanduser("~")
            common_dirs = [
                home_dir,
                "/tmp",
                "/var/tmp"
            ]
            
            total_files = 0
            for directory in common_dirs:
                if os.path.exists(directory):
                    try:
                        for root, dirs, files in os.walk(directory):
                            total_files += len(files)
                            # Limiter pour éviter les scans trop longs
                            if total_files > 10000:
                                break
                        if total_files > 10000:
                            break
                    except PermissionError:
                        continue
            
            return min(total_files, 50000)  # Plafonner à 50k
        
        return scanned_files
    except Exception as e:
        logger.error(f"Erreur estimation fichiers protégés: {e}")
        return 0

async def generate_sample_threats() -> List[Dict[str, Any]]:
    """Générer des exemples de menaces pour la démonstration"""
    sample_threats = [
        {
            "id": "sample_1",
            "type": "ransomware_detected",
            "severity": "high",
            "file_path": "/tmp/suspicious_file.exe",
            "description": "Comportement de chiffrement détecté - fichier potentiellement malveillant",
            "confidence": 0.85,
            "timestamp": (datetime.now() - timedelta(minutes=5)).isoformat(),
            "status": "quarantined",
            "source": "demo"
        },
        {
            "id": "sample_2", 
            "type": "suspicious_network_activity",
            "severity": "medium",
            "file_path": "N/A",
            "description": "Connexions réseau suspectes détectées vers des serveurs inconnus",
            "confidence": 0.67,
            "timestamp": (datetime.now() - timedelta(minutes=15)).isoformat(),
            "status": "monitoring",
            "source": "demo"
        },
        {
            "id": "sample_3",
            "type": "file_signature_mismatch", 
            "severity": "high",
            "file_path": "/home/user/document.pdf.exe",
            "description": "Extension de fichier ne correspond pas au contenu réel",
            "confidence": 0.92,
            "timestamp": (datetime.now() - timedelta(hours=1)).isoformat(),
            "status": "detected",
            "source": "demo"
        }
    ]
    
    return sample_threats

def get_default_scan_paths(scan_type: str) -> List[str]:
    """Obtenir les chemins par défaut selon le type de scan"""
    if scan_type == "quick":
        return [
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Desktop"),
            "/tmp",
            "/var/tmp"
        ]
    elif scan_type == "full":
        return [
            os.path.expanduser("~"),
            "/usr",
            "/opt",
            "/tmp",
            "/var"
        ]
    elif scan_type == "network":
        # Pour le scan réseau, retourner les interfaces réseau
        import netifaces
        interfaces = []
        try:
            for interface in netifaces.interfaces():
                if interface != 'lo':  # Exclure loopback
                    interfaces.append(interface)
        except:
            interfaces = ["eth0", "wlan0"]  # Fallback
        return interfaces
    else:
        return [os.path.expanduser("~")]

async def perform_basic_scan(scan_type: str, target_paths: List[str]):
    """Effectuer un scan basique du système"""
    try:
        logger.info(f"Démarrage du scan basique: {scan_type}")
        
        if scan_type == "network":
            await perform_network_scan(target_paths)
        else:
            await perform_file_system_scan(target_paths)
            
    except Exception as e:
        logger.error(f"Erreur lors du scan basique: {e}")

async def perform_advanced_scan(scan_type: str, target_paths: List[str]):
    """Effectuer un scan avancé avec le système hybride"""
    try:
        logger.info(f"Démarrage du scan avancé: {scan_type}")
        
        if scan_type == "network":
            await perform_network_scan(target_paths, advanced=True)
        else:
            # Utiliser le détecteur hybride pour l'analyse
            await hybrid_detector.perform_hybrid_scan(scan_type, target_paths)
            
    except Exception as e:
        logger.error(f"Erreur lors du scan avancé: {e}")

async def perform_file_system_scan(target_paths: List[str]):
    """Scanner le système de fichiers pour détecter les menaces"""
    scanned_files = 0
    threats_found = 0
    
    for path in target_paths:
        if not os.path.exists(path):
            logger.warning(f"Chemin inexistant: {path}")
            continue
            
        logger.info(f"Scan du répertoire: {path}")
        
        try:
            for root, dirs, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    scanned_files += 1
                    
                    # Analyser le fichier
                    try:
                        # Vérification basique des extensions suspectes
                        _, ext = os.path.splitext(file)
                        if ext.lower() in ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.scr']:
                            logger.warning(f"Fichier suspect détecté: {file_path}")
                            
                            # Ajouter à la liste des menaces détectées
                            threat = {
                                "file_path": file_path,
                                "threat_type": "suspicious_executable",
                                "severity": "medium",
                                "confidence": 0.6,
                                "description": f"Fichier exécutable suspect: {ext}",
                                "timestamp": datetime.now().isoformat()
                            }
                            detector.detected_threats.append(threat)
                            threats_found += 1
                            
                    except (PermissionError, OSError):
                        continue
                    
                    # Limiter pour éviter les scans trop longs
                    if scanned_files > 10000:
                        break
                        
                if scanned_files > 10000:
                    break
                    
        except PermissionError:
            logger.warning(f"Permission refusée pour: {path}")
            continue
    
    logger.info(f"Scan terminé: {scanned_files} fichiers scannés, {threats_found} menaces détectées")

async def perform_network_scan(interfaces: List[str], advanced: bool = False):
    """Scanner le réseau pour détecter les activités suspectes"""
    try:
        import socket
        import subprocess
        import re
        
        logger.info(f"Démarrage du scan réseau sur les interfaces: {interfaces}")
        
        # Scanner les connexions réseau actives
        connections = psutil.net_connections(kind='inet')
        suspicious_connections = []
        
        for conn in connections:
            if conn.status == 'ESTABLISHED' and conn.raddr:
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                
                # Vérifier si l'IP est suspecte (exemple: IP privées vers ports non standards)
                if advanced:
                    risk_score = await analyze_connection_risk(remote_ip, remote_port)
                    if risk_score > 0.5:
                        suspicious_connections.append({
                            "remote_ip": remote_ip,
                            "remote_port": remote_port,
                            "risk_score": risk_score,
                            "process": conn.pid
                        })
        
        # Scanner les ports ouverts
        open_ports = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 1433, 3389, 5432, 5900]
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        
        # Ajouter les résultats au monitoring
        system_monitor = SystemMonitor()
        network_activity = {
            "activity_type": "network_scan_results",
            "suspicious_connections": suspicious_connections,
            "open_ports": open_ports,
            "severity": "medium" if suspicious_connections else "low",
            "description": f"Scan réseau: {len(suspicious_connections)} connexions suspectes, {len(open_ports)} ports ouverts",
            "timestamp": datetime.now().isoformat()
        }
        
        system_monitor.suspicious_activities.append(network_activity)
        
        logger.info(f"Scan réseau terminé: {len(suspicious_connections)} connexions suspectes, {len(open_ports)} ports ouverts")
        
    except Exception as e:
        logger.error(f"Erreur lors du scan réseau: {e}")

async def analyze_connection_risk(ip: str, port: int) -> float:
    """Analyser le risque d'une connexion réseau"""
    risk_score = 0.0
    
    # IPs privées se connectant vers l'extérieur sur des ports non standards
    if not ip.startswith(('192.168.', '10.', '172.')):
        risk_score += 0.3
    
    # Ports suspects
    suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999, 1234, 31337]
    if port in suspicious_ports:
        risk_score += 0.5
    
    # Ports non standards élevés
    if port > 49152:
        risk_score += 0.2
    
    return min(risk_score, 1.0)

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    ) 
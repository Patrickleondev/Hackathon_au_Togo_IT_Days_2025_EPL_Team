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
from datetime import datetime
import json
import os
import tempfile
import shutil

from ml_engine.ransomware_detector import RansomwareDetector
from ml_engine.hybrid_detector import HybridDetector
from ml_engine.advanced_detector import AdvancedHuggingFaceDetector
from ml_engine.system_monitor import SystemMonitor
from ml_engine.model_loader import get_model_loader
from database.models import init_db
from utils.config import settings

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
    
    # Initialisation de la base de données
    await init_db()
    
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
        # Obtenir les métriques système
        cpu_usage = monitor.get_cpu_usage()
        memory_usage = monitor.get_memory_usage()
        
        # Obtenir les statistiques de protection
        stats = await detector.get_statistics()
        
        return SystemStatus(
            status="active",
            threats_detected=stats.get('threats_detected', 0),
            files_protected=stats.get('files_protected', 0),
            last_scan=datetime.now(),
            cpu_usage=cpu_usage,
            memory_usage=memory_usage,
            hybrid_system_active=True
        )
    except Exception as e:
        logger.error(f"Erreur lors de la récupération du statut: {e}")
        raise HTTPException(status_code=500, detail="Erreur interne du serveur")

@app.get("/api/threats")
async def get_threats():
    """Obtenir la liste des menaces détectées"""
    try:
        threats = await detector.get_detected_threats()
        return {"threats": threats, "count": len(threats)}
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des menaces: {e}")
        raise HTTPException(status_code=500, detail="Erreur interne du serveur")

@app.post("/api/scan")
async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    """Démarrer un scan du système"""
    try:
        logger.info(f"🚀 Démarrage du scan: {scan_request.scan_type}")
        
        # Ajouter le scan aux tâches en arrière-plan
        if scan_request.use_advanced_detection:
            background_tasks.add_task(hybrid_detector.perform_hybrid_scan, scan_request.scan_type, scan_request.target_paths)
        else:
            background_tasks.add_task(detector.perform_scan, scan_request.scan_type, scan_request.target_paths)
        
        return {
            "message": "Scan démarré avec succès",
            "scan_type": scan_request.scan_type,
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
            # Analyser avec le système hybride
            result = await hybrid_detector.analyze_file_hybrid(temp_path, {})
            
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
        hybrid_stats = await hybrid_detector.get_hybrid_statistics()
        model_loader_status = model_loader.get_model_status()
        
        return {
            "hybrid_detector": hybrid_stats,
            "advanced_detector": hybrid_stats.get('advanced_detector', {}),
            "huggingface_detector": hybrid_stats.get('huggingface_detector', {}),
            "traditional_detector": hybrid_stats.get('traditional_detector', {}),
            "model_loader": model_loader_status,
            "models_available": model_loader_status.get('models_available', False),
            "fallback_mode": model_loader_status.get('cache_keys', []).count('fallback_model') > 0
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

# Configuration des fichiers statiques
app.mount("/static", StaticFiles(directory="static"), name="static")

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    ) 
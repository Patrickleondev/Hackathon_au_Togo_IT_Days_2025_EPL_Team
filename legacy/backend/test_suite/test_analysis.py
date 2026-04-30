"""
Script de test pour l'analyse de fichiers
RansomGuard AI - Hackathon Togo IT Days 2025
"""

import asyncio
import os
import tempfile
import logging
from ml_engine.hybrid_detector import HybridDetector
from ml_engine.model_loader import get_model_loader

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_file_analysis():
    """Tester l'analyse de fichiers"""
    try:
        logger.info("🧪 Test de l'analyse de fichiers...")
        
        # Initialiser le détecteur hybride
        hybrid_detector = HybridDetector()
        
        # Initialiser les modèles
        init_result = await hybrid_detector.initialize()
        logger.info(f"Initialisation: {init_result}")
        
        # Créer un fichier de test
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as test_file:
            test_file.write(b"This is a test file for analysis")
            test_path = test_file.name
        
        try:
            # Analyser le fichier
            logger.info(f"Analyse du fichier: {test_path}")
            result = await hybrid_detector.analyze_file_hybrid(
                test_path, 
                {"filename": "test.txt", "upload_source": "test"}
            )
            
            logger.info("✅ Analyse réussie!")
            logger.info(f"Résultat: {result}")
            
            # Vérifier la structure du résultat
            required_fields = ['is_threat', 'confidence', 'threat_type', 'severity']
            for field in required_fields:
                if field not in result:
                    logger.error(f"❌ Champ manquant: {field}")
                else:
                    logger.info(f"✅ {field}: {result[field]}")
            
        finally:
            # Nettoyer le fichier de test
            if os.path.exists(test_path):
                os.unlink(test_path)
        
        logger.info("🎉 Test terminé avec succès!")
        
    except Exception as e:
        logger.error(f"❌ Erreur lors du test: {e}")
        raise

async def test_model_loading():
    """Tester le chargement des modèles"""
    try:
        logger.info("🧪 Test du chargement des modèles...")
        
        model_loader = get_model_loader()
        load_result = model_loader.load_models()
        
        logger.info(f"Résultat du chargement: {load_result}")
        
        if load_result.get('success', False):
            logger.info("✅ Modèles chargés avec succès!")
            
            # Vérifier les modèles disponibles
            model_data = load_result.get('model_data', {})
            if 'models' in model_data:
                models = model_data['models']
                logger.info(f"📊 Modèles disponibles: {list(models.keys())}")
                
                for name, model in models.items():
                    logger.info(f"  • {name}: {type(model).__name__}")
        else:
            logger.warning("⚠️ Échec du chargement des modèles")
        
    except Exception as e:
        logger.error(f"❌ Erreur lors du test de chargement: {e}")
        raise

async def main():
    """Fonction principale de test"""
    logger.info("🚀 Démarrage des tests...")
    
    # Test 1: Chargement des modèles
    await test_model_loading()
    
    # Test 2: Analyse de fichiers
    await test_file_analysis()
    
    logger.info("🎯 Tous les tests terminés!")

if __name__ == "__main__":
    asyncio.run(main())

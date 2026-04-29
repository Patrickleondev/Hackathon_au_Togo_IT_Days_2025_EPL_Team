#!/usr/bin/env python3
"""
Script de démarrage de l'entraînement des modèles
RansomGuard AI - Hackathon Togo IT Days 2025
"""

import asyncio
import logging
import os
import sys
from pathlib import Path

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Fonction principale pour démarrer l'entraînement"""
    try:
        logger.info("🚀 Démarrage de l'entraînement des modèles pour le hackathon...")
        
        # Vérifier que nous sommes dans le bon répertoire
        if not os.path.exists("train_models_for_hackathon.py"):
            logger.error("❌ Script d'entraînement non trouvé. Assurez-vous d'être dans le répertoire backend/")
            sys.exit(1)
        
        # Créer le dossier models s'il n'existe pas
        models_dir = Path("models")
        models_dir.mkdir(exist_ok=True)
        logger.info(f"📁 Dossier models créé/vérifié: {models_dir.absolute()}")
        
        # Importer et exécuter l'entraînement
        from train_models_for_hackathon import main as train_main
        
        logger.info("🔄 Lancement de l'entraînement unifié...")
        asyncio.run(train_main())
        
        logger.info("✅ Entraînement terminé avec succès!")
        
        # Vérifier les fichiers créés
        model_files = list(models_dir.glob("*.pkl"))
        metadata_files = list(models_dir.glob("*.json"))
        
        logger.info(f"📊 Fichiers de modèles créés: {len(model_files)}")
        for file in model_files:
            logger.info(f"  - {file.name}")
        
        logger.info(f"📋 Fichiers de métadonnées créés: {len(metadata_files)}")
        for file in metadata_files:
            logger.info(f"  - {file.name}")
        
        # Vérifier le modèle frontend unifié
        frontend_model = models_dir / "frontend_unified_model.pkl"
        if frontend_model.exists():
            logger.info("✅ Modèle frontend unifié créé avec succès!")
        else:
            logger.warning("⚠️ Modèle frontend unifié non trouvé")
        
        logger.info("\n🎯 Les modèles sont prêts pour l'utilisation!")
        logger.info("💡 Vous pouvez maintenant lancer le backend avec: python main.py")
        
    except ImportError as e:
        logger.error(f"❌ Erreur d'import: {e}")
        logger.error("Assurez-vous que toutes les dépendances sont installées:")
        logger.error("pip install -r requirements.txt")
        sys.exit(1)
        
    except Exception as e:
        logger.error(f"❌ Erreur lors de l'entraînement: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 
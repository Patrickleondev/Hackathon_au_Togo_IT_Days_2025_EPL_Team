#!/usr/bin/env python3
"""
Script d'entraînement pour les modèles Hugging Face
RansomGuard AI - Hackathon Togo IT Days 2025
"""

import asyncio
import json
import logging
from pathlib import Path
from ml_engine.huggingface_detector import HuggingFaceDetector

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Données d'entraînement simulées pour le ransomware
TRAINING_DATA = [
    # Exemples de ransomware
    {
        "text": "filename: encrypt_files.exe | extension: .exe | size: 2048576 bytes | suspicious_patterns: filename_contains_encrypt",
        "is_threat": True
    },
    {
        "text": "filename: crypto_locker.exe | extension: .exe | size: 1536000 bytes | suspicious_patterns: filename_contains_crypto",
        "is_threat": True
    },
    {
        "text": "filename: ransom_note.txt | extension: .txt | size: 1024 bytes | suspicious_patterns: filename_contains_ransom",
        "is_threat": True
    },
    {
        "text": "filename: bitcoin_wallet.dat | extension: .dat | size: 512000 bytes | suspicious_patterns: filename_contains_bitcoin",
        "is_threat": True
    },
    {
        "text": "filename: decrypt_instructions.pdf | extension: .pdf | size: 256000 bytes | suspicious_patterns: filename_contains_decrypt",
        "is_threat": True
    },
    {
        "text": "process: crypto_miner.exe | cpu_usage: 85.2% | memory_usage: 45.8% | suspicious_patterns: process_contains_crypto",
        "is_threat": True
    },
    {
        "text": "process: encrypt_process.exe | cpu_usage: 92.1% | memory_usage: 67.3% | suspicious_patterns: process_contains_encrypt",
        "is_threat": True
    },
    {
        "text": "filename: locked_files.encrypted | extension: .encrypted | size: 1048576 bytes | suspicious_patterns: filename_contains_locked",
        "is_threat": True
    },
    {
        "text": "filename: pay_ransom.html | extension: .html | size: 8192 bytes | suspicious_patterns: filename_contains_pay",
        "is_threat": True
    },
    {
        "text": "filename: malware_virus.exe | extension: .exe | size: 3072000 bytes | suspicious_patterns: filename_contains_malware",
        "is_threat": True
    },
    
    # Exemples de fichiers normaux
    {
        "text": "filename: document.pdf | extension: .pdf | size: 1024000 bytes",
        "is_threat": False
    },
    {
        "text": "filename: image.jpg | extension: .jpg | size: 512000 bytes",
        "is_threat": False
    },
    {
        "text": "filename: spreadsheet.xlsx | extension: .xlsx | size: 256000 bytes",
        "is_threat": False
    },
    {
        "text": "filename: presentation.pptx | extension: .pptx | size: 2048000 bytes",
        "is_threat": False
    },
    {
        "text": "filename: text_file.txt | extension: .txt | size: 2048 bytes",
        "is_threat": False
    },
    {
        "text": "process: chrome.exe | cpu_usage: 15.3% | memory_usage: 25.7%",
        "is_threat": False
    },
    {
        "text": "process: word.exe | cpu_usage: 8.2% | memory_usage: 12.4%",
        "is_threat": False
    },
    {
        "text": "filename: backup.zip | extension: .zip | size: 52428800 bytes",
        "is_threat": False
    },
    {
        "text": "filename: photo.png | extension: .png | size: 1024000 bytes",
        "is_threat": False
    },
    {
        "text": "filename: music.mp3 | extension: .mp3 | size: 4096000 bytes",
        "is_threat": False
    }
]

# Données de test
TEST_DATA = [
    {
        "text": "filename: suspicious_encrypt.exe | extension: .exe | size: 1048576 bytes | suspicious_patterns: filename_contains_encrypt",
        "is_threat": True
    },
    {
        "text": "filename: normal_document.docx | extension: .docx | size: 512000 bytes",
        "is_threat": False
    },
    {
        "text": "process: suspicious_crypto.exe | cpu_usage: 78.5% | memory_usage: 45.2% | suspicious_patterns: process_contains_crypto",
        "is_threat": True
    },
    {
        "text": "filename: image.png | extension: .png | size: 2048000 bytes",
        "is_threat": False
    }
]

async def train_models():
    """Entraîner les modèles Hugging Face"""
    try:
        logger.info(" Démarrage de l'entraînement des modèles...")
        
        # Initialiser le détecteur
        detector = HuggingFaceDetector()
        
        # Vérifier que les modèles sont chargés
        model_info = detector.get_model_info()
        logger.info(f" Modèles chargés: {model_info['loaded_models']}")
        
        if not model_info['loaded_models']:
            logger.error("Aucun modèle chargé")
            return False
        
        # Entraîner chaque modèle
        for model_name in model_info['loaded_models']:
            logger.info(f" Entraînement du modèle {model_name}...")
            
            try:
                success = await detector.fine_tune_model(TRAINING_DATA, model_name)
                
                if success:
                    logger.info(f" Modèle {model_name} entraîné avec succès")
                else:
                    logger.error(f" Échec de l'entraînement du modèle {model_name}")
                    
            except Exception as e:
                logger.error(f" Erreur lors de l'entraînement de {model_name}: {e}")
                continue
        
        # Tester la performance
        logger.info(" Test de performance des modèles...")
        performance_results = await detector.test_model_performance(TEST_DATA)
        
        logger.info("📈 Résultats de performance:")
        for model_name, results in performance_results.items():
            if 'accuracy' in results:
                accuracy = results['accuracy'] * 100
                logger.info(f"  {model_name}: {accuracy:.1f}% de précision")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Erreur lors de l'entraînement: {e}")
        return False

async def test_models():
    """Tester les modèles entraînés"""
    try:
        logger.info("🧪 Test des modèles...")
        
        detector = HuggingFaceDetector()
        
        # Test avec des exemples
        test_cases = [
            {
                "file_path": "/test/encrypt_files.exe",
                "process_info": {"process_name": "encrypt.exe", "cpu_percent": 85.0, "memory_percent": 60.0}
            },
            {
                "file_path": "/test/document.pdf", 
                "process_info": {"process_name": "chrome.exe", "cpu_percent": 15.0, "memory_percent": 25.0}
            }
        ]
        
        for i, test_case in enumerate(test_cases):
            logger.info(f"Test {i+1}: {test_case['file_path']}")
            
            result = await detector.analyze_with_huggingface(
                test_case['file_path'], 
                test_case['process_info']
            )
            
            logger.info(f"  Résultat: {'Menace' if result['is_threat'] else 'Normal'}")
            logger.info(f"  Score: {result['ensemble_score']:.3f}")
            logger.info(f"  Confiance: {result['confidence']:.3f}")
            
            # Afficher les prédictions individuelles
            for model_name, prediction in result.get('model_predictions', {}).items():
                logger.info(f"    {model_name}: {prediction['threat_score']:.3f}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Erreur lors du test: {e}")
        return False

async def main():
    """Fonction principale"""
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║              🛡️ Entraînement RansomGuard AI 🛡️                ║
    ║                                                              ║
    ║           Fine-tuning des modèles Hugging Face               ║
    ║                    Hackathon TID 2025                       ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Créer le dossier models s'il n'existe pas
    Path("models").mkdir(exist_ok=True)
    
    # Entraîner les modèles
    success = await train_models()
    
    if success:
        logger.info("✅ Entraînement terminé avec succès")
        
        # Tester les modèles
        await test_models()
        
        logger.info("🎉 Tous les modèles sont prêts!")
        logger.info("📁 Modèles sauvegardés dans le dossier 'models/'")
        
    else:
        logger.error("❌ Échec de l'entraînement")

if __name__ == "__main__":
    asyncio.run(main()) 
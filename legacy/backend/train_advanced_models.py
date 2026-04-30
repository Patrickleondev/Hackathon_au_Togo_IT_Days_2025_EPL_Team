"""
Script d'entraînement avancé pour les modèles de détection
RansomGuard AI - Hackathon Togo IT Days 2025
"""

import asyncio
import logging
import json
import os
from datetime import datetime
from typing import List, Dict, Any
import pandas as pd
import numpy as np

from ml_engine.hybrid_detector import HybridDetector
from ml_engine.advanced_detector import AdvancedHuggingFaceDetector

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AdvancedModelTrainer:
    """Entraîneur avancé pour les modèles de détection"""
    
    def __init__(self):
        self.hybrid_detector = HybridDetector()
        self.advanced_detector = AdvancedHuggingFaceDetector()
        
        # Configuration d'entraînement
        self.training_config = {
            'epochs': 10,
            'batch_size': 16,
            'learning_rate': 2e-5,
            'warmup_steps': 500,
            'weight_decay': 0.01,
            'eval_steps': 100,
            'save_steps': 500
        }
        
        # Dossiers de sauvegarde
        self.model_dirs = {
            'huggingface': 'models/huggingface_fine_tuned',
            'advanced': 'models/advanced_fine_tuned',
            'hybrid': 'models/hybrid_ensemble'
        }
        
        # Créer les dossiers
        for dir_path in self.model_dirs.values():
            os.makedirs(dir_path, exist_ok=True)
    
    def generate_synthetic_training_data(self, num_samples: int = 1000) -> List[Dict[str, Any]]:
        """Générer des données d'entraînement synthétiques avec techniques d'évasion"""
        logger.info(f"🔄 Génération de {num_samples} échantillons d'entraînement...")
        
        training_data = []
        
        # Patterns de ransomware avec évasion
        ransomware_patterns = [
            "encrypt files ransom bitcoin payment",
            "crypto locker decrypt wallet",
            "wannacry encrypt system files",
            "trojan ransomware encrypt documents",
            "malware encrypt user files",
            "virus encrypt hard drive",
            "backdoor encrypt system",
            "rootkit encrypt data",
            "spyware encrypt personal files",
            "adware encrypt photos"
        ]
        
        # Techniques d'évasion
        evasion_techniques = [
            "sleep delay timeout wait",
            "mouse movement keyboard input",
            "system info vm detection",
            "packing obfuscation encryption",
            "polymorphic metamorphic code",
            "code injection process hollowing",
            "file operations registry changes",
            "network activity process creation",
            "service installation scheduled tasks",
            "sandbox evasion antivirus bypass"
        ]
        
        # Générer des échantillons positifs (ransomware)
        for i in range(num_samples // 2):
            # Choisir un pattern de ransomware
            base_pattern = np.random.choice(ransomware_patterns)
            
            # Ajouter des techniques d'évasion
            num_evasion = np.random.randint(1, 4)
            selected_evasions = np.random.choice(evasion_techniques, num_evasion, replace=False)
            
            # Créer le texte d'entraînement
            training_text = f"{base_pattern} {' '.join(selected_evasions)}"
            
            # Scores d'évasion simulés
            evasion_scores = {
                'sandbox_evasion': np.random.uniform(0.3, 0.9),
                'antivirus_evasion': np.random.uniform(0.4, 0.8),
                'behavioral_evasion': np.random.uniform(0.2, 0.7),
                'anomaly_detection': np.random.uniform(0.1, 0.6)
            }
            
            training_data.append({
                'text': training_text,
                'is_threat': True,
                'evasion_scores': evasion_scores,
                'threat_type': 'ransomware',
                'confidence': np.random.uniform(0.7, 1.0)
            })
        
        # Générer des échantillons négatifs (fichiers normaux)
        normal_patterns = [
            "document text file normal",
            "image photo picture safe",
            "video movie film clean",
            "music song audio legitimate",
            "application software program safe",
            "data backup restore normal",
            "configuration settings file clean",
            "log file system normal",
            "database record information safe",
            "archive zip rar legitimate"
        ]
        
        for i in range(num_samples // 2):
            # Choisir un pattern normal
            base_pattern = np.random.choice(normal_patterns)
            
            # Ajouter quelques mots aléatoires
            additional_words = np.random.choice([
                "user", "system", "file", "data", "information",
                "process", "memory", "network", "security", "access"
            ], np.random.randint(2, 5), replace=False)
            
            training_text = f"{base_pattern} {' '.join(additional_words)}"
            
            # Scores d'évasion faibles
            evasion_scores = {
                'sandbox_evasion': np.random.uniform(0.0, 0.2),
                'antivirus_evasion': np.random.uniform(0.0, 0.1),
                'behavioral_evasion': np.random.uniform(0.0, 0.3),
                'anomaly_detection': np.random.uniform(0.0, 0.2)
            }
            
            training_data.append({
                'text': training_text,
                'is_threat': False,
                'evasion_scores': evasion_scores,
                'threat_type': 'normal',
                'confidence': np.random.uniform(0.8, 1.0)
            })
        
        logger.info(f"✅ {len(training_data)} échantillons générés")
        return training_data
    
    def generate_evasion_training_data(self, num_samples: int = 500) -> List[Dict[str, Any]]:
        """Générer des données spécifiques aux techniques d'évasion"""
        logger.info(f"🔄 Génération de {num_samples} échantillons d'évasion...")
        
        evasion_data = []
        
        # Techniques d'évasion avancées
        advanced_evasion_patterns = [
            # Sandbox évasion
            "sleep 30000 mouse movement detection",
            "timeout delay system info check",
            "vm detection hypervisor bypass",
            "sandbox environment analysis",
            
            # Antivirus évasion
            "packing obfuscation encryption layers",
            "polymorphic code metamorphic engine",
            "code injection process hollowing",
            "antivirus bypass signature evasion",
            
            # Behavioral évasion
            "file operations registry changes stealth",
            "network activity process creation hidden",
            "service installation scheduled tasks",
            "behavioral analysis bypass"
        ]
        
        for i in range(num_samples):
            # Choisir un pattern d'évasion
            evasion_pattern = np.random.choice(advanced_evasion_patterns)
            
            # Ajouter du contexte
            context_words = np.random.choice([
                "malware", "trojan", "virus", "backdoor", "rootkit",
                "spyware", "adware", "ransomware", "cryptominer"
            ], 1)[0]
            
            training_text = f"{context_words} {evasion_pattern}"
            
            # Scores d'évasion élevés
            evasion_scores = {
                'sandbox_evasion': np.random.uniform(0.6, 1.0),
                'antivirus_evasion': np.random.uniform(0.7, 1.0),
                'behavioral_evasion': np.random.uniform(0.5, 0.9),
                'anomaly_detection': np.random.uniform(0.4, 0.8)
            }
            
            evasion_data.append({
                'text': training_text,
                'is_threat': True,
                'evasion_scores': evasion_scores,
                'threat_type': 'evasion_technique',
                'confidence': np.random.uniform(0.8, 1.0)
            })
        
        logger.info(f"✅ {len(evasion_data)} échantillons d'évasion générés")
        return evasion_data
    
    async def train_hybrid_system(self, training_data: List[Dict[str, Any]]):
        """Entraîner le système hybride complet"""
        try:
            logger.info("🚀 Démarrage de l'entraînement du système hybride...")
            
            # Diviser les données en ensembles d'entraînement et de validation
            np.random.shuffle(training_data)
            split_idx = int(len(training_data) * 0.8)
            
            train_data = training_data[:split_idx]
            val_data = training_data[split_idx:]
            
            logger.info(f"📊 Données d'entraînement: {len(train_data)}, Validation: {len(val_data)}")
            
            # Entraîner tous les modèles
            training_results = await self.hybrid_detector.fine_tune_all_models(train_data)
            
            if training_results['success']:
                logger.info("✅ Entraînement du système hybride réussi")
                
                # Évaluer les performances
                evaluation_results = await self.evaluate_models(val_data)
                
                # Sauvegarder les résultats
                self.save_training_results(training_results, evaluation_results)
                
                return {
                    'success': True,
                    'training_results': training_results,
                    'evaluation_results': evaluation_results
                }
            else:
                logger.error("❌ Échec de l'entraînement du système hybride")
                return {'success': False, 'error': 'Training failed'}
                
        except Exception as e:
            logger.error(f"❌ Erreur lors de l'entraînement: {e}")
            return {'success': False, 'error': str(e)}
    
    async def train_advanced_evasion_detector(self, training_data: List[Dict[str, Any]]):
        """Entraîner spécifiquement le détecteur d'évasion avancé"""
        try:
            logger.info("🔄 Entraînement du détecteur d'évasion avancé...")
            
            # Filtrer les données avec des techniques d'évasion
            evasion_data = [
                data for data in training_data 
                if any(score > 0.5 for score in data.get('evasion_scores', {}).values())
            ]
            
            if len(evasion_data) < 100:
                logger.warning("⚠️ Données d'évasion insuffisantes, génération de données synthétiques")
                evasion_data.extend(self.generate_evasion_training_data(200))
            
            # Entraîner le modèle avancé
            success = await self.advanced_detector.fine_tune_model_advanced(
                evasion_data, 'distilbert_advanced'
            )
            
            if success:
                logger.info("✅ Détecteur d'évasion entraîné avec succès")
                
                # Tester la détection d'évasion
                test_files = [f"test_file_{i}.txt" for i in range(10)]
                evasion_test_results = await self.advanced_detector.test_evasion_detection(test_files)
                
                return {
                    'success': True,
                    'evasion_test_results': evasion_test_results
                }
            else:
                logger.error("❌ Échec de l'entraînement du détecteur d'évasion")
                return {'success': False}
                
        except Exception as e:
            logger.error(f"❌ Erreur lors de l'entraînement du détecteur d'évasion: {e}")
            return {'success': False, 'error': str(e)}
    
    async def evaluate_models(self, validation_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Évaluer les performances des modèles"""
        try:
            logger.info("📊 Évaluation des modèles...")
            
            results = {
                'total_samples': len(validation_data),
                'correct_predictions': 0,
                'false_positives': 0,
                'false_negatives': 0,
                'model_performance': {}
            }
            
            for data_point in validation_data:
                try:
                    # Simuler l'analyse d'un fichier
                    file_path = f"test_{hash(data_point['text']) % 1000}.txt"
                    process_info = {'cpu_percent': 0, 'memory_percent': 0}
                    
                    # Analyse hybride
                    hybrid_result = await self.hybrid_detector.analyze_file_hybrid(
                        file_path, process_info
                    )
                    
                    # Comparer avec la vérité terrain
                    predicted_threat = hybrid_result.get('is_threat', False)
                    actual_threat = data_point.get('is_threat', False)
                    
                    if predicted_threat == actual_threat:
                        results['correct_predictions'] += 1
                    elif predicted_threat and not actual_threat:
                        results['false_positives'] += 1
                    elif not predicted_threat and actual_threat:
                        results['false_negatives'] += 1
                    
                except Exception as e:
                    logger.error(f"Erreur lors de l'évaluation: {e}")
                    continue
            
            # Calculer les métriques
            total = results['total_samples']
            if total > 0:
                results['accuracy'] = results['correct_predictions'] / total
                results['precision'] = results['correct_predictions'] / (results['correct_predictions'] + results['false_positives']) if (results['correct_predictions'] + results['false_positives']) > 0 else 0
                results['recall'] = results['correct_predictions'] / (results['correct_predictions'] + results['false_negatives']) if (results['correct_predictions'] + results['false_negatives']) > 0 else 0
                
                # F1-Score
                if results['precision'] + results['recall'] > 0:
                    results['f1_score'] = 2 * (results['precision'] * results['recall']) / (results['precision'] + results['recall'])
                else:
                    results['f1_score'] = 0
            
            logger.info(f"📈 Précision: {results.get('accuracy', 0):.3f}")
            logger.info(f"📈 F1-Score: {results.get('f1_score', 0):.3f}")
            
            return results
            
        except Exception as e:
            logger.error(f"❌ Erreur lors de l'évaluation: {e}")
            return {'error': str(e)}
    
    def save_training_results(self, training_results: Dict, evaluation_results: Dict):
        """Sauvegarder les résultats d'entraînement"""
        try:
            results = {
                'timestamp': datetime.now().isoformat(),
                'training_results': training_results,
                'evaluation_results': evaluation_results,
                'training_config': self.training_config
            }
            
            # Sauvegarder dans un fichier JSON
            results_file = f"training_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            logger.info(f"💾 Résultats sauvegardés dans {results_file}")
            
        except Exception as e:
            logger.error(f"❌ Erreur lors de la sauvegarde: {e}")
    
    async def run_complete_training(self):
        """Exécuter l'entraînement complet"""
        try:
            logger.info("🎯 Démarrage de l'entraînement complet...")
            
            # 1. Générer les données d'entraînement
            training_data = self.generate_synthetic_training_data(2000)
            evasion_data = self.generate_evasion_training_data(500)
            
            # Combiner les données
            all_training_data = training_data + evasion_data
            
            # 2. Entraîner le système hybride
            hybrid_results = await self.train_hybrid_system(all_training_data)
            
            # 3. Entraîner spécifiquement le détecteur d'évasion
            evasion_results = await self.train_advanced_evasion_detector(all_training_data)
            
            # 4. Résultats finaux
            final_results = {
                'hybrid_training': hybrid_results,
                'evasion_training': evasion_results,
                'total_training_samples': len(all_training_data),
                'timestamp': datetime.now().isoformat()
            }
            
            logger.info("✅ Entraînement complet terminé")
            return final_results
            
        except Exception as e:
            logger.error(f"❌ Erreur lors de l'entraînement complet: {e}")
            return {'error': str(e)}

async def main():
    """Fonction principale"""
    trainer = AdvancedModelTrainer()
    
    # Exécuter l'entraînement complet
    results = await trainer.run_complete_training()
    
    if 'error' not in results:
        print("🎉 Entraînement terminé avec succès!")
        print(f"📊 Échantillons d'entraînement: {results['total_training_samples']}")
    else:
        print(f"❌ Erreur lors de l'entraînement: {results['error']}")

if __name__ == "__main__":
    asyncio.run(main()) 
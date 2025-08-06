"""
Système de détection hybride combinant IA traditionnelle et modèles Hugging Face
RansomGuard AI - Hackathon Togo IT Days 2025
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import json
import hashlib
import os

from .ransomware_detector import RansomwareDetector
from .huggingface_detector import HuggingFaceDetector
from .advanced_detector import AdvancedHuggingFaceDetector
from .model_loader import get_model_loader

logger = logging.getLogger(__name__)

class HybridDetector:
    """
    Système de détection hybride combinant plusieurs approches
    """
    
    def __init__(self):
        self.ransomware_detector = RansomwareDetector()
        self.huggingface_detector = HuggingFaceDetector()
        self.advanced_detector = AdvancedHuggingFaceDetector()
        self.model_loader = get_model_loader()
        
        # Configuration des poids pour l'ensemble
        self.ensemble_weights = {
            'traditional': 0.3,      # Détecteur traditionnel
            'huggingface': 0.4,      # Modèles Hugging Face
            'advanced': 0.3           # Détecteur avancé avec évasion
        }
        
        # Seuils adaptatifs
        self.adaptive_thresholds = {
            'low_risk': 0.6,
            'medium_risk': 0.75,
            'high_risk': 0.85
        }
        
        # Cache pour les résultats
        self.results_cache = {}
        
        # Statut d'initialisation
        self.initialized = False
        
    async def initialize(self):
        """Initialiser le système hybride avec les modèles entraînés"""
        try:
            logger.info("🔄 Initialisation du système hybride...")
            
            # Charger les modèles entraînés
            model_load_result = self.model_loader.load_models()
            
            if model_load_result.get('success', False):
                logger.info("✅ Modèles entraînés chargés avec succès")
                self.initialized = True
                
                # Vérifier les modèles disponibles
                model_data = model_load_result.get('model_data', {})
                if 'models' in model_data:
                    models = model_data['models']
                    logger.info(f"📊 Modèles disponibles: {list(models.keys())}")
                    
                    # Vérifier les métadonnées
                    metadata = model_data.get('metadata', {})
                    if metadata.get('hackathon_optimized', False):
                        logger.info("🎯 Modèles optimisés pour le hackathon détectés")
                    
                    return {
                        'success': True,
                        'models_loaded': True,
                        'models_count': len(models),
                        'hackathon_optimized': metadata.get('hackathon_optimized', False),
                        'version': model_data.get('version', '1.0.0')
                    }
                else:
                    logger.warning("⚠️ Aucun modèle trouvé dans les données")
                    return {
                        'success': False,
                        'error': 'Aucun modèle trouvé',
                        'fallback': True
                    }
            else:
                logger.warning("⚠️ Utilisation des modèles de fallback")
                return {
                    'success': False,
                    'error': 'Impossible de charger les modèles entraînés',
                    'fallback': True
                }
                
        except Exception as e:
            logger.error(f"❌ Erreur lors de l'initialisation: {e}")
            return {
                'success': False,
                'error': str(e),
                'fallback': True
            }
    
    async def analyze_file_hybrid(self, file_path: str, process_info: Dict) -> Dict[str, Any]:
        """Analyser un fichier avec tous les détecteurs"""
        try:
            logger.info(f"🔍 Analyse hybride de {file_path}")
            
            # Vérifier l'initialisation
            if not self.initialized:
                init_result = await self.initialize()
                if not init_result.get('success', False):
                    logger.warning("⚠️ Système non initialisé, utilisation des modèles de base")
            
            # 1. Analyse avec le détecteur traditionnel (utilise les modèles entraînés)
            traditional_result = await self._analyze_traditional(file_path, process_info)
            
            # 2. Analyse avec Hugging Face
            huggingface_result = await self._analyze_huggingface(file_path, process_info)
            
            # 3. Analyse avec le détecteur avancé
            advanced_result = await self._analyze_advanced(file_path, process_info)
            
            # 4. Combiner les résultats
            combined_result = self._combine_results(
                traditional_result,
                huggingface_result,
                advanced_result
            )
            
            # 5. Décision finale avec seuils adaptatifs
            final_decision = self._make_final_decision(combined_result)
            
            # 6. Sauvegarder dans le cache
            cache_key = hashlib.md5(f"{file_path}_{datetime.now().timestamp()}".encode()).hexdigest()
            self.results_cache[cache_key] = {
                'timestamp': datetime.now().isoformat(),
                'file_path': file_path,
                'final_decision': final_decision,
                'individual_results': {
                    'traditional': traditional_result,
                    'huggingface': huggingface_result,
                    'advanced': advanced_result
                },
                'combined_result': combined_result
            }
            
            return final_decision
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse hybride: {e}")
            return {
                'is_threat': False,
                'confidence': 0,
                'risk_level': 'unknown',
                'error': str(e)
            }
    
    async def _analyze_traditional(self, file_path: str, process_info: Dict) -> Dict[str, Any]:
        """Analyse avec le détecteur traditionnel utilisant les modèles entraînés"""
        try:
            # Extraire les caractéristiques
            features = await self.ransomware_detector.extract_features(file_path, process_info)
            
            # Obtenir les modèles entraînés
            trained_models = self.model_loader.get_model()
            
            if trained_models and 'models' in trained_models:
                # Utiliser les modèles entraînés pour la prédiction
                predictions = []
                confidences = []
                
                for model_name, model in trained_models['models'].items():
                    try:
                        # Prédire avec le modèle entraîné
                        prediction = model.predict([features])[0]
                        confidence = model.predict_proba([features])[0].max() if hasattr(model, 'predict_proba') else 0.8
                        
                        predictions.append(prediction)
                        confidences.append(confidence)
                        
                        logger.debug(f"Modèle {model_name}: prédiction={prediction}, confiance={confidence:.3f}")
                        
                    except Exception as e:
                        logger.warning(f"Erreur avec le modèle {model_name}: {e}")
                        continue
                
                if predictions:
                    # Vote majoritaire
                    final_prediction = 1 if sum(predictions) > len(predictions) / 2 else 0
                    avg_confidence = sum(confidences) / len(confidences)
                    
                    return {
                        'is_threat': bool(final_prediction),
                        'confidence': avg_confidence,
                        'ensemble_score': avg_confidence if final_prediction else 1 - avg_confidence,
                        'method': 'trained_models',
                        'models_used': len(predictions)
                    }
            
            # Fallback vers l'analyse traditionnelle
            logger.info("Utilisation de l'analyse traditionnelle de fallback")
            return await self.ransomware_detector.analyze_file(file_path, process_info)
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse traditionnelle: {e}")
            return {
                'is_threat': False,
                'confidence': 0,
                'ensemble_score': 0,
                'error': str(e)
            }
    
    async def _analyze_huggingface(self, file_path: str, process_info: Dict) -> Dict[str, Any]:
        """Analyse avec les modèles Hugging Face"""
        try:
            result = await self.huggingface_detector.analyze_with_huggingface(file_path, process_info)
            
            return {
                'method': 'huggingface',
                'is_threat': result['is_threat'],
                'confidence': result['confidence'],
                'ensemble_score': result['ensemble_score'],
                'model_predictions': result['model_predictions']
            }
            
        except Exception as e:
            logger.error(f"Erreur dans l'analyse Hugging Face: {e}")
            return {
                'method': 'huggingface',
                'is_threat': False,
                'confidence': 0,
                'ensemble_score': 0,
                'error': str(e)
            }
    
    async def _analyze_advanced(self, file_path: str, process_info: Dict) -> Dict[str, Any]:
        """Analyse avec le détecteur avancé"""
        try:
            # Utiliser l'analyse asynchrone
            task_id = await self.advanced_detector.analyze_file_async(file_path, process_info)
            
            # Attendre le résultat
            max_wait = 30  # 30 secondes max
            wait_time = 0
            while wait_time < max_wait:
                result = await self.advanced_detector.get_analysis_result(task_id)
                if result:
                    return {
                        'method': 'advanced',
                        'is_threat': result['is_threat'],
                        'confidence': result['confidence'],
                        'ensemble_score': result['ensemble_score'],
                        'evasion_scores': result['evasion_scores'],
                        'threshold_used': result['threshold_used']
                    }
                
                await asyncio.sleep(0.5)
                wait_time += 0.5
            
            # Timeout
            return {
                'method': 'advanced',
                'is_threat': False,
                'confidence': 0,
                'ensemble_score': 0,
                'error': 'timeout'
            }
            
        except Exception as e:
            logger.error(f"Erreur dans l'analyse avancée: {e}")
            return {
                'method': 'advanced',
                'is_threat': False,
                'confidence': 0,
                'ensemble_score': 0,
                'error': str(e)
            }
    
    def _combine_results(self, traditional: Dict, huggingface: Dict, advanced: Dict) -> Dict[str, Any]:
        """Combiner les résultats des différents détecteurs"""
        try:
            # Calculer le score pondéré
            weighted_score = 0
            total_weight = 0
            
            # Score traditionnel
            if 'ensemble_score' in traditional and not 'error' in traditional:
                weighted_score += traditional['ensemble_score'] * self.ensemble_weights['traditional']
                total_weight += self.ensemble_weights['traditional']
            
            # Score Hugging Face
            if 'ensemble_score' in huggingface and not 'error' in huggingface:
                weighted_score += huggingface['ensemble_score'] * self.ensemble_weights['huggingface']
                total_weight += self.ensemble_weights['huggingface']
            
            # Score avancé
            if 'ensemble_score' in advanced and not 'error' in advanced:
                weighted_score += advanced['ensemble_score'] * self.ensemble_weights['advanced']
                total_weight += self.ensemble_weights['advanced']
            
            # Normaliser le score
            if total_weight > 0:
                final_score = weighted_score / total_weight
            else:
                final_score = 0
            
            # Analyser les techniques d'évasion
            evasion_analysis = self._analyze_evasion_techniques(advanced)
            
            # Déterminer le niveau de risque
            risk_level = self._determine_risk_level(final_score, evasion_analysis)
            
            return {
                'final_score': final_score,
                'risk_level': risk_level,
                'evasion_analysis': evasion_analysis,
                'method_agreement': self._calculate_method_agreement(traditional, huggingface, advanced),
                'confidence': self._calculate_confidence(traditional, huggingface, advanced)
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la combinaison des résultats: {e}")
            return {
                'final_score': 0,
                'risk_level': 'unknown',
                'evasion_analysis': {},
                'method_agreement': 0,
                'confidence': 0,
                'error': str(e)
            }
    
    def _analyze_evasion_techniques(self, advanced_result: Dict) -> Dict[str, Any]:
        """Analyser les techniques d'évasion"""
        if 'evasion_scores' not in advanced_result:
            return {}
        
        evasion_scores = advanced_result['evasion_scores']
        
        # Calculer le score d'évasion global
        total_evasion = sum(evasion_scores.values()) / len(evasion_scores) if evasion_scores else 0
        
        # Déterminer les techniques les plus utilisées
        high_risk_techniques = [
            technique for technique, score in evasion_scores.items()
            if score > 0.7
        ]
        
        return {
            'total_evasion_score': total_evasion,
            'high_risk_techniques': high_risk_techniques,
            'technique_count': len(high_risk_techniques),
            'is_sophisticated_attack': len(high_risk_techniques) >= 2
        }
    
    def _determine_risk_level(self, final_score: float, evasion_analysis: Dict) -> str:
        """Déterminer le niveau de risque"""
        # Ajuster le score en fonction des techniques d'évasion
        evasion_penalty = evasion_analysis.get('total_evasion_score', 0) * 0.2
        adjusted_score = min(final_score + evasion_penalty, 1.0)
        
        if adjusted_score >= self.adaptive_thresholds['high_risk']:
            return 'high'
        elif adjusted_score >= self.adaptive_thresholds['medium_risk']:
            return 'medium'
        elif adjusted_score >= self.adaptive_thresholds['low_risk']:
            return 'low'
        else:
            return 'safe'
    
    def _calculate_method_agreement(self, traditional: Dict, huggingface: Dict, advanced: Dict) -> float:
        """Calculer l'accord entre les méthodes"""
        agreements = []
        
        # Comparer les décisions binaires
        decisions = []
        if 'is_threat' in traditional and 'error' not in traditional:
            decisions.append(traditional['is_threat'])
        if 'is_threat' in huggingface and 'error' not in huggingface:
            decisions.append(huggingface['is_threat'])
        if 'is_threat' in advanced and 'error' not in advanced:
            decisions.append(advanced['is_threat'])
        
        if len(decisions) >= 2:
            # Calculer le pourcentage d'accord
            agreement = sum(decisions) / len(decisions)
            agreements.append(agreement)
        
        return sum(agreements) / len(agreements) if agreements else 0
    
    def _calculate_confidence(self, traditional: Dict, huggingface: Dict, advanced: Dict) -> float:
        """Calculer la confiance globale"""
        confidences = []
        
        if 'confidence' in traditional and 'error' not in traditional:
            confidences.append(traditional['confidence'])
        if 'confidence' in huggingface and 'error' not in huggingface:
            confidences.append(huggingface['confidence'])
        if 'confidence' in advanced and 'error' not in advanced:
            confidences.append(advanced['confidence'])
        
        return sum(confidences) / len(confidences) if confidences else 0
    
    def _make_final_decision(self, combined_result: Dict) -> Dict[str, Any]:
        """Prendre la décision finale"""
        final_score = combined_result['final_score']
        risk_level = combined_result['risk_level']
        confidence = combined_result['confidence']
        
        # Décision basée sur le score et le niveau de risque
        is_threat = risk_level in ['high', 'medium']
        
        # Recommandations d'action
        recommendations = self._generate_recommendations(combined_result)
        
        return {
            'is_threat': is_threat,
            'confidence': confidence,
            'risk_level': risk_level,
            'final_score': final_score,
            'recommendations': recommendations,
            'timestamp': datetime.now().isoformat(),
            'analysis_method': 'hybrid'
        }
    
    def _generate_recommendations(self, combined_result: Dict) -> List[str]:
        """Générer des recommandations basées sur l'analyse"""
        recommendations = []
        
        risk_level = combined_result['risk_level']
        evasion_analysis = combined_result['evasion_analysis']
        
        if risk_level == 'high':
            recommendations.extend([
                "Quarantaine immédiate recommandée",
                "Analyse approfondie requise",
                "Notification à l'administrateur"
            ])
        elif risk_level == 'medium':
            recommendations.extend([
                "Surveillance renforcée",
                "Analyse complémentaire recommandée"
            ])
        
        # Recommandations basées sur les techniques d'évasion
        if evasion_analysis.get('is_sophisticated_attack', False):
            recommendations.append("Attaque sophistiquée détectée - vigilance maximale")
        
        if evasion_analysis.get('technique_count', 0) > 0:
            recommendations.append(f"{evasion_analysis['technique_count']} techniques d'évasion détectées")
        
        return recommendations
    
    async def perform_hybrid_scan(self, scan_type: str = "quick", target_paths: List[str] = None):
        """Effectuer un scan hybride complet"""
        try:
            logger.info(f"🚀 Démarrage du scan hybride: {scan_type}")
            
            # Utiliser le scan traditionnel comme base
            await self.ransomware_detector.perform_scan(scan_type, target_paths)
            
            # Analyser les menaces détectées avec les autres méthodes
            threats = await self.ransomware_detector.get_detected_threats()
            
            enhanced_threats = []
            for threat in threats:
                try:
                    # Analyse hybride de chaque menace
                    hybrid_result = await self.analyze_file_hybrid(
                        threat['file_path'],
                        threat.get('process_info', {})
                    )
                    
                    # Enrichir les informations de menace
                    enhanced_threat = {
                        **threat,
                        'hybrid_analysis': hybrid_result,
                        'risk_level': hybrid_result.get('risk_level', 'unknown'),
                        'confidence': hybrid_result.get('confidence', 0),
                        'recommendations': hybrid_result.get('recommendations', [])
                    }
                    
                    enhanced_threats.append(enhanced_threat)
                    
                except Exception as e:
                    logger.error(f"Erreur lors de l'analyse hybride de {threat['file_path']}: {e}")
                    enhanced_threats.append(threat)
            
            return enhanced_threats
            
        except Exception as e:
            logger.error(f"Erreur lors du scan hybride: {e}")
            return []
    
    async def get_hybrid_statistics(self) -> Dict[str, Any]:
        """Obtenir les statistiques du système hybride"""
        try:
            # Statistiques des différents détecteurs
            traditional_stats = await self.ransomware_detector.get_statistics()
            huggingface_stats = self.huggingface_detector.get_model_info()
            advanced_stats = self.advanced_detector.get_model_statistics()
            
            return {
                'hybrid_system': {
                    'total_detectors': 3,
                    'ensemble_weights': self.ensemble_weights,
                    'adaptive_thresholds': self.adaptive_thresholds,
                    'cache_size': len(self.results_cache)
                },
                'traditional_detector': traditional_stats,
                'huggingface_detector': huggingface_stats,
                'advanced_detector': advanced_stats,
                'system_health': {
                    'all_detectors_loaded': len(self.ransomware_detector.models) > 0 and 
                                          len(self.huggingface_detector.models) > 0 and
                                          len(self.advanced_detector.models) > 0,
                    'background_processor_active': self.advanced_detector.background_thread.is_alive()
                }
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des statistiques: {e}")
            return {'error': str(e)}
    
    async def fine_tune_all_models(self, training_data: List[Dict[str, Any]]):
        """Fine-tuner tous les modèles avec les nouvelles données"""
        try:
            logger.info("🔄 Fine-tuning de tous les modèles...")
            
            results = {}
            
            # Fine-tuning du modèle Hugging Face
            try:
                huggingface_success = await self.huggingface_detector.fine_tune_model(
                    training_data, 'distilbert'
                )
                results['huggingface'] = huggingface_success
            except Exception as e:
                logger.error(f"Erreur fine-tuning Hugging Face: {e}")
                results['huggingface'] = False
            
            # Fine-tuning du modèle avancé
            try:
                advanced_success = await self.advanced_detector.fine_tune_model_advanced(
                    training_data, 'distilbert_advanced'
                )
                results['advanced'] = advanced_success
            except Exception as e:
                logger.error(f"Erreur fine-tuning avancé: {e}")
                results['advanced'] = False
            
            # Entraînement des modèles traditionnels
            try:
                await self.ransomware_detector.train_models(training_data)
                results['traditional'] = True
            except Exception as e:
                logger.error(f"Erreur entraînement traditionnel: {e}")
                results['traditional'] = False
            
            success_count = sum(results.values())
            total_models = len(results)
            
            logger.info(f"✅ Fine-tuning terminé: {success_count}/{total_models} modèles mis à jour")
            
            return {
                'success': success_count == total_models,
                'results': results,
                'success_rate': success_count / total_models
            }
            
        except Exception as e:
            logger.error(f"Erreur lors du fine-tuning global: {e}")
            return {'success': False, 'error': str(e)} 
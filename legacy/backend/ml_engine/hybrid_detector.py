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
import numpy as np

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
            
            # 7. S'assurer que le résultat contient tous les champs nécessaires
            if not isinstance(final_decision, dict):
                final_decision = {}
            
            # Garantir les champs requis
            result = {
                'is_threat': final_decision.get('is_threat', False),
                'confidence': final_decision.get('confidence', 0.0),
                'threat_type': final_decision.get('threat_type', 'unknown'),
                'severity': final_decision.get('severity', 'low'),
                'risk_level': final_decision.get('risk_level', 'safe'),
                'final_score': final_decision.get('final_score', 0.0),
                'recommendations': final_decision.get('recommendations', ['Analyse terminée']),
                'timestamp': final_decision.get('timestamp', datetime.now().isoformat()),
                'analysis_method': final_decision.get('analysis_method', 'hybrid'),
                'file_name': os.path.basename(file_path),
                'pattern_analysis': {
                    'malicious_patterns': traditional_result.get('malicious_patterns', 0),
                    'encryption_patterns': traditional_result.get('encryption_patterns', 0),
                    'risk_score': final_decision.get('confidence', 0.0)
                },
                'detected_strings': traditional_result.get('detected_strings', [])
            }
            
            logger.info(f"✅ Analyse hybride terminée - Score: {result['confidence']:.2f}, Menace: {result['is_threat']}")
            return result
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse hybride: {e}")
            # Retourner un résultat de fallback valide
            return {
                'is_threat': False,
                'confidence': 0.0,
                'threat_type': 'unknown',
                'severity': 'low',
                'risk_level': 'safe',
                'final_score': 0.0,
                'recommendations': ['Erreur lors de l\'analyse - Fichier considéré comme sûr'],
                'timestamp': datetime.now().isoformat(),
                'analysis_method': 'hybrid_error',
                'file_name': os.path.basename(file_path) if file_path else 'unknown',
                'pattern_analysis': {
                    'malicious_patterns': 0,
                    'encryption_patterns': 0,
                    'risk_score': 0.0
                },
                'detected_strings': [],
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
                        # S'assurer que features est un array numpy 2D
                        if isinstance(features, np.ndarray):
                            if features.ndim == 1:
                                features = features.reshape(1, -1)
                        else:
                            # Convertir en array numpy si ce n'est pas déjà le cas
                            features = np.array(features).reshape(1, -1)
                        
                        # Prédire avec le modèle entraîné
                        prediction = model.predict(features)[0]
                        confidence = model.predict_proba(features)[0].max() if hasattr(model, 'predict_proba') else 0.8
                        
                        predictions.append(prediction)
                        confidences.append(confidence)
                        
                        logger.debug(f"Modèle {model_name}: prédiction={prediction}, confiance={confidence:.3f}")
                        
                    except Exception as e:
                        logger.warning(f"Erreur avec le modèle {model_name}: {e}")
                        predictions.append(0)
                        confidences.append(0.0)
                
                if predictions:
                    # Calculer le score d'ensemble
                    ensemble_score = sum(confidences) / len(confidences)
                    is_threat = ensemble_score > 0.6  # Seuil de 60%
                    
                    return {
                        'is_threat': is_threat,
                        'confidence': ensemble_score,
                        'threat_type': 'ransomware' if is_threat else 'safe',
                        'severity': 'high' if ensemble_score > 0.8 else 'medium' if ensemble_score > 0.6 else 'low',
                        'description': f'Analyse ML traditionnelle - Score: {ensemble_score:.2f}',
                        'individual_predictions': dict(zip(trained_models['models'].keys(), predictions)),
                        'individual_confidences': dict(zip(trained_models['models'].keys(), confidences)),
                        'analysis_method': 'traditional_ml',
                        'timestamp': datetime.now().isoformat(),
                        'malicious_patterns': len([p for p in predictions if p == 1]),
                        'encryption_patterns': 0,  # À calculer si nécessaire
                        'detected_strings': features.get('suspicious_strings', []) if isinstance(features, dict) else []
                    }
                else:
                    logger.warning("Aucune prédiction valide obtenue")
                    return self._create_fallback_result("traditional")
            else:
                logger.warning("Aucun modèle entraîné disponible")
                return self._create_fallback_result("traditional")
            
        except Exception as e:
            logger.error(f"Erreur dans l'analyse traditionnelle: {e}")
            return self._create_fallback_result("traditional", str(e))
    
    async def _analyze_huggingface(self, file_path: str, process_info: Dict) -> Dict[str, Any]:
        """Analyse avec les modèles Hugging Face"""
        try:
            result = await self.huggingface_detector.analyze_with_huggingface(file_path, process_info)
            
            return {
                'method': 'huggingface',
                'is_threat': result.get('is_threat', False),
                'confidence': result.get('confidence', 0.0),
                'ensemble_score': result.get('ensemble_score', result.get('confidence', 0.0)),
                'model_predictions': result.get('model_predictions', {})
            }
            
        except Exception as e:
            logger.error(f"Erreur dans l'analyse Hugging Face: {e}")
            return {
                'method': 'huggingface',
                'is_threat': False,
                'confidence': 0.0,
                'ensemble_score': 0.0,
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
                        'is_threat': result.get('is_threat', False),
                        'confidence': result.get('confidence', 0.0),
                        'ensemble_score': result.get('ensemble_score', result.get('confidence', 0.0)),
                        'evasion_scores': result.get('evasion_scores', {}),
                        'threshold_used': result.get('threshold_used', 0.5)
                    }
                
                await asyncio.sleep(0.5)
                wait_time += 0.5
            
            # Timeout
            return {
                'method': 'advanced',
                'is_threat': False,
                'confidence': 0.0,
                'ensemble_score': 0.0,
                'error': 'timeout'
            }
            
        except Exception as e:
            logger.error(f"Erreur dans l'analyse avancée: {e}")
            return {
                'method': 'advanced',
                'is_threat': False,
                'confidence': 0.0,
                'ensemble_score': 0.0,
                'error': str(e)
            }
    
    def _combine_results(self, traditional: Dict, huggingface: Dict, advanced: Dict) -> Dict[str, Any]:
        """Combiner les résultats des différents détecteurs"""
        try:
            # Extraire les scores de confiance
            traditional_score = traditional.get('confidence', 0.0) if 'error' not in traditional else 0.0
            huggingface_score = huggingface.get('confidence', 0.0) if 'error' not in huggingface else 0.0
            advanced_score = advanced.get('confidence', 0.0) if 'error' not in advanced else 0.0
            
            # Calculer le score final pondéré
            final_score = (
                traditional_score * self.ensemble_weights['traditional'] +
                huggingface_score * self.ensemble_weights['huggingface'] +
                advanced_score * self.ensemble_weights['advanced']
            )
            
            # Normaliser le score
            final_score = min(final_score, 1.0)
            
            # Calculer l'accord entre les méthodes
            method_agreement = self._calculate_method_agreement(traditional, huggingface, advanced)
            
            # Calculer la confiance globale
            global_confidence = self._calculate_confidence(traditional, huggingface, advanced)
            
            return {
                'traditional': traditional,
                'huggingface': huggingface,
                'advanced': advanced,
                'final_score': final_score,
                'method_agreement': method_agreement,
                'global_confidence': global_confidence,
                'risk_level': self._calculate_risk_level(final_score),
                'confidence': final_score
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la combinaison des résultats: {e}")
            return {
                'traditional': traditional,
                'huggingface': huggingface,
                'advanced': advanced,
                'final_score': 0.0,
                'method_agreement': 0.0,
                'global_confidence': 0.0,
                'risk_level': 'safe',
                'confidence': 0.0
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
    
    def _create_fallback_result(self, method: str, error: str = None) -> Dict[str, Any]:
        """Créer un résultat de fallback en cas d'erreur"""
        return {
            'is_threat': False,
            'confidence': 0.0,
            'threat_type': 'unknown',
            'severity': 'low',
            'description': f'Analyse {method} - Mode fallback',
            'analysis_method': f'{method}_fallback',
            'error': error,
            'timestamp': datetime.now().isoformat()
        }
    
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
    
    def _calculate_risk_level(self, score: float) -> str:
        """Calculer le niveau de risque basé sur le score"""
        if score >= self.adaptive_thresholds['high_risk']:
            return 'high'
        elif score >= self.adaptive_thresholds['medium_risk']:
            return 'medium'
        elif score >= self.adaptive_thresholds['low_risk']:
            return 'low'
        else:
            return 'safe'
    
    def _make_final_decision(self, combined_result: Dict[str, Any]) -> Dict[str, Any]:
        """Prendre la décision finale basée sur les résultats combinés"""
        try:
            # Extraire les scores
            traditional_score = combined_result.get('traditional', {}).get('confidence', 0.0)
            huggingface_score = combined_result.get('huggingface', {}).get('confidence', 0.0)
            advanced_score = combined_result.get('advanced', {}).get('confidence', 0.0)
            
            # Calculer le score final pondéré
            final_score = (
                traditional_score * self.ensemble_weights['traditional'] +
                huggingface_score * self.ensemble_weights['huggingface'] +
                advanced_score * self.ensemble_weights['advanced']
            )
            
            # Déterminer si c'est une menace
            is_threat = final_score > 0.6  # Seuil de 60%
            
            # Déterminer le type de menace
            threat_type = "unknown"
            if is_threat:
                if final_score > 0.8:
                    threat_type = "ransomware"
                elif final_score > 0.6:
                    threat_type = "malware"
                else:
                    threat_type = "suspicious"
            
            # Déterminer la sévérité
            severity = "low"
            if final_score > 0.8:
                severity = "high"
            elif final_score > 0.6:
                severity = "medium"
            
            # Générer des recommandations
            recommendations = []
            if is_threat:
                recommendations.extend([
                    "Ne pas exécuter le fichier suspect",
                    "Isoler la machine du réseau si possible",
                    "Contacter CERT-TG au (+228) 70 54 93 25",
                    "Ne jamais payer la rançon"
                ])
            else:
                recommendations.append("Fichier analysé et considéré comme sûr")
            
            return {
                'is_threat': is_threat,
                'confidence': final_score,
                'threat_type': threat_type,
                'severity': severity,
                'risk_level': self._calculate_risk_level(final_score),
                'final_score': final_score,
                'recommendations': recommendations,
                'timestamp': datetime.now().isoformat(),
                'analysis_method': 'hybrid'
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la décision finale: {e}")
            return {
                'is_threat': False,
                'confidence': 0.0,
                'threat_type': 'unknown',
                'severity': 'low',
                'risk_level': 'safe',
                'final_score': 0.0,
                'recommendations': ["Erreur lors de l'analyse"],
                'timestamp': datetime.now().isoformat(),
                'analysis_method': 'hybrid_error'
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
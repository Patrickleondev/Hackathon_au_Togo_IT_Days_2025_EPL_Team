"""
Chargeur de modèles optimisé pour le frontend
RansomGuard AI - Hackathon Togo IT Days 2025
"""

import os
import pickle
import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class ModelLoader:
    """Chargeur de modèles optimisé pour le hackathon"""
    
    def __init__(self):
        self.models_dir = "models/"
        self.models_cache = {}
        self.load_status = {
            'models_loaded': False,
            'last_load_time': None,
            'errors': [],
            'warnings': []
        }
        
    def load_models(self) -> Dict[str, Any]:
        """Charger tous les modèles avec gestion d'erreurs"""
        try:
            logger.info(" Chargement des modèles...")
            
            # Vérifier si le dossier existe
            if not os.path.exists(self.models_dir):
                self.load_status['errors'].append(f"Dossier models/ non trouvé: {self.models_dir}")
                return self._create_fallback_models()
            
            # Charger le modèle frontend unifié principal
            frontend_model_path = os.path.join(self.models_dir, 'frontend_unified_model.pkl')
            if os.path.exists(frontend_model_path):
                try:
                    with open(frontend_model_path, 'rb') as f:
                        frontend_model = pickle.load(f)
                    
                    self.models_cache['frontend_unified_model'] = frontend_model
                    self.load_status['models_loaded'] = True
                    self.load_status['last_load_time'] = datetime.now().isoformat()
                    
                    logger.info(" Modèle frontend unifié chargé avec succès")
                    return self._create_success_response(frontend_model)
                    
                except Exception as e:
                    self.load_status['errors'].append(f"Erreur lors du chargement du modèle frontend unifié: {str(e)}")
                    logger.error(f" Erreur lors du chargement du modèle frontend unifié: {e}")
            
            # Essayer l'ancien modèle frontend
            old_frontend_model_path = os.path.join(self.models_dir, 'frontend_model.pkl')
            if os.path.exists(old_frontend_model_path):
                try:
                    with open(old_frontend_model_path, 'rb') as f:
                        frontend_model = pickle.load(f)
                    
                    self.models_cache['frontend_model'] = frontend_model
                    self.load_status['models_loaded'] = True
                    self.load_status['last_load_time'] = datetime.now().isoformat()
                    
                    logger.info(" Ancien modèle frontend chargé avec succès")
                    return self._create_success_response(frontend_model)
                    
                except Exception as e:
                    self.load_status['errors'].append(f"Erreur lors du chargement de l'ancien modèle frontend: {str(e)}")
                    logger.error(f" Erreur lors du chargement de l'ancien modèle frontend: {e}")
            
            # Essayer de charger les modèles individuels
            return self._load_individual_models()
            
        except Exception as e:
            self.load_status['errors'].append(f"Erreur générale lors du chargement: {str(e)}")
            logger.error(f" Erreur générale lors du chargement: {e}")
            return self._create_fallback_models()
    
    def _load_individual_models(self) -> Dict[str, Any]:
        """Charger les modèles individuels"""
        try:
            models = {}
            metadata = {}
            
            # Charger les modèles sklearn
            model_names = ['random_forest', 'svm', 'neural_network']
            for model_name in model_names:
                model_path = os.path.join(self.models_dir, f'{model_name}_model.pkl')
                if os.path.exists(model_path):
                    try:
                        with open(model_path, 'rb') as f:
                            models[model_name] = pickle.load(f)
                        logger.info(f" Modèle {model_name} chargé")
                    except Exception as e:
                        self.load_status['warnings'].append(f"Impossible de charger {model_name}: {str(e)}")
                        logger.warning(f" Impossible de charger {model_name}: {e}")
                else:
                    self.load_status['warnings'].append(f"Fichier {model_name}_model.pkl non trouvé")
            
            # Charger les métadonnées
            metadata_path = os.path.join(self.models_dir, 'model_metadata.json')
            if os.path.exists(metadata_path):
                try:
                    with open(metadata_path, 'r', encoding='utf-8') as f:
                        metadata = json.load(f)
                    logger.info(" Métadonnées chargées")
                except Exception as e:
                    self.load_status['warnings'].append(f"Impossible de charger les métadonnées: {str(e)}")
            
            if models:
                self.models_cache['individual_models'] = models
                self.models_cache['metadata'] = metadata
                self.load_status['models_loaded'] = True
                self.load_status['last_load_time'] = datetime.now().isoformat()
                
                return self._create_success_response({
                    'models': models,
                    'metadata': metadata,
                    'version': '1.0.0',
                    'hackathon_optimized': True
                })
            else:
                self.load_status['errors'].append("Aucun modèle trouvé")
                return self._create_fallback_models()
                
        except Exception as e:
            self.load_status['errors'].append(f"Erreur lors du chargement individuel: {str(e)}")
            return self._create_fallback_models()
    
    def _create_fallback_models(self) -> Dict[str, Any]:
        """Créer des modèles de fallback pour le hackathon"""
        logger.warning(" Création de modèles de fallback...")
        
        try:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.svm import SVC
            from sklearn.neural_network import MLPClassifier
            
            # Créer des modèles simples
            fallback_models = {
                'random_forest': RandomForestClassifier(n_estimators=10, random_state=42),
                'svm': SVC(kernel='rbf', random_state=42),
                'neural_network': MLPClassifier(hidden_layer_sizes=(10,), max_iter=100, random_state=42)
            }
            
            # Entraîner avec des données factices
            import numpy as np
            X = np.random.rand(100, 10)
            y = np.random.randint(0, 2, 100)
            
            for name, model in fallback_models.items():
                model.fit(X, y)
            
            fallback_model = {
                'models': fallback_models,
                'metadata': {
                    'feature_names': [f'feature_{i}' for i in range(10)],
                    'training_config': {'max_samples': 100, 'fallback': True},
                    'metrics': {'fallback': {'accuracy': 0.5, 'precision': 0.5, 'recall': 0.5, 'f1_score': 0.5}},
                    'training_time': 0.1,
                    'created_at': datetime.now().isoformat()
                },
                'version': '1.0.0-fallback',
                'hackathon_optimized': True,
                'fallback': True
            }
            
            self.models_cache['fallback_model'] = fallback_model
            self.load_status['models_loaded'] = True
            self.load_status['last_load_time'] = datetime.now().isoformat()
            self.load_status['warnings'].append("Modèles de fallback utilisés")
            
            logger.info(" Modèles de fallback créés")
            return self._create_success_response(fallback_model)
            
        except Exception as e:
            self.load_status['errors'].append(f"Erreur lors de la création des modèles de fallback: {str(e)}")
            logger.error(f" Erreur lors de la création des modèles de fallback: {e}")
            
            # Retourner une réponse minimale
            return {
                'success': False,
                'error': 'Impossible de charger ou créer des modèles',
                'fallback': True,
                'models_available': False,
                'load_status': self.load_status
            }
    
    def _create_success_response(self, model_data: Dict[str, Any]) -> Dict[str, Any]:
        """Créer une réponse de succès"""
        return {
            'success': True,
            'models_available': True,
            'model_data': model_data,
            'load_status': self.load_status,
            'version': model_data.get('version', '1.0.0'),
            'hackathon_optimized': model_data.get('hackathon_optimized', False),
            'fallback': model_data.get('fallback', False)
        }
    
    def get_model(self, model_name: str = None) -> Optional[Any]:
        """Obtenir un modèle spécifique"""
        try:
            if not self.models_cache:
                self.load_models()
            
            if 'frontend_model' in self.models_cache:
                frontend_model = self.models_cache['frontend_model']
                if model_name:
                    return frontend_model.get('models', {}).get(model_name)
                return frontend_model
            
            elif 'individual_models' in self.models_cache:
                models = self.models_cache['individual_models']
                if model_name:
                    return models.get(model_name)
                return models
            
            elif 'fallback_model' in self.models_cache:
                fallback_model = self.models_cache['fallback_model']
                if model_name:
                    return fallback_model.get('models', {}).get(model_name)
                return fallback_model
            
            return None
            
        except Exception as e:
            logger.error(f"❌ Erreur lors de la récupération du modèle: {e}")
            return None
    
    def get_model_status(self) -> Dict[str, Any]:
        """Obtenir le statut des modèles"""
        return {
            'models_loaded': self.load_status['models_loaded'],
            'last_load_time': self.load_status['last_load_time'],
            'errors': self.load_status['errors'],
            'warnings': self.load_status['warnings'],
            'models_available': len(self.models_cache) > 0,
            'cache_keys': list(self.models_cache.keys())
        }
    
    def reload_models(self) -> Dict[str, Any]:
        """Recharger les modèles"""
        logger.info(" Rechargement des modèles...")
        
        # Vider le cache
        self.models_cache.clear()
        self.load_status['errors'].clear()
        self.load_status['warnings'].clear()
        
        # Recharger
        return self.load_models()

# Instance globale pour le hackathon
model_loader = ModelLoader()

def get_model_loader() -> ModelLoader:
    """Obtenir l'instance du chargeur de modèles"""
    return model_loader 
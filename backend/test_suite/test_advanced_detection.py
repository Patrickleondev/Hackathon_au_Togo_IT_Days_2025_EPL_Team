"""
Script de test pour le modèle de détection avancée
RansomGuard AI - Hackathon Togo IT Days 2025
"""

import asyncio
import logging
import os
import json
import hashlib
import time
from datetime import datetime
from typing import Dict, List, Any
import subprocess
import tempfile
import shutil

from ml_engine.hybrid_detector import HybridDetector
from ml_engine.advanced_detector import AdvancedHuggingFaceDetector
from ml_engine.ransomware_detector import RansomwareDetector

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AdvancedDetectionTester:
    """Testeur pour le modèle de détection avancée"""
    
    def __init__(self):
        self.hybrid_detector = HybridDetector()
        self.advanced_detector = AdvancedHuggingFaceDetector()
        self.ransomware_detector = RansomwareDetector()
        
        # Dossier de test sécurisé
        self.test_dir = "test_files/"
        os.makedirs(self.test_dir, exist_ok=True)
        
        # Résultats des tests
        self.test_results = []
        
    async def test_executable_analysis(self, executable_path: str) -> Dict[str, Any]:
        """Tester l'analyse d'un exécutable malveillant"""
        try:
            logger.info(f"🔍 Test d'analyse de l'exécutable: {executable_path}")
            
            if not os.path.exists(executable_path):
                return {
                    'error': 'Fichier non trouvé',
                    'file_path': executable_path
                }
            
            # Informations sur le fichier
            file_info = self._get_file_info(executable_path)
            
            # Simuler les informations de processus
            process_info = self._simulate_process_info(executable_path)
            
            # 1. Test avec le détecteur avancé
            logger.info("📊 Test avec le détecteur avancé...")
            advanced_result = await self._test_advanced_detector(executable_path, process_info)
            
            # 2. Test avec le système hybride
            logger.info("🔗 Test avec le système hybride...")
            hybrid_result = await self._test_hybrid_detector(executable_path, process_info)
            
            # 3. Test avec le détecteur traditionnel
            logger.info("🏛️ Test avec le détecteur traditionnel...")
            traditional_result = await self._test_traditional_detector(executable_path, process_info)
            
            # 4. Analyse comparative
            comparison = self._compare_results(advanced_result, hybrid_result, traditional_result)
            
            # 5. Résultats finaux
            final_result = {
                'file_info': file_info,
                'process_info': process_info,
                'advanced_detection': advanced_result,
                'hybrid_detection': hybrid_result,
                'traditional_detection': traditional_result,
                'comparison': comparison,
                'timestamp': datetime.now().isoformat(),
                'overall_assessment': self._get_overall_assessment(comparison)
            }
            
            # Sauvegarder les résultats
            self.test_results.append(final_result)
            
            return final_result
            
        except Exception as e:
            logger.error(f"❌ Erreur lors du test: {e}")
            return {
                'error': str(e),
                'file_path': executable_path,
                'timestamp': datetime.now().isoformat()
            }
    
    def _get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Obtenir les informations sur le fichier"""
        try:
            stat = os.stat(file_path)
            
            # Calculer le hash du fichier
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            return {
                'file_path': file_path,
                'file_name': os.path.basename(file_path),
                'file_size': stat.st_size,
                'file_hash': file_hash,
                'file_extension': os.path.splitext(file_path)[1].lower(),
                'creation_time': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'modification_time': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'is_executable': os.access(file_path, os.X_OK)
            }
        except Exception as e:
            logger.error(f"Erreur lors de l'obtention des infos fichier: {e}")
            return {'error': str(e)}
    
    def _simulate_process_info(self, file_path: str) -> Dict[str, Any]:
        """Simuler les informations de processus pour l'exécutable"""
        try:
            # Simuler un processus qui exécute le fichier
            process_info = {
                'process_name': os.path.basename(file_path),
                'cpu_percent': 15.0,  # Simulation d'utilisation CPU
                'memory_percent': 8.0,  # Simulation d'utilisation mémoire
                'connections': [
                    {'remote_ip': '192.168.1.100', 'remote_port': 8080, 'status': 'ESTABLISHED'},
                    {'remote_ip': '10.0.0.1', 'remote_port': 443, 'status': 'ESTABLISHED'}
                ],
                'registry_changes': 5,  # Simulation de modifications de registre
                'file_operations': [
                    {'operation': 'create', 'target': 'encrypted_file.txt'},
                    {'operation': 'modify', 'target': 'system_config.ini'},
                    {'operation': 'delete', 'target': 'backup_file.bak'}
                ]
            }
            
            return process_info
            
        except Exception as e:
            logger.error(f"Erreur lors de la simulation des infos processus: {e}")
            return {}
    
    async def _test_advanced_detector(self, file_path: str, process_info: Dict) -> Dict[str, Any]:
        """Tester le détecteur avancé"""
        try:
            # Utiliser l'analyse asynchrone
            task_id = await self.advanced_detector.analyze_file_async(file_path, process_info)
            
            # Attendre le résultat
            max_wait = 30
            wait_time = 0
            while wait_time < max_wait:
                result = await self.advanced_detector.get_analysis_result(task_id)
                if result:
                    return {
                        'method': 'advanced_detector',
                        'success': True,
                        'result': result,
                        'processing_time': wait_time
                    }
                
                await asyncio.sleep(0.5)
                wait_time += 0.5
            
            return {
                'method': 'advanced_detector',
                'success': False,
                'error': 'timeout',
                'processing_time': max_wait
            }
            
        except Exception as e:
            logger.error(f"Erreur dans le test du détecteur avancé: {e}")
            return {
                'method': 'advanced_detector',
                'success': False,
                'error': str(e)
            }
    
    async def _test_hybrid_detector(self, file_path: str, process_info: Dict) -> Dict[str, Any]:
        """Tester le système hybride"""
        try:
            start_time = time.time()
            
            result = await self.hybrid_detector.analyze_file_hybrid(file_path, process_info)
            
            processing_time = time.time() - start_time
            
            return {
                'method': 'hybrid_detector',
                'success': True,
                'result': result,
                'processing_time': processing_time
            }
            
        except Exception as e:
            logger.error(f"Erreur dans le test du système hybride: {e}")
            return {
                'method': 'hybrid_detector',
                'success': False,
                'error': str(e)
            }
    
    async def _test_traditional_detector(self, file_path: str, process_info: Dict) -> Dict[str, Any]:
        """Tester le détecteur traditionnel"""
        try:
            start_time = time.time()
            
            # Extraire les caractéristiques
            features = await self.ransomware_detector.extract_features(file_path, process_info)
            
            # Prédire la menace
            prediction = await self.ransomware_detector.predict_threat(features)
            
            processing_time = time.time() - start_time
            
            return {
                'method': 'traditional_detector',
                'success': True,
                'result': prediction,
                'processing_time': processing_time
            }
            
        except Exception as e:
            logger.error(f"Erreur dans le test du détecteur traditionnel: {e}")
            return {
                'method': 'traditional_detector',
                'success': False,
                'error': str(e)
            }
    
    def _compare_results(self, advanced_result: Dict, hybrid_result: Dict, traditional_result: Dict) -> Dict[str, Any]:
        """Comparer les résultats des différents détecteurs"""
        try:
            comparison = {
                'detection_agreement': 0,
                'threat_detected_by': [],
                'confidence_scores': {},
                'processing_times': {},
                'evasion_detection': {},
                'risk_levels': {}
            }
            
            # Vérifier l'accord entre les détecteurs
            detections = []
            
            if advanced_result.get('success') and 'result' in advanced_result:
                detections.append(('advanced', advanced_result['result'].get('is_threat', False)))
                comparison['confidence_scores']['advanced'] = advanced_result['result'].get('confidence', 0)
                comparison['processing_times']['advanced'] = advanced_result.get('processing_time', 0)
                comparison['evasion_detection']['advanced'] = advanced_result['result'].get('evasion_scores', {})
                comparison['risk_levels']['advanced'] = advanced_result['result'].get('risk_level', 'unknown')
            
            if hybrid_result.get('success') and 'result' in hybrid_result:
                detections.append(('hybrid', hybrid_result['result'].get('is_threat', False)))
                comparison['confidence_scores']['hybrid'] = hybrid_result['result'].get('confidence', 0)
                comparison['processing_times']['hybrid'] = hybrid_result.get('processing_time', 0)
                comparison['risk_levels']['hybrid'] = hybrid_result['result'].get('risk_level', 'unknown')
            
            if traditional_result.get('success') and 'result' in traditional_result:
                detections.append(('traditional', traditional_result['result'].get('is_threat', False)))
                comparison['confidence_scores']['traditional'] = traditional_result['result'].get('confidence', 0)
                comparison['processing_times']['traditional'] = traditional_result.get('processing_time', 0)
                comparison['risk_levels']['traditional'] = 'unknown'  # Pas de niveau de risque dans le traditionnel
            
            # Calculer l'accord
            if detections:
                threat_detections = [d[1] for d in detections]
                agreement = sum(threat_detections) / len(threat_detections)
                comparison['detection_agreement'] = agreement
                
                # Détecteurs qui ont trouvé une menace
                comparison['threat_detected_by'] = [d[0] for d in detections if d[1]]
            
            return comparison
            
        except Exception as e:
            logger.error(f"Erreur lors de la comparaison: {e}")
            return {'error': str(e)}
    
    def _get_overall_assessment(self, comparison: Dict) -> Dict[str, Any]:
        """Obtenir l'évaluation globale"""
        try:
            # Déterminer le niveau de menace global
            threat_detectors = len(comparison.get('threat_detected_by', []))
            total_detectors = len(comparison.get('confidence_scores', {}))
            
            if total_detectors == 0:
                threat_level = 'unknown'
            elif threat_detectors == 0:
                threat_level = 'safe'
            elif threat_detectors == total_detectors:
                threat_level = 'high'
            elif threat_detectors >= total_detectors / 2:
                threat_level = 'medium'
            else:
                threat_level = 'low'
            
            # Recommandations
            recommendations = []
            
            if threat_level == 'high':
                recommendations.extend([
                    "Quarantaine immédiate recommandée",
                    "Analyse approfondie requise",
                    "Notification à l'administrateur"
                ])
            elif threat_level == 'medium':
                recommendations.extend([
                    "Surveillance renforcée",
                    "Analyse complémentaire recommandée"
                ])
            elif threat_level == 'low':
                recommendations.append("Surveillance normale")
            else:
                recommendations.append("Analyse manuelle recommandée")
            
            # Vérifier les techniques d'évasion
            evasion_detected = any(
                scores for scores in comparison.get('evasion_detection', {}).values()
                if any(score > 0.5 for score in scores.values())
            )
            
            if evasion_detected:
                recommendations.append("Techniques d'évasion détectées - vigilance maximale")
            
            return {
                'threat_level': threat_level,
                'threat_detectors_count': threat_detectors,
                'total_detectors': total_detectors,
                'evasion_detected': evasion_detected,
                'recommendations': recommendations,
                'confidence_avg': sum(comparison.get('confidence_scores', {}).values()) / len(comparison.get('confidence_scores', {})) if comparison.get('confidence_scores') else 0
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de l'évaluation globale: {e}")
            return {'error': str(e)}
    
    async def test_multiple_executables(self, executable_paths: List[str]) -> Dict[str, Any]:
        """Tester plusieurs exécutables"""
        logger.info(f"🧪 Test de {len(executable_paths)} exécutables...")
        
        results = []
        successful_tests = 0
        failed_tests = 0
        
        for i, executable_path in enumerate(executable_paths, 1):
            logger.info(f"📁 Test {i}/{len(executable_paths)}: {executable_path}")
            
            result = await self.test_executable_analysis(executable_path)
            
            if 'error' not in result:
                successful_tests += 1
            else:
                failed_tests += 1
            
            results.append(result)
            
            # Pause entre les tests
            await asyncio.sleep(1)
        
        # Statistiques globales
        stats = self._calculate_global_stats(results)
        
        return {
            'total_tests': len(executable_paths),
            'successful_tests': successful_tests,
            'failed_tests': failed_tests,
            'success_rate': successful_tests / len(executable_paths) if executable_paths else 0,
            'results': results,
            'statistics': stats,
            'timestamp': datetime.now().isoformat()
        }
    
    def _calculate_global_stats(self, results: List[Dict]) -> Dict[str, Any]:
        """Calculer les statistiques globales"""
        try:
            stats = {
                'total_files_tested': len(results),
                'threat_detection_rates': {},
                'average_processing_times': {},
                'evasion_detection_rate': 0,
                'risk_level_distribution': {}
            }
            
            # Compter les détections par méthode
            detection_counts = {'advanced': 0, 'hybrid': 0, 'traditional': 0}
            processing_times = {'advanced': [], 'hybrid': [], 'traditional': []}
            risk_levels = {'high': 0, 'medium': 0, 'low': 0, 'safe': 0, 'unknown': 0}
            evasion_detected = 0
            
            for result in results:
                if 'comparison' in result:
                    comparison = result['comparison']
                    
                    # Compter les détections
                    for detector in comparison.get('threat_detected_by', []):
                        detection_counts[detector] += 1
                    
                    # Temps de traitement
                    for detector, time in comparison.get('processing_times', {}).items():
                        if time > 0:
                            processing_times[detector].append(time)
                    
                    # Niveaux de risque
                    for detector, risk_level in comparison.get('risk_levels', {}).items():
                        if risk_level in risk_levels:
                            risk_levels[risk_level] += 1
                    
                    # Détection d'évasion
                    if any(
                        scores for scores in comparison.get('evasion_detection', {}).values()
                        if any(score > 0.5 for score in scores.values())
                    ):
                        evasion_detected += 1
            
            # Calculer les taux
            total_files = len(results)
            if total_files > 0:
                stats['threat_detection_rates'] = {
                    detector: count / total_files 
                    for detector, count in detection_counts.items()
                }
                
                stats['average_processing_times'] = {
                    detector: sum(times) / len(times) if times else 0
                    for detector, times in processing_times.items()
                }
                
                stats['evasion_detection_rate'] = evasion_detected / total_files
                stats['risk_level_distribution'] = {
                    level: count / total_files 
                    for level, count in risk_levels.items()
                }
            
            return stats
            
        except Exception as e:
            logger.error(f"Erreur lors du calcul des statistiques: {e}")
            return {'error': str(e)}
    
    def save_test_results(self, results: Dict, filename: str = None):
        """Sauvegarder les résultats de test"""
        try:
            if not filename:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"test_results_{timestamp}.json"
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            logger.info(f"💾 Résultats sauvegardés dans {filename}")
            
        except Exception as e:
            logger.error(f"❌ Erreur lors de la sauvegarde: {e}")
    
    def print_test_summary(self, results: Dict):
        """Afficher un résumé des tests"""
        try:
            print("\n" + "="*60)
            print("📊 RÉSUMÉ DES TESTS DE DÉTECTION AVANCÉE")
            print("="*60)
            
            stats = results.get('statistics', {})
            
            print(f"📁 Fichiers testés: {results.get('total_tests', 0)}")
            print(f"✅ Tests réussis: {results.get('successful_tests', 0)}")
            print(f"❌ Tests échoués: {results.get('failed_tests', 0)}")
            print(f"📈 Taux de succès: {results.get('success_rate', 0)*100:.1f}%")
            
            print("\n🔍 TAUX DE DÉTECTION PAR MÉTHODE:")
            detection_rates = stats.get('threat_detection_rates', {})
            for method, rate in detection_rates.items():
                print(f"  • {method.capitalize()}: {rate*100:.1f}%")
            
            print("\n⏱️ TEMPS MOYEN DE TRAITEMENT:")
            processing_times = stats.get('average_processing_times', {})
            for method, time in processing_times.items():
                print(f"  • {method.capitalize()}: {time:.3f}s")
            
            print(f"\n🛡️ DÉTECTION D'ÉVASION: {stats.get('evasion_detection_rate', 0)*100:.1f}%")
            
            print("\n⚠️ DISTRIBUTION DES NIVEAUX DE RISQUE:")
            risk_distribution = stats.get('risk_level_distribution', {})
            for level, rate in risk_distribution.items():
                print(f"  • {level.capitalize()}: {rate*100:.1f}%")
            
            print("="*60)
            
        except Exception as e:
            logger.error(f"Erreur lors de l'affichage du résumé: {e}")

async def main():
    """Fonction principale de test"""
    tester = AdvancedDetectionTester()
    
    # Exemples d'exécutables à tester (remplacez par vos vrais fichiers)
    test_executables = [
        # Ajoutez ici les chemins vers vos exécutables malveillants
        # "path/to/malware1.exe",
        # "path/to/malware2.exe",
        # "path/to/ransomware.exe",
    ]
    
    if not test_executables:
        print("⚠️ Aucun exécutable à tester. Ajoutez les chemins dans la liste test_executables.")
        return
    
    # Exécuter les tests
    results = await tester.test_multiple_executables(test_executables)
    
    # Afficher le résumé
    tester.print_test_summary(results)
    
    # Sauvegarder les résultats
    tester.save_test_results(results)
    
    print("\n🎯 Tests terminés! Consultez le fichier JSON pour les détails complets.")

if __name__ == "__main__":
    asyncio.run(main()) 
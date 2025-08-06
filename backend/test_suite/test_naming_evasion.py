"""
Test des techniques d'évasion par nom de fichier
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
import shutil
import tempfile

from ml_engine.hybrid_detector import HybridDetector
from ml_engine.advanced_detector import AdvancedHuggingFaceDetector

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class NamingEvasionTester:
    """Testeur spécialisé pour les techniques d'évasion par nom"""
    
    def __init__(self):
        self.hybrid_detector = HybridDetector()
        self.advanced_detector = AdvancedHuggingFaceDetector()
        
        # Patterns d'évasion par nom
        self.evasion_patterns = {
            'legitimate_names': [
                'bible.exe', 'netflix_gratuit.exe', 'crack_office.exe',
                'free_music.exe', 'game_hack.exe', 'antivirus_free.exe',
                'windows_update.exe', 'adobe_reader.exe', 'chrome_installer.exe',
                'spotify_premium.exe', 'minecraft_free.exe', 'photoshop_crack.exe'
            ],
            'double_extensions': [
                'document.pdf.exe', 'image.jpg.exe', 'video.mp4.exe',
                'archive.zip.exe', 'presentation.pptx.exe', 'spreadsheet.xlsx.exe',
                'text.txt.exe', 'music.mp3.exe', 'backup.rar.exe'
            ],
            'spaces_and_special_chars': [
                'bible .exe', 'netflix gratuit.exe', 'crack office.exe',
                'free music.exe', 'game hack.exe', 'antivirus free.exe',
                'windows update.exe', 'adobe reader.exe', 'chrome installer.exe'
            ],
            'unicode_evasion': [
                'biblе.exe', 'nеtflix.exe', 'chrоme.exe',  # Caractères cyrilliques
                'biblé.exe', 'nétflix.exe', 'chrôme.exe',   # Accents
                'biblë.exe', 'nëtflix.exe', 'chrömë.exe'    # Trémas
            ],
            'case_evasion': [
                'BIBLE.EXE', 'NETFLIX.EXE', 'CHROME.EXE',
                'bible.EXE', 'netflix.EXE', 'chrome.EXE',
                'BIBLE.exe', 'NETFLIX.exe', 'CHROME.exe'
            ]
        }
        
        # Dossier de test sécurisé
        self.test_dir = "test_files/naming_evasion/"
        os.makedirs(self.test_dir, exist_ok=True)
        
        # Résultats des tests
        self.test_results = []
        
    def create_evasion_test_files(self) -> List[str]:
        """Créer des fichiers de test avec des noms d'évasion"""
        logger.info("🔄 Création des fichiers de test avec noms d'évasion...")
        
        test_files = []
        
        # Créer des fichiers factices pour les tests
        for category, patterns in self.evasion_patterns.items():
            for pattern in patterns:
                try:
                    # Créer un fichier avec le nom d'évasion
                    file_path = os.path.join(self.test_dir, pattern)
                    
                    # Créer un contenu factice (simulation de malware)
                    content = self._generate_malicious_content(pattern)
                    
                    with open(file_path, 'wb') as f:
                        f.write(content)
                    
                    test_files.append(file_path)
                    logger.info(f"✅ Créé: {pattern}")
                    
                except Exception as e:
                    logger.error(f"❌ Erreur lors de la création de {pattern}: {e}")
        
        logger.info(f"📁 {len(test_files)} fichiers de test créés")
        return test_files
    
    def _generate_malicious_content(self, filename: str) -> bytes:
        """Générer du contenu malveillant factice"""
        # Contenu qui simule un exécutable malveillant
        malicious_signatures = [
            b'MZ\x90\x00',  # Signature PE
            b'encrypt files',
            b'ransomware',
            b'bitcoin',
            b'wallet',
            b'decrypt',
            b'payment',
            b'crypto',
            b'lock',
            b'virus'
        ]
        
        # Ajouter des patterns d'évasion
        evasion_patterns = [
            b'sleep 30000',
            b'mouse movement',
            b'vm detection',
            b'sandbox evasion',
            b'antivirus bypass',
            b'packing obfuscation'
        ]
        
        # Combiner le contenu
        content = b''
        content += b'\x4d\x5a\x90\x00'  # Signature PE
        content += b'\x00' * 100  # Padding
        
        # Ajouter des signatures malveillantes
        for sig in malicious_signatures:
            content += sig + b'\x00'
        
        # Ajouter des patterns d'évasion
        for pattern in evasion_patterns:
            content += pattern + b'\x00'
        
        # Ajouter le nom du fichier dans le contenu
        content += filename.encode('utf-8') + b'\x00'
        
        return content
    
    async def test_naming_evasion_detection(self, file_path: str) -> Dict[str, Any]:
        """Tester la détection d'évasion par nom"""
        try:
            logger.info(f"🔍 Test d'évasion par nom: {os.path.basename(file_path)}")
            
            # Informations sur le fichier
            file_info = self._get_file_info(file_path)
            
            # Simuler les informations de processus
            process_info = self._simulate_process_info(file_path)
            
            # Test avec le détecteur avancé
            advanced_result = await self._test_advanced_detector(file_path, process_info)
            
            # Test avec le système hybride
            hybrid_result = await self._test_hybrid_detector(file_path, process_info)
            
            # Analyser les résultats d'évasion
            evasion_analysis = self._analyze_naming_evasion(file_path, advanced_result, hybrid_result)
            
            return {
                'file_info': file_info,
                'process_info': process_info,
                'advanced_detection': advanced_result,
                'hybrid_detection': hybrid_result,
                'evasion_analysis': evasion_analysis,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"❌ Erreur lors du test d'évasion par nom: {e}")
            return {
                'error': str(e),
                'file_path': file_path,
                'timestamp': datetime.now().isoformat()
            }
    
    def _get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Obtenir les informations sur le fichier"""
        try:
            stat = os.stat(file_path)
            
            # Calculer le hash
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            filename = os.path.basename(file_path)
            
            return {
                'file_path': file_path,
                'file_name': filename,
                'file_size': stat.st_size,
                'file_hash': file_hash,
                'file_extension': os.path.splitext(file_path)[1].lower(),
                'creation_time': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'modification_time': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'is_executable': os.access(file_path, os.X_OK),
                'evasion_category': self._categorize_evasion(filename)
            }
        except Exception as e:
            logger.error(f"Erreur lors de l'obtention des infos fichier: {e}")
            return {'error': str(e)}
    
    def _categorize_evasion(self, filename: str) -> str:
        """Catégoriser le type d'évasion par nom"""
        filename_lower = filename.lower()
        
        if any(pattern in filename_lower for pattern in self.evasion_patterns['legitimate_names']):
            return 'legitimate_names'
        elif any(pattern in filename_lower for pattern in self.evasion_patterns['double_extensions']):
            return 'double_extensions'
        elif any(pattern in filename_lower for pattern in self.evasion_patterns['spaces_and_special_chars']):
            return 'spaces_and_special_chars'
        elif any(pattern in filename_lower for pattern in self.evasion_patterns['unicode_evasion']):
            return 'unicode_evasion'
        elif any(pattern in filename_lower for pattern in self.evasion_patterns['case_evasion']):
            return 'case_evasion'
        else:
            return 'unknown'
    
    def _simulate_process_info(self, file_path: str) -> Dict[str, Any]:
        """Simuler les informations de processus"""
        filename = os.path.basename(file_path)
        
        return {
            'process_name': filename,
            'cpu_percent': 12.5,
            'memory_percent': 6.8,
            'connections': [
                {'remote_ip': '192.168.1.100', 'remote_port': 8080, 'status': 'ESTABLISHED'},
                {'remote_ip': '10.0.0.1', 'remote_port': 443, 'status': 'ESTABLISHED'}
            ],
            'registry_changes': 3,
            'file_operations': [
                {'operation': 'create', 'target': 'encrypted_file.txt'},
                {'operation': 'modify', 'target': 'system_config.ini'},
                {'operation': 'delete', 'target': 'backup_file.bak'}
            ]
        }
    
    async def _test_advanced_detector(self, file_path: str, process_info: Dict) -> Dict[str, Any]:
        """Tester le détecteur avancé"""
        try:
            task_id = await self.advanced_detector.analyze_file_async(file_path, process_info)
            
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
    
    def _analyze_naming_evasion(self, file_path: str, advanced_result: Dict, hybrid_result: Dict) -> Dict[str, Any]:
        """Analyser les résultats d'évasion par nom"""
        try:
            filename = os.path.basename(file_path)
            evasion_category = self._categorize_evasion(filename)
            
            analysis = {
                'filename': filename,
                'evasion_category': evasion_category,
                'detection_success': False,
                'evasion_detected': False,
                'confidence_scores': {},
                'recommendations': []
            }
            
            # Vérifier la détection
            if advanced_result.get('success') and 'result' in advanced_result:
                adv_data = advanced_result['result']
                analysis['detection_success'] = adv_data.get('is_threat', False)
                analysis['confidence_scores']['advanced'] = adv_data.get('confidence', 0)
                
                # Vérifier les techniques d'évasion
                evasion_scores = adv_data.get('evasion_scores', {})
                if any(score > 0.5 for score in evasion_scores.values()):
                    analysis['evasion_detected'] = True
            
            if hybrid_result.get('success') and 'result' in hybrid_result:
                hyb_data = hybrid_result['result']
                analysis['confidence_scores']['hybrid'] = hyb_data.get('confidence', 0)
                
                # Recommandations
                recommendations = hyb_data.get('recommendations', [])
                analysis['recommendations'].extend(recommendations)
            
            # Recommandations spécifiques à l'évasion par nom
            if evasion_category != 'unknown':
                analysis['recommendations'].append(f"Nom d'évasion détecté: {evasion_category}")
            
            if 'double' in evasion_category:
                analysis['recommendations'].append("Double extension suspecte détectée")
            
            if 'unicode' in evasion_category:
                analysis['recommendations'].append("Caractères Unicode suspects détectés")
            
            return analysis
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse d'évasion par nom: {e}")
            return {'error': str(e)}
    
    async def run_comprehensive_naming_tests(self) -> Dict[str, Any]:
        """Exécuter des tests complets d'évasion par nom"""
        logger.info("🎯 Démarrage des tests complets d'évasion par nom...")
        
        # Créer les fichiers de test
        test_files = self.create_evasion_test_files()
        
        if not test_files:
            logger.error("❌ Aucun fichier de test créé")
            return {'error': 'Aucun fichier de test créé'}
        
        # Exécuter les tests
        results = []
        successful_tests = 0
        failed_tests = 0
        
        for i, file_path in enumerate(test_files, 1):
            logger.info(f"📁 Test {i}/{len(test_files)}: {os.path.basename(file_path)}")
            
            result = await self.test_naming_evasion_detection(file_path)
            
            if 'error' not in result:
                successful_tests += 1
            else:
                failed_tests += 1
            
            results.append(result)
            
            # Pause entre les tests
            await asyncio.sleep(0.5)
        
        # Statistiques globales
        stats = self._calculate_naming_evasion_stats(results)
        
        return {
            'total_tests': len(test_files),
            'successful_tests': successful_tests,
            'failed_tests': failed_tests,
            'success_rate': successful_tests / len(test_files) if test_files else 0,
            'results': results,
            'statistics': stats,
            'timestamp': datetime.now().isoformat()
        }
    
    def _calculate_naming_evasion_stats(self, results: List[Dict]) -> Dict[str, Any]:
        """Calculer les statistiques d'évasion par nom"""
        try:
            stats = {
                'total_files_tested': len(results),
                'evasion_categories': {},
                'detection_rates': {},
                'average_confidence': {},
                'evasion_detection_rate': 0
            }
            
            # Compter par catégorie d'évasion
            category_counts = {}
            detection_counts = {'advanced': 0, 'hybrid': 0}
            confidence_scores = {'advanced': [], 'hybrid': []}
            evasion_detected = 0
            
            for result in results:
                if 'evasion_analysis' in result:
                    analysis = result['evasion_analysis']
                    category = analysis.get('evasion_category', 'unknown')
                    
                    category_counts[category] = category_counts.get(category, 0) + 1
                    
                    # Compter les détections
                    if analysis.get('detection_success', False):
                        detection_counts['advanced'] += 1
                    
                    # Scores de confiance
                    for method, score in analysis.get('confidence_scores', {}).items():
                        if score > 0:
                            confidence_scores[method].append(score)
                    
                    # Détection d'évasion
                    if analysis.get('evasion_detected', False):
                        evasion_detected += 1
            
            # Calculer les statistiques
            total_files = len(results)
            if total_files > 0:
                stats['evasion_categories'] = {
                    category: count / total_files 
                    for category, count in category_counts.items()
                }
                
                stats['detection_rates'] = {
                    method: count / total_files 
                    for method, count in detection_counts.items()
                }
                
                stats['average_confidence'] = {
                    method: sum(scores) / len(scores) if scores else 0
                    for method, scores in confidence_scores.items()
                }
                
                stats['evasion_detection_rate'] = evasion_detected / total_files
            
            return stats
            
        except Exception as e:
            logger.error(f"Erreur lors du calcul des statistiques: {e}")
            return {'error': str(e)}
    
    def save_test_results(self, results: Dict, filename: str = None):
        """Sauvegarder les résultats de test"""
        try:
            if not filename:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"naming_evasion_test_{timestamp}.json"
            
            # Créer le dossier results s'il n'existe pas
            results_dir = "results/json/"
            os.makedirs(results_dir, exist_ok=True)
            
            filepath = os.path.join(results_dir, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            logger.info(f"💾 Résultats sauvegardés dans {filepath}")
            
        except Exception as e:
            logger.error(f"❌ Erreur lors de la sauvegarde: {e}")
    
    def print_test_summary(self, results: Dict):
        """Afficher un résumé des tests"""
        try:
            print("\n" + "="*60)
            print("📊 RÉSUMÉ DES TESTS D'ÉVASION PAR NOM")
            print("="*60)
            
            stats = results.get('statistics', {})
            
            print(f"📁 Fichiers testés: {results.get('total_tests', 0)}")
            print(f"✅ Tests réussis: {results.get('successful_tests', 0)}")
            print(f"❌ Tests échoués: {results.get('failed_tests', 0)}")
            print(f"📈 Taux de succès: {results.get('success_rate', 0)*100:.1f}%")
            
            print("\n🔍 CATÉGORIES D'ÉVASION:")
            categories = stats.get('evasion_categories', {})
            for category, rate in categories.items():
                print(f"  • {category}: {rate*100:.1f}%")
            
            print("\n🛡️ TAUX DE DÉTECTION:")
            detection_rates = stats.get('detection_rates', {})
            for method, rate in detection_rates.items():
                print(f"  • {method.capitalize()}: {rate*100:.1f}%")
            
            print(f"\n🎯 DÉTECTION D'ÉVASION: {stats.get('evasion_detection_rate', 0)*100:.1f}%")
            
            print("\n📊 CONFIANCE MOYENNE:")
            confidence_scores = stats.get('average_confidence', {})
            for method, score in confidence_scores.items():
                print(f"  • {method.capitalize()}: {score*100:.1f}%")
            
            print("="*60)
            
        except Exception as e:
            logger.error(f"Erreur lors de l'affichage du résumé: {e}")

async def main():
    """Fonction principale"""
    tester = NamingEvasionTester()
    
    # Exécuter les tests complets
    results = await tester.run_comprehensive_naming_tests()
    
    # Afficher le résumé
    tester.print_test_summary(results)
    
    # Sauvegarder les résultats
    tester.save_test_results(results)
    
    print("\n🎯 Tests d'évasion par nom terminés!")

if __name__ == "__main__":
    asyncio.run(main()) 
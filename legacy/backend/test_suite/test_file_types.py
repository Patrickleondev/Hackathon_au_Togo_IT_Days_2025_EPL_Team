"""
Test des types de fichiers trompeurs
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
import zipfile
import struct

from ml_engine.hybrid_detector import HybridDetector
from ml_engine.advanced_detector import AdvancedHuggingFaceDetector

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class FileTypeEvasionTester:
    """Testeur spécialisé pour les types de fichiers trompeurs"""
    
    def __init__(self):
        self.hybrid_detector = HybridDetector()
        self.advanced_detector = AdvancedHuggingFaceDetector()
        
        # Types de fichiers trompeurs
        self.deceptive_file_types = {
            'document_masquerade': [
                'document.pdf.exe', 'report.docx.exe', 'presentation.pptx.exe',
                'spreadsheet.xlsx.exe', 'text.txt.exe', 'readme.md.exe',
                'manual.pdf.exe', 'guide.docx.exe', 'tutorial.pptx.exe'
            ],
            'media_masquerade': [
                'video.mp4.exe', 'movie.avi.exe', 'music.mp3.exe',
                'song.wav.exe', 'image.jpg.exe', 'photo.png.exe',
                'picture.gif.exe', 'screenshot.bmp.exe', 'album.zip.exe'
            ],
            'archive_masquerade': [
                'backup.zip.exe', 'archive.rar.exe', 'files.7z.exe',
                'data.tar.exe', 'download.zip.exe', 'update.rar.exe',
                'installer.zip.exe', 'patch.7z.exe', 'mod.zip.exe'
            ],
            'system_masquerade': [
                'windows_update.exe', 'system_repair.exe', 'driver_update.exe',
                'antivirus_update.exe', 'firewall_update.exe', 'security_patch.exe',
                'registry_cleaner.exe', 'disk_cleaner.exe', 'optimizer.exe'
            ],
            'application_masquerade': [
                'chrome_installer.exe', 'firefox_setup.exe', 'adobe_reader.exe',
                'office_installer.exe', 'photoshop_setup.exe', 'vlc_installer.exe',
                'winrar_setup.exe', 'notepad_plus.exe', 'ccleaner_setup.exe'
            ]
        }
        
        # Dossier de test sécurisé
        self.test_dir = "test_files/file_types/"
        os.makedirs(self.test_dir, exist_ok=True)
        
        # Résultats des tests
        self.test_results = []
        
    def create_deceptive_test_files(self) -> List[str]:
        """Créer des fichiers de test avec des types trompeurs"""
        logger.info("🔄 Création des fichiers de test avec types trompeurs...")
        
        test_files = []
        
        for category, patterns in self.deceptive_file_types.items():
            for pattern in patterns:
                try:
                    # Créer un fichier avec le nom trompeur
                    file_path = os.path.join(self.test_dir, pattern)
                    
                    # Créer du contenu malveillant déguisé
                    content = self._generate_deceptive_content(pattern, category)
                    
                    with open(file_path, 'wb') as f:
                        f.write(content)
                    
                    test_files.append(file_path)
                    logger.info(f"✅ Créé: {pattern}")
                    
                except Exception as e:
                    logger.error(f"❌ Erreur lors de la création de {pattern}: {e}")
        
        logger.info(f"📁 {len(test_files)} fichiers trompeurs créés")
        return test_files
    
    def _generate_deceptive_content(self, filename: str, category: str) -> bytes:
        """Générer du contenu malveillant déguisé"""
        # Signature PE (exécutable Windows)
        pe_signature = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
        
        # Headers PE factices
        pe_headers = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        
        # Contenu malveillant déguisé selon la catégorie
        malicious_content = b''
        
        if 'document' in category:
            # Déguisé en document
            malicious_content += b'%PDF-1.4\n'
            malicious_content += b'1 0 obj\n<<\n/Type /Catalog\n/Pages 2 0 R\n>>\nendobj\n'
            malicious_content += b'2 0 obj\n<<\n/Type /Pages\n/Kids [3 0 R]\n/Count 1\n>>\nendobj\n'
            malicious_content += b'3 0 obj\n<<\n/Type /Page\n/Parent 2 0 R\n/MediaBox [0 0 612 792]\n>>\nendobj\n'
            malicious_content += b'xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n'
            malicious_content += b'trailer\n<<\n/Size 4\n/Root 1 0 R\n>>\nstartxref\n186\n%%EOF\n'
        
        elif 'media' in category:
            # Déguisé en média
            malicious_content += b'ID3'
            malicious_content += b'\x00\x00\x00\x00\x00\x00\x00\x00'
            malicious_content += b'TIT2\x00\x00\x00\x0c\x00\x00\x00Malicious Song'
            malicious_content += b'TPE1\x00\x00\x00\x0c\x00\x00\x00Evil Artist'
            malicious_content += b'COMM\x00\x00\x00\x1c\x00\x00\x00eng\x00\x00\x00Malicious content'
        
        elif 'archive' in category:
            # Déguisé en archive
            malicious_content += b'PK\x03\x04'
            malicious_content += b'\x14\x00\x00\x00\x08\x00'
            malicious_content += b'readme.txt'
            malicious_content += b'This is a malicious archive'
            malicious_content += b'PK\x01\x02'
            malicious_content += b'\x14\x00\x00\x00\x08\x00'
            malicious_content += b'readme.txt'
            malicious_content += b'PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00'
        
        elif 'system' in category:
            # Déguisé en mise à jour système
            malicious_content += b'Windows Update Package'
            malicious_content += b'System Security Patch'
            malicious_content += b'Critical Security Update'
            malicious_content += b'Driver Update Package'
        
        elif 'application' in category:
            # Déguisé en installateur d'application
            malicious_content += b'Setup Information'
            malicious_content += b'Installation Package'
            malicious_content += b'Application Installer'
            malicious_content += b'Software Setup'
        
        # Ajouter des signatures malveillantes cachées
        malicious_signatures = [
            b'encrypt files',
            b'ransomware',
            b'bitcoin wallet',
            b'decrypt payment',
            b'crypto lock',
            b'virus payload',
            b'malware code',
            b'backdoor',
            b'trojan',
            b'rootkit'
        ]
        
        # Ajouter des techniques d'évasion
        evasion_patterns = [
            b'sleep 30000',
            b'mouse movement detection',
            b'vm detection',
            b'sandbox evasion',
            b'antivirus bypass',
            b'packing obfuscation',
            b'code injection',
            b'process hollowing'
        ]
        
        # Combiner le contenu
        content = pe_signature + pe_headers + malicious_content
        
        # Ajouter les signatures malveillantes
        for sig in malicious_signatures:
            content += sig + b'\x00'
        
        # Ajouter les patterns d'évasion
        for pattern in evasion_patterns:
            content += pattern + b'\x00'
        
        # Ajouter le nom du fichier
        content += filename.encode('utf-8') + b'\x00'
        
        return content
    
    async def test_file_type_evasion(self, file_path: str) -> Dict[str, Any]:
        """Tester la détection d'évasion par type de fichier"""
        try:
            logger.info(f"🔍 Test d'évasion par type: {os.path.basename(file_path)}")
            
            # Informations sur le fichier
            file_info = self._get_file_info(file_path)
            
            # Simuler les informations de processus
            process_info = self._simulate_process_info(file_path)
            
            # Test avec le détecteur avancé
            advanced_result = await self._test_advanced_detector(file_path, process_info)
            
            # Test avec le système hybride
            hybrid_result = await self._test_hybrid_detector(file_path, process_info)
            
            # Analyser les résultats d'évasion
            evasion_analysis = self._analyze_file_type_evasion(file_path, advanced_result, hybrid_result)
            
            return {
                'file_info': file_info,
                'process_info': process_info,
                'advanced_detection': advanced_result,
                'hybrid_detection': hybrid_result,
                'evasion_analysis': evasion_analysis,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"❌ Erreur lors du test d'évasion par type: {e}")
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
            
            # Analyser les extensions
            extensions = self._analyze_extensions(filename)
            
            return {
                'file_path': file_path,
                'file_name': filename,
                'file_size': stat.st_size,
                'file_hash': file_hash,
                'file_extension': os.path.splitext(file_path)[1].lower(),
                'creation_time': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'modification_time': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'is_executable': os.access(file_path, os.X_OK),
                'deceptive_category': self._categorize_deception(filename),
                'extensions_analysis': extensions
            }
        except Exception as e:
            logger.error(f"Erreur lors de l'obtention des infos fichier: {e}")
            return {'error': str(e)}
    
    def _analyze_extensions(self, filename: str) -> Dict[str, Any]:
        """Analyser les extensions du fichier"""
        try:
            # Séparer les extensions
            parts = filename.split('.')
            
            analysis = {
                'total_extensions': len(parts) - 1,
                'extensions': parts[1:] if len(parts) > 1 else [],
                'has_double_extension': len(parts) > 2,
                'final_extension': parts[-1] if len(parts) > 1 else '',
                'suspicious_extensions': []
            }
            
            # Vérifier les extensions suspectes
            suspicious_exts = ['.exe', '.bat', '.cmd', '.com', '.scr', '.pif']
            for ext in analysis['extensions']:
                if ext.lower() in suspicious_exts:
                    analysis['suspicious_extensions'].append(ext.lower())
            
            # Vérifier les extensions trompeuses
            deceptive_exts = ['.pdf', '.docx', '.xlsx', '.pptx', '.jpg', '.mp4', '.zip']
            analysis['has_deceptive_extension'] = any(
                ext.lower() in deceptive_exts for ext in analysis['extensions'][:-1]
            )
            
            return analysis
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse des extensions: {e}")
            return {'error': str(e)}
    
    def _categorize_deception(self, filename: str) -> str:
        """Catégoriser le type de tromperie"""
        filename_lower = filename.lower()
        
        for category, patterns in self.deceptive_file_types.items():
            if any(pattern in filename_lower for pattern in patterns):
                return category
        
        return 'unknown'
    
    def _simulate_process_info(self, file_path: str) -> Dict[str, Any]:
        """Simuler les informations de processus"""
        filename = os.path.basename(file_path)
        
        return {
            'process_name': filename,
            'cpu_percent': 15.2,
            'memory_percent': 8.7,
            'connections': [
                {'remote_ip': '192.168.1.100', 'remote_port': 8080, 'status': 'ESTABLISHED'},
                {'remote_ip': '10.0.0.1', 'remote_port': 443, 'status': 'ESTABLISHED'}
            ],
            'registry_changes': 4,
            'file_operations': [
                {'operation': 'create', 'target': 'encrypted_file.txt'},
                {'operation': 'modify', 'target': 'system_config.ini'},
                {'operation': 'delete', 'target': 'backup_file.bak'},
                {'operation': 'create', 'target': 'ransom_note.txt'}
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
    
    def _analyze_file_type_evasion(self, file_path: str, advanced_result: Dict, hybrid_result: Dict) -> Dict[str, Any]:
        """Analyser les résultats d'évasion par type de fichier"""
        try:
            filename = os.path.basename(file_path)
            deception_category = self._categorize_deception(filename)
            extensions_analysis = self._analyze_extensions(filename)
            
            analysis = {
                'filename': filename,
                'deception_category': deception_category,
                'extensions_analysis': extensions_analysis,
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
            
            # Recommandations spécifiques aux types de fichiers trompeurs
            if extensions_analysis.get('has_double_extension', False):
                analysis['recommendations'].append("Double extension suspecte détectée")
            
            if extensions_analysis.get('has_deceptive_extension', False):
                analysis['recommendations'].append("Extension trompeuse détectée")
            
            if extensions_analysis.get('suspicious_extensions'):
                analysis['recommendations'].append(f"Extensions suspectes: {', '.join(extensions_analysis['suspicious_extensions'])}")
            
            if deception_category != 'unknown':
                analysis['recommendations'].append(f"Type de tromperie détecté: {deception_category}")
            
            return analysis
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse d'évasion par type: {e}")
            return {'error': str(e)}
    
    async def run_comprehensive_file_type_tests(self) -> Dict[str, Any]:
        """Exécuter des tests complets d'évasion par type de fichier"""
        logger.info("🎯 Démarrage des tests complets d'évasion par type de fichier...")
        
        # Créer les fichiers de test
        test_files = self.create_deceptive_test_files()
        
        if not test_files:
            logger.error("❌ Aucun fichier de test créé")
            return {'error': 'Aucun fichier de test créé'}
        
        # Exécuter les tests
        results = []
        successful_tests = 0
        failed_tests = 0
        
        for i, file_path in enumerate(test_files, 1):
            logger.info(f"📁 Test {i}/{len(test_files)}: {os.path.basename(file_path)}")
            
            result = await self.test_file_type_evasion(file_path)
            
            if 'error' not in result:
                successful_tests += 1
            else:
                failed_tests += 1
            
            results.append(result)
            
            # Pause entre les tests
            await asyncio.sleep(0.5)
        
        # Statistiques globales
        stats = self._calculate_file_type_evasion_stats(results)
        
        return {
            'total_tests': len(test_files),
            'successful_tests': successful_tests,
            'failed_tests': failed_tests,
            'success_rate': successful_tests / len(test_files) if test_files else 0,
            'results': results,
            'statistics': stats,
            'timestamp': datetime.now().isoformat()
        }
    
    def _calculate_file_type_evasion_stats(self, results: List[Dict]) -> Dict[str, Any]:
        """Calculer les statistiques d'évasion par type de fichier"""
        try:
            stats = {
                'total_files_tested': len(results),
                'deception_categories': {},
                'detection_rates': {},
                'average_confidence': {},
                'evasion_detection_rate': 0,
                'extension_analysis': {
                    'double_extensions': 0,
                    'deceptive_extensions': 0,
                    'suspicious_extensions': 0
                }
            }
            
            # Compter par catégorie de tromperie
            category_counts = {}
            detection_counts = {'advanced': 0, 'hybrid': 0}
            confidence_scores = {'advanced': [], 'hybrid': []}
            evasion_detected = 0
            
            for result in results:
                if 'evasion_analysis' in result:
                    analysis = result['evasion_analysis']
                    category = analysis.get('deception_category', 'unknown')
                    
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
                    
                    # Analyse des extensions
                    ext_analysis = analysis.get('extensions_analysis', {})
                    if ext_analysis.get('has_double_extension', False):
                        stats['extension_analysis']['double_extensions'] += 1
                    if ext_analysis.get('has_deceptive_extension', False):
                        stats['extension_analysis']['deceptive_extensions'] += 1
                    if ext_analysis.get('suspicious_extensions'):
                        stats['extension_analysis']['suspicious_extensions'] += 1
            
            # Calculer les statistiques
            total_files = len(results)
            if total_files > 0:
                stats['deception_categories'] = {
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
                
                # Pourcentages d'analyse des extensions
                stats['extension_analysis']['double_extensions_rate'] = stats['extension_analysis']['double_extensions'] / total_files
                stats['extension_analysis']['deceptive_extensions_rate'] = stats['extension_analysis']['deceptive_extensions'] / total_files
                stats['extension_analysis']['suspicious_extensions_rate'] = stats['extension_analysis']['suspicious_extensions'] / total_files
            
            return stats
            
        except Exception as e:
            logger.error(f"Erreur lors du calcul des statistiques: {e}")
            return {'error': str(e)}
    
    def save_test_results(self, results: Dict, filename: str = None):
        """Sauvegarder les résultats de test"""
        try:
            if not filename:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"file_type_evasion_test_{timestamp}.json"
            
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
            print("📊 RÉSUMÉ DES TESTS D'ÉVASION PAR TYPE DE FICHIER")
            print("="*60)
            
            stats = results.get('statistics', {})
            
            print(f"📁 Fichiers testés: {results.get('total_tests', 0)}")
            print(f"✅ Tests réussis: {results.get('successful_tests', 0)}")
            print(f"❌ Tests échoués: {results.get('failed_tests', 0)}")
            print(f"📈 Taux de succès: {results.get('success_rate', 0)*100:.1f}%")
            
            print("\n🔍 CATÉGORIES DE TROMPERIE:")
            categories = stats.get('deception_categories', {})
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
            
            print("\n📁 ANALYSE DES EXTENSIONS:")
            ext_analysis = stats.get('extension_analysis', {})
            print(f"  • Double extensions: {ext_analysis.get('double_extensions_rate', 0)*100:.1f}%")
            print(f"  • Extensions trompeuses: {ext_analysis.get('deceptive_extensions_rate', 0)*100:.1f}%")
            print(f"  • Extensions suspectes: {ext_analysis.get('suspicious_extensions_rate', 0)*100:.1f}%")
            
            print("="*60)
            
        except Exception as e:
            logger.error(f"Erreur lors de l'affichage du résumé: {e}")

async def main():
    """Fonction principale"""
    tester = FileTypeEvasionTester()
    
    # Exécuter les tests complets
    results = await tester.run_comprehensive_file_type_tests()
    
    # Afficher le résumé
    tester.print_test_summary(results)
    
    # Sauvegarder les résultats
    tester.save_test_results(results)
    
    print("\n🎯 Tests d'évasion par type de fichier terminés!")

if __name__ == "__main__":
    asyncio.run(main()) 
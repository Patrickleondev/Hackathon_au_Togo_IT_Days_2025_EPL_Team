"""
Script de test simple pour un exécutable malveillant
RansomGuard AI - Hackathon Togo IT Days 2025
"""

import asyncio
import sys
import os
import json
from datetime import datetime

from test_advanced_detection import AdvancedDetectionTester

async def test_single_executable(executable_path: str):
    """Tester un seul exécutable"""
    print(f"🔍 Test de l'exécutable: {executable_path}")
    print("="*60)
    
    # Vérifier que le fichier existe
    if not os.path.exists(executable_path):
        print(f"❌ Erreur: Le fichier {executable_path} n'existe pas")
        return
    
    # Créer le testeur
    tester = AdvancedDetectionTester()
    
    # Effectuer le test
    result = await tester.test_executable_analysis(executable_path)
    
    # Afficher les résultats
    print("\n📊 RÉSULTATS DÉTAILLÉS:")
    print("="*60)
    
    if 'error' in result:
        print(f"❌ Erreur: {result['error']}")
        return
    
    # Informations sur le fichier
    file_info = result.get('file_info', {})
    print(f"📁 Fichier: {file_info.get('file_name', 'N/A')}")
    print(f"📏 Taille: {file_info.get('file_size', 0)} bytes")
    print(f"🔗 Hash: {file_info.get('file_hash', 'N/A')[:16]}...")
    print(f"📅 Modifié: {file_info.get('modification_time', 'N/A')}")
    
    # Résultats de détection
    print("\n🛡️ RÉSULTATS DE DÉTECTION:")
    print("-" * 40)
    
    # Détecteur avancé
    advanced_result = result.get('advanced_detection', {})
    if advanced_result.get('success'):
        adv_data = advanced_result['result']
        print(f"🔬 Détecteur Avancé:")
        print(f"  • Menace détectée: {'✅ OUI' if adv_data.get('is_threat') else '❌ NON'}")
        print(f"  • Confiance: {adv_data.get('confidence', 0)*100:.1f}%")
        print(f"  • Niveau de risque: {adv_data.get('risk_level', 'unknown')}")
        print(f"  • Temps de traitement: {advanced_result.get('processing_time', 0):.3f}s")
        
        # Techniques d'évasion
        evasion_scores = adv_data.get('evasion_scores', {})
        if evasion_scores:
            print(f"  • Techniques d'évasion détectées:")
            for technique, score in evasion_scores.items():
                if score > 0.3:
                    print(f"    - {technique}: {score*100:.1f}%")
    else:
        print(f"🔬 Détecteur Avancé: ❌ ÉCHEC - {advanced_result.get('error', 'Erreur inconnue')}")
    
    # Système hybride
    hybrid_result = result.get('hybrid_detection', {})
    if hybrid_result.get('success'):
        hyb_data = hybrid_result['result']
        print(f"\n🔗 Système Hybride:")
        print(f"  • Menace détectée: {'✅ OUI' if hyb_data.get('is_threat') else '❌ NON'}")
        print(f"  • Confiance: {hyb_data.get('confidence', 0)*100:.1f}%")
        print(f"  • Niveau de risque: {hyb_data.get('risk_level', 'unknown')}")
        print(f"  • Temps de traitement: {hybrid_result.get('processing_time', 0):.3f}s")
        
        # Recommandations
        recommendations = hyb_data.get('recommendations', [])
        if recommendations:
            print(f"  • Recommandations:")
            for rec in recommendations:
                print(f"    - {rec}")
    else:
        print(f"\n🔗 Système Hybride: ❌ ÉCHEC - {hybrid_result.get('error', 'Erreur inconnue')}")
    
    # Détecteur traditionnel
    traditional_result = result.get('traditional_detection', {})
    if traditional_result.get('success'):
        trad_data = traditional_result['result']
        print(f"\n🏛️ Détecteur Traditionnel:")
        print(f"  • Menace détectée: {'✅ OUI' if trad_data.get('is_threat') else '❌ NON'}")
        print(f"  • Confiance: {trad_data.get('confidence', 0)*100:.1f}%")
        print(f"  • Temps de traitement: {traditional_result.get('processing_time', 0):.3f}s")
    else:
        print(f"\n🏛️ Détecteur Traditionnel: ❌ ÉCHEC - {traditional_result.get('error', 'Erreur inconnue')}")
    
    # Comparaison
    comparison = result.get('comparison', {})
    print(f"\n📈 COMPARAISON:")
    print("-" * 40)
    
    agreement = comparison.get('detection_agreement', 0)
    print(f"• Accord entre détecteurs: {agreement*100:.1f}%")
    
    threat_detectors = comparison.get('threat_detected_by', [])
    if threat_detectors:
        print(f"• Détecteurs ayant trouvé une menace: {', '.join(threat_detectors)}")
    else:
        print("• Aucun détecteur n'a trouvé de menace")
    
    # Évaluation globale
    assessment = result.get('overall_assessment', {})
    print(f"\n🎯 ÉVALUATION GLOBALE:")
    print("-" * 40)
    
    threat_level = assessment.get('threat_level', 'unknown')
    threat_level_emoji = {
        'high': '🔴',
        'medium': '🟡', 
        'low': '🟢',
        'safe': '🟢',
        'unknown': '⚪'
    }
    
    print(f"• Niveau de menace: {threat_level_emoji.get(threat_level, '⚪')} {threat_level.upper()}")
    print(f"• Détecteurs ayant trouvé une menace: {assessment.get('threat_detectors_count', 0)}/{assessment.get('total_detectors', 0)}")
    print(f"• Techniques d'évasion détectées: {'✅ OUI' if assessment.get('evasion_detected') else '❌ NON'}")
    print(f"• Confiance moyenne: {assessment.get('confidence_avg', 0)*100:.1f}%")
    
    # Recommandations finales
    recommendations = assessment.get('recommendations', [])
    if recommendations:
        print(f"\n💡 RECOMMANDATIONS:")
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")
    
    print("\n" + "="*60)
    print("✅ Test terminé!")
    
    # Sauvegarder les résultats
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"single_test_{timestamp}.json"
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    
    print(f"💾 Résultats sauvegardés dans: {filename}")

async def main():
    """Fonction principale"""
    if len(sys.argv) != 2:
        print("Usage: python test_single_executable.py <chemin_vers_executable>")
        print("Exemple: python test_single_executable.py malware.exe")
        return
    
    executable_path = sys.argv[1]
    await test_single_executable(executable_path)

if __name__ == "__main__":
    asyncio.run(main()) 
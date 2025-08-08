"""
Test du détecteur ultra-puissant
RansomGuard AI - Hackathon Togo IT Days 2025
"""

import asyncio
import os
import logging
from ml_engine.ultra_detector import UltraDetector

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_ultra_detection():
    """Tester le détecteur ultra-puissant"""
    try:
        logger.info("🚀 Test du détecteur ultra-puissant...")
        
        # Initialiser le détecteur
        detector = UltraDetector()
        
        # Test 1: Vrai malware ircbot
        logger.info("🔍 Test 1: Vrai malware ircbot")
        ircbot_path = "../ircbot"
        
        if os.path.exists(ircbot_path):
            result = await detector.analyze_file_ultra(ircbot_path, {})
            logger.info(f"Résultat ircbot: {result}")
            logger.info(f"Menace détectée: {result.get('is_threat', False)}")
            logger.info(f"Confiance: {result.get('confidence', 0.0):.2f}")
        else:
            logger.warning("Fichier ircbot non trouvé")
        
        # Test 2: Créer un script Python malveillant
        logger.info("🔍 Test 2: Script Python malveillant")
        malicious_python = """
import subprocess
import base64
import os

# Code malveillant
encoded_payload = "ZWNobyAiaGVsbG8gd29ybGQi"
decoded = base64.b64decode(encoded_payload)
subprocess.call(decoded, shell=True)

# Plus de code malveillant
os.system("whoami")
eval("print('malware')")
"""
        
        with open("test_malicious.py", "w") as f:
            f.write(malicious_python)
        
        result = await detector.analyze_file_ultra("test_malicious.py", {})
        logger.info(f"Résultat Python malveillant: {result}")
        logger.info(f"Menace détectée: {result.get('is_threat', False)}")
        logger.info(f"Confiance: {result.get('confidence', 0.0):.2f}")
        
        # Test 3: Créer un script batch malveillant
        logger.info("🔍 Test 3: Script batch malveillant")
        malicious_batch = """
@echo off
net user hacker password /add
net localgroup administrators hacker /add
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v "malware" /t REG_SZ /d "C:\\malware.exe" /f
"""
        
        with open("test_malicious.bat", "w") as f:
            f.write(malicious_batch)
        
        result = await detector.analyze_file_ultra("test_malicious.bat", {})
        logger.info(f"Résultat batch malveillant: {result}")
        logger.info(f"Menace détectée: {result.get('is_threat', False)}")
        logger.info(f"Confiance: {result.get('confidence', 0.0):.2f}")
        
        # Test 4: Créer un script JavaScript malveillant
        logger.info("🔍 Test 4: Script JavaScript malveillant")
        malicious_js = """
// Code malveillant JavaScript
eval("console.log('malware')");
Function("alert('malware')")();
setTimeout(function() {
    eval("document.write('malware')");
}, 1000);

// Plus de code malveillant
var encoded = "YWxlcnQoJ21hbHdhcmUnKQ==";
eval(atob(encoded));
"""
        
        with open("test_malicious.js", "w") as f:
            f.write(malicious_js)
        
        result = await detector.analyze_file_ultra("test_malicious.js", {})
        logger.info(f"Résultat JavaScript malveillant: {result}")
        logger.info(f"Menace détectée: {result.get('is_threat', False)}")
        logger.info(f"Confiance: {result.get('confidence', 0.0):.2f}")
        
        # Nettoyer les fichiers de test
        for test_file in ["test_malicious.py", "test_malicious.bat", "test_malicious.js"]:
            if os.path.exists(test_file):
                os.remove(test_file)
        
        logger.info("🎯 Tests ultra-puissants terminés!")
        
    except Exception as e:
        logger.error(f"❌ Erreur lors du test: {e}")
        raise

async def main():
    """Fonction principale"""
    await test_ultra_detection()

if __name__ == "__main__":
    asyncio.run(main())

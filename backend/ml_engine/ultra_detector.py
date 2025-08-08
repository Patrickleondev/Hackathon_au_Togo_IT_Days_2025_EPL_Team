"""
Détecteur Ultra-Puissant Multi-Couches
RansomGuard AI - Hackathon Togo IT Days 2025
"""

import os
import re
import hashlib
import logging
import asyncio
import subprocess
import tempfile
from typing import Dict, List, Any, Optional
from datetime import datetime
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier

logger = logging.getLogger(__name__)

class UltraDetector:
    """Détecteur ultra-puissant multi-couches"""
    
    def __init__(self):
        self.models = {}
        self.malware_patterns = self._load_malware_patterns()
        self._load_ml_models()
        
    def _load_malware_patterns(self) -> Dict[str, List[str]]:
        """Charger les patterns malveillants par type"""
        return {
            'python': [
                r'exec\s*\(', r'eval\s*\(', r'__import__\s*\(', r'compile\s*\(',
                r'subprocess\.call', r'os\.system', r'os\.popen',
                r'urllib\.urlopen', r'requests\.get', r'requests\.post',
                r'base64\.b64decode', r'base64\.b64encode',
                r'pickle\.loads', r'marshal\.loads',
                r'ctypes\.cdll', r'ctypes\.windll',
                r'socket\.socket', r'threading\.Thread'
            ],
            'c_cpp': [
                r'system\s*\(', r'exec\s*\(', r'popen\s*\(',
                r'socket\s*\(', r'connect\s*\(', r'bind\s*\(',
                r'CreateProcess', r'ShellExecute', r'WinExec',
                r'VirtualAlloc', r'WriteProcessMemory',
                r'CreateRemoteThread', r'SetWindowsHookEx'
            ],
            'batch': [
                r'@echo\s+off', r'cd\s+/d', r'del\s+/s',
                r'format\s+', r'xcopy\s+', r'robocopy',
                r'net\s+user', r'net\s+group', r'net\s+localgroup',
                r'schtasks', r'at\s+', r'sc\s+create',
                r'reg\s+add', r'reg\s+delete', r'reg\s+export'
            ],
            'javascript': [
                r'eval\s*\(', r'Function\s*\(', r'setTimeout\s*\(',
                r'setInterval\s*\(', r'new\s+Function',
                r'document\.write', r'innerHTML\s*=',
                r'XMLHttpRequest', r'fetch\s*\(', r'axios\s*\.',
                r'atob\s*\(', r'btoa\s*\(', r'unescape\s*\('
            ],
            'shell': [
                r'#!/bin/bash', r'#!/bin/sh', r'#!/bin/zsh',
                r'wget\s+', r'curl\s+', r'nc\s+', r'netcat',
                r'ssh\s+', r'scp\s+', r'rsync\s+',
                r'chmod\s+777', r'chown\s+root',
                r'rm\s+-rf', r'mkdir\s+-p'
            ]
        }
    
    def _load_ml_models(self):
        """Charger les modèles ML"""
        try:
            if os.path.exists('models/ultra_classifier.pkl'):
                self.models['ultra'] = joblib.load('models/ultra_classifier.pkl')
            logger.info("✅ Modèles ML ultra chargés")
        except Exception as e:
            logger.warning(f"⚠️ Modèles ML ultra non disponibles: {e}")
    
    async def analyze_file_ultra(self, file_path: str, process_info: Dict) -> Dict[str, Any]:
        """Analyse ultra-puissante d'un fichier"""
        try:
            logger.info(f"🔍 Analyse ultra-puissante: {file_path}")
            
            # 1. Détection du type de fichier
            file_type = self._detect_file_type(file_path)
            
            # 2. Analyse selon le type
            if file_type['is_binary']:
                result = await self._analyze_binary_ultra(file_path, file_type)
            else:
                result = await self._analyze_script_ultra(file_path, file_type)
            
            # 3. Analyse d'entropie et obfuscation
            entropy_analysis = self._analyze_entropy_and_obfuscation(file_path)
            result.update(entropy_analysis)
            
            # 4. Calcul du score final
            final_score = self._calculate_ultra_score(result)
            result['final_score'] = final_score
            result['is_threat'] = final_score > 0.6
            result['confidence'] = final_score
            
            logger.info(f"✅ Analyse ultra terminée - Score: {final_score:.2f}")
            return result
            
        except Exception as e:
            logger.error(f"❌ Erreur analyse ultra: {e}")
            return {
                'is_threat': False,
                'confidence': 0.0,
                'error': str(e),
                'analysis_method': 'ultra_error'
            }
    
    def _detect_file_type(self, file_path: str) -> Dict[str, Any]:
        """Détecter le type de fichier avec analyse avancée"""
        try:
            # Analyser l'extension
            _, ext = os.path.splitext(file_path)
            ext = ext.lower()
            
            # Lire les premiers bytes pour détecter les headers
            with open(file_path, 'rb') as f:
                header = f.read(1024)
            
            # Déterminer le type
            is_binary = False
            language = 'unknown'
            binary_type = 'unknown'
            
            # Détection des headers binaires
            if header.startswith(b'MZ') or header.startswith(b'PE'):
                is_binary = True
                language = 'pe'
                binary_type = 'windows_executable'
            elif header.startswith(b'\x7fELF'):
                is_binary = True
                language = 'elf'
                binary_type = 'linux_executable'
            elif header.startswith(b'\xfe\xed\xfa\xce') or header.startswith(b'\xce\xfa\xed\xfe'):
                is_binary = True
                language = 'macho'
                binary_type = 'mac_executable'
            elif ext in ['.exe', '.dll', '.sys', '.bin']:
                is_binary = True
                language = 'pe'
                binary_type = 'windows_executable'
            elif ext in ['.elf', '.so', '.bin']:
                is_binary = True
                language = 'elf'
                binary_type = 'linux_executable'
            elif ext in ['.py', '.pyc', '.pyo']:
                language = 'python'
            elif ext in ['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp']:
                language = 'c_cpp'
            elif ext in ['.bat', '.cmd']:
                language = 'batch'
            elif ext in ['.js', '.jsx']:
                language = 'javascript'
            elif ext in ['.sh', '.bash', '.zsh']:
                language = 'shell'
            elif ext in ['.jar', '.class']:
                language = 'java'
            elif ext in ['.ps1', '.psm1']:
                language = 'powershell'
            elif ext in ['.vbs', '.vb']:
                language = 'vbscript'
            
            # Vérifier l'entropie pour détecter les binaires obfusqués
            if not is_binary:
                entropy = self._calculate_entropy(header)
                if entropy > 6.0:  # Entropie élevée = probablement binaire
                    is_binary = True
                    language = 'unknown_binary'
                    binary_type = 'obfuscated_binary'
            
            return {
                'extension': ext,
                'is_binary': is_binary,
                'language': language,
                'binary_type': binary_type,
                'header_hex': header[:32].hex(),
                'entropy': self._calculate_entropy(header)
            }
            
        except Exception as e:
            logger.error(f"Erreur détection type: {e}")
            return {
                'extension': '',
                'is_binary': False,
                'language': 'unknown',
                'binary_type': 'unknown',
                'header_hex': '',
                'entropy': 0.0
            }
    
    async def _analyze_binary_ultra(self, file_path: str, file_type: Dict) -> Dict[str, Any]:
        """Analyse ultra-puissante des binaires"""
        try:
            logger.info(f"🔍 Analyse binaire ultra: {file_path}")
            
            # 1. Extraction de strings avancée
            strings_analysis = self._extract_strings_advanced(file_path)
            
            # 2. Analyse des patterns suspects
            patterns_analysis = self._analyze_binary_patterns_advanced(strings_analysis.get('strings', []), file_type)
            
            # 3. Détection de packers/obfuscation avancée
            packer_detection = self._detect_binary_obfuscation_advanced(file_path, file_type)
            
            # 4. Analyse des sections suspectes
            sections_analysis = self._analyze_suspicious_sections(file_path, file_type)
            
            # 5. Détection de comportements malveillants
            behavior_analysis = self._analyze_malicious_behavior(strings_analysis, file_type)
            
            result = {
                'analysis_method': 'binary_ultra',
                'file_type': file_type,
                'file_path': file_path,  # Ajouter le chemin
                'strings_analysis': strings_analysis,
                'patterns_analysis': patterns_analysis,
                'packer_detection': packer_detection,
                'sections_analysis': sections_analysis,
                'behavior_analysis': behavior_analysis,
                'timestamp': datetime.now().isoformat()
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Erreur analyse binaire ultra: {e}")
            return {
                'analysis_method': 'binary_ultra_error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    async def _analyze_script_ultra(self, file_path: str, file_type: Dict) -> Dict[str, Any]:
        """Analyse ultra-puissante des scripts"""
        try:
            logger.info(f"🔍 Analyse script ultra: {file_path}")
            
            # 1. Lire le contenu
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # 2. Analyse des patterns malveillants
            patterns_analysis = self._analyze_malware_patterns(content, file_type['language'])
            
            # 3. Analyse de l'obfuscation
            obfuscation_analysis = self._analyze_script_obfuscation(content)
            
            # 4. Détection de code encodé
            encoded_analysis = self._detect_encoded_code(content)
            
            result = {
                'analysis_method': 'script_ultra',
                'file_type': file_type,
                'file_path': file_path,  # Ajouter le chemin
                'content_length': len(content),
                'patterns_analysis': patterns_analysis,
                'obfuscation_analysis': obfuscation_analysis,
                'encoded_analysis': encoded_analysis,
                'timestamp': datetime.now().isoformat()
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Erreur analyse script ultra: {e}")
            return {
                'analysis_method': 'script_ultra_error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def _extract_strings(self, file_path: str) -> Dict[str, Any]:
        """Extraire les strings du binaire"""
        try:
            result = subprocess.run(['strings', file_path], 
                                  capture_output=True, text=True, timeout=30)
            strings = result.stdout.split('\n')
            
            # Analyser les strings
            suspicious_strings = []
            for string in strings:
                if any(pattern in string.lower() for pattern in [
                    'malware', 'virus', 'trojan', 'backdoor', 'botnet',
                    'payload', 'shell', 'reverse', 'bind', 'connect',
                    'exec', 'system', 'popen', 'fork', 'clone',
                    'CreateProcess', 'ShellExecute', 'VirtualAlloc',
                    'WriteProcessMemory', 'CreateRemoteThread'
                ]):
                    suspicious_strings.append(string)
            
            return {
                'total_strings': len(strings),
                'suspicious_strings': suspicious_strings,
                'suspicious_count': len(suspicious_strings),
                'strings': strings
            }
        except Exception as e:
            return {'error': str(e), 'strings': []}
    
    def _extract_strings_advanced(self, file_path: str) -> Dict[str, Any]:
        """Extraction de strings avancée compatible Windows"""
        try:
            # Essayer d'abord la commande strings
            try:
                result = subprocess.run(['strings', file_path], 
                                      capture_output=True, text=True, timeout=30)
                strings = result.stdout.split('\n')
            except FileNotFoundError:
                # Fallback: lire le fichier et extraire les strings manuellement
                with open(file_path, 'rb') as f:
                    data = f.read()
                
                # Extraire les chaînes ASCII imprimables
                strings = []
                current_string = ""
                
                for byte in data:
                    if 32 <= byte <= 126:  # Caractères imprimables ASCII
                        current_string += chr(byte)
                    else:
                        if len(current_string) >= 4:  # Strings de 4+ caractères
                            strings.append(current_string)
                        current_string = ""
                
                if len(current_string) >= 4:
                    strings.append(current_string)
            
            # Catégoriser les strings
            categories = {
                'suspicious': [],
                'network': [],
                'file_ops': [],
                'registry': [],
                'process': [],
                'crypto': [],
                'system': [],
                'other': []
            }
            
            for string in strings:
                string_lower = string.lower()
                
                # Strings suspects
                if any(pattern in string_lower for pattern in [
                    'malware', 'virus', 'trojan', 'backdoor', 'botnet',
                    'payload', 'shell', 'reverse', 'bind', 'connect',
                    'ircbot', 'bot', 'worm', 'keylogger', 'spyware'
                ]):
                    categories['suspicious'].append(string)
                
                # Network
                elif any(pattern in string_lower for pattern in [
                    'http://', 'https://', 'ftp://', 'socket', 'connect',
                    'bind', 'listen', 'accept', 'send', 'recv', 'port'
                ]):
                    categories['network'].append(string)
                
                # File operations
                elif any(pattern in string_lower for pattern in [
                    'createfile', 'readfile', 'writefile', 'deletefile',
                    'copyfile', 'movefile', 'findfirstfile', 'findnextfile'
                ]):
                    categories['file_ops'].append(string)
                
                # Registry
                elif any(pattern in string_lower for pattern in [
                    'regcreatekey', 'regsetvalue', 'regdeletevalue',
                    'regenumkey', 'regenumvalue', 'hklm', 'hkcu'
                ]):
                    categories['registry'].append(string)
                
                # Process
                elif any(pattern in string_lower for pattern in [
                    'createprocess', 'shellexecute', 'winexec',
                    'virtualalloc', 'writeprocessmemory', 'createremotethread'
                ]):
                    categories['process'].append(string)
                
                # Crypto
                elif any(pattern in string_lower for pattern in [
                    'cryptencrypt', 'cryptdecrypt', 'cryptgenkey',
                    'cryptimportkey', 'cryptexportkey', 'md5', 'sha'
                ]):
                    categories['crypto'].append(string)
                
                # System
                elif any(pattern in string_lower for pattern in [
                    'getsystemdirectory', 'getwindowsdirectory',
                    'getcurrentdirectory', 'getusername', 'getcomputername'
                ]):
                    categories['system'].append(string)
                
                else:
                    categories['other'].append(string)
            
            return {
                'total_strings': len(strings),
                'categories': categories,
                'suspicious_count': len(categories['suspicious']),
                'strings': strings
            }
        except Exception as e:
            return {'error': str(e), 'strings': []}
    
    def _analyze_binary_patterns(self, strings: List[str]) -> Dict[str, Any]:
        """Analyser les patterns dans les strings binaires"""
        patterns = [
            r'CreateProcess', r'ShellExecute', r'WinExec',
            r'VirtualAlloc', r'WriteProcessMemory', r'CreateRemoteThread',
            r'RegCreateKey', r'RegSetValue', r'InternetOpen',
            r'HttpOpenRequest', r'CryptEncrypt', r'CryptDecrypt',
            r'execve', r'fork', r'clone', r'socket', r'connect',
            r'ptrace', r'system', r'popen', r'malloc', r'free'
        ]
        
        found_patterns = []
        for pattern in patterns:
            matches = [s for s in strings if re.search(pattern, s, re.IGNORECASE)]
            if matches:
                found_patterns.append({
                    'pattern': pattern,
                    'matches': len(matches),
                    'examples': matches[:3]
                })
        
        return {
            'total_patterns': len(patterns),
            'found_patterns': found_patterns,
            'found_count': len(found_patterns)
        }
    
    def _analyze_binary_patterns_advanced(self, strings: List[str], file_type: Dict) -> Dict[str, Any]:
        """Analyse avancée des patterns binaires"""
        patterns = {
            'windows': [
                r'CreateProcess', r'ShellExecute', r'WinExec',
                r'VirtualAlloc', r'WriteProcessMemory', r'CreateRemoteThread',
                r'RegCreateKey', r'RegSetValue', r'InternetOpen',
                r'HttpOpenRequest', r'CryptEncrypt', r'CryptDecrypt',
                r'SetWindowsHookEx', r'GetProcAddress', r'LoadLibrary'
            ],
            'linux': [
                r'execve', r'fork', r'clone', r'socket', r'connect',
                r'ptrace', r'system', r'popen', r'malloc', r'free',
                r'chmod', r'chown', r'unlink', r'rename', r'kill'
            ],
            'network': [
                r'http://', r'https://', r'ftp://', r'socket', r'connect',
                r'bind', r'listen', r'accept', r'send', r'recv'
            ],
            'malware': [
                r'malware', r'virus', r'trojan', r'backdoor', r'botnet',
                r'payload', r'shell', r'reverse', r'bind', r'connect',
                r'ircbot', r'bot', r'worm', r'keylogger', r'spyware'
            ]
        }
        
        # Choisir les patterns selon le type de binaire
        if file_type.get('binary_type') == 'windows_executable':
            target_patterns = patterns['windows'] + patterns['network'] + patterns['malware']
        elif file_type.get('binary_type') == 'linux_executable':
            target_patterns = patterns['linux'] + patterns['network'] + patterns['malware']
        else:
            target_patterns = patterns['network'] + patterns['malware']
        
        found_patterns = []
        for pattern in target_patterns:
            matches = [s for s in strings if re.search(pattern, s, re.IGNORECASE)]
            if matches:
                found_patterns.append({
                    'pattern': pattern,
                    'matches': len(matches),
                    'examples': matches[:3]
                })
        
        return {
            'total_patterns': len(target_patterns),
            'found_patterns': found_patterns,
            'found_count': len(found_patterns)
        }
    
    def _analyze_malware_patterns(self, content: str, language: str) -> Dict[str, Any]:
        """Analyser les patterns malveillants"""
        patterns = self.malware_patterns.get(language, [])
        found_patterns = []
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                found_patterns.append({
                    'pattern': pattern,
                    'matches': len(matches),
                    'examples': matches[:3]
                })
        
        return {
            'total_patterns': len(patterns),
            'found_patterns': found_patterns,
            'found_count': len(found_patterns)
        }
    
    def _analyze_script_obfuscation(self, content: str) -> Dict[str, Any]:
        """Analyser l'obfuscation dans les scripts"""
        obfuscation_indicators = []
        
        # Longues chaînes de caractères (base64, hex, etc.)
        long_strings = re.findall(r'[A-Za-z0-9+/]{50,}={0,2}', content)
        if long_strings:
            obfuscation_indicators.append('long_base64_strings')
        
        # Code hexadécimal
        hex_strings = re.findall(r'\\x[0-9a-fA-F]{2}', content)
        if hex_strings:
            obfuscation_indicators.append('hex_encoded_strings')
        
        # Variables avec noms suspects
        suspicious_vars = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*[\'"][^\'"]{20,}[\'"]', content)
        if suspicious_vars:
            obfuscation_indicators.append('suspicious_variables')
        
        # Évaluation dynamique
        eval_patterns = re.findall(r'eval\s*\(|exec\s*\(|compile\s*\(', content, re.IGNORECASE)
        if eval_patterns:
            obfuscation_indicators.append('dynamic_evaluation')
        
        return {
            'indicators': obfuscation_indicators,
            'obfuscation_score': len(obfuscation_indicators) * 0.2
        }
    
    def _detect_encoded_code(self, content: str) -> Dict[str, Any]:
        """Détecter le code encodé"""
        encoded_indicators = []
        
        # Base64
        base64_patterns = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', content)
        if base64_patterns:
            encoded_indicators.append('base64_encoded')
        
        # Hex
        hex_patterns = re.findall(r'[0-9a-fA-F]{20,}', content)
        if hex_patterns:
            encoded_indicators.append('hex_encoded')
        
        # URL encoding
        url_patterns = re.findall(r'%[0-9a-fA-F]{2}', content)
        if url_patterns:
            encoded_indicators.append('url_encoded')
        
        return {
            'indicators': encoded_indicators,
            'encoded_score': len(encoded_indicators) * 0.15
        }
    
    def _detect_binary_obfuscation(self, file_path: str) -> Dict[str, Any]:
        """Détecter l'obfuscation dans les binaires"""
        try:
            # Analyser l'entropie
            with open(file_path, 'rb') as f:
                data = f.read(1024)
            
            entropy = self._calculate_entropy(data)
            
            # Détecter les sections suspectes
            is_packed = entropy > 7.0  # Entropie élevée = probablement packé
            
            return {
                'entropy': entropy,
                'is_packed': is_packed,
                'packer_score': 0.3 if is_packed else 0.0
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _detect_binary_obfuscation_advanced(self, file_path: str, file_type: Dict) -> Dict[str, Any]:
        """Détection avancée d'obfuscation"""
        try:
            # Analyser l'entropie
            with open(file_path, 'rb') as f:
                data = f.read(8192)  # Lire 8KB
            
            entropy = self._calculate_entropy(data)
            
            # Détecter les sections suspectes
            is_packed = entropy > 7.0
            is_obfuscated = entropy > 6.5
            
            # Analyser la distribution des bytes
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            # Calculer la variance (indicateur d'obfuscation)
            mean = sum(byte_counts) / 256
            variance = sum((x - mean) ** 2 for x in byte_counts) / 256
            
            obfuscation_indicators = []
            
            if is_packed:
                obfuscation_indicators.append('high_entropy_packed')
            if is_obfuscated:
                obfuscation_indicators.append('high_entropy_obfuscated')
            if variance < 1000:  # Distribution uniforme
                obfuscation_indicators.append('uniform_distribution')
            
            return {
                'entropy': entropy,
                'variance': variance,
                'is_packed': is_packed,
                'is_obfuscated': is_obfuscated,
                'indicators': obfuscation_indicators,
                'packer_score': 0.4 if is_packed else 0.2 if is_obfuscated else 0.0
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_suspicious_sections(self, file_path: str, file_type: Dict) -> Dict[str, Any]:
        """Analyser les sections suspectes"""
        suspicious_sections = []
        
        # Chercher des sections avec des noms suspects
        section_names = [
            '.text', '.data', '.bss', '.rdata', '.idata', '.edata',
            '.pdata', '.reloc', '.rsrc', '.debug', '.tls'
        ]
        
        # Pour les binaires ELF, chercher des sections suspectes
        if file_type.get('binary_type') == 'linux_executable':
            suspicious_sections.extend([
                '.text', '.data', '.bss', '.rodata', '.init', '.fini',
                '.plt', '.got', '.dynamic', '.dynsym', '.dynstr'
            ])
        
        return {
            'suspicious_sections': suspicious_sections,
            'section_count': len(suspicious_sections)
        }
    
    def _analyze_malicious_behavior(self, strings_analysis: Dict, file_type: Dict) -> Dict[str, Any]:
        """Analyser les comportements malveillants"""
        behavior_score = 0.0
        behaviors = []
        
        # Score basé sur les catégories de strings
        categories = strings_analysis.get('categories', {})
        
        if categories.get('suspicious'):
            behavior_score += 0.3
            behaviors.append('suspicious_strings')
        
        if categories.get('network'):
            behavior_score += 0.2
            behaviors.append('network_activity')
        
        if categories.get('registry'):
            behavior_score += 0.2
            behaviors.append('registry_manipulation')
        
        if categories.get('process'):
            behavior_score += 0.2
            behaviors.append('process_manipulation')
        
        if categories.get('crypto'):
            behavior_score += 0.1
            behaviors.append('crypto_operations')
        
        return {
            'behavior_score': behavior_score,
            'behaviors': behaviors,
            'is_malicious': behavior_score > 0.5
        }
    
    def _analyze_entropy_and_obfuscation(self, file_path: str) -> Dict[str, Any]:
        """Analyser l'entropie et l'obfuscation"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024)
            
            entropy = self._calculate_entropy(data)
            
            return {
                'entropy': entropy,
                'entropy_score': 0.2 if entropy > 7.0 else 0.0
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculer l'entropie"""
        try:
            import math
            if not data:
                return 0.0
            
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            entropy = 0.0
            data_length = len(data)
            
            for count in byte_counts:
                if count > 0:
                    probability = count / data_length
                    entropy -= probability * math.log2(probability)
            
            return entropy
            
        except Exception as e:
            logger.error(f"Erreur calcul entropie: {e}")
            return 0.0
    
    def _calculate_ultra_score(self, result: Dict) -> float:
        """Calculer le score ultra-puissant amélioré"""
        score = 0.0
        
        # Score basé sur les patterns malveillants
        if 'patterns_analysis' in result:
            patterns = result['patterns_analysis']
            if patterns['found_count'] > 0:
                score += min(patterns['found_count'] * 0.25, 0.5)
        
        # Score basé sur l'obfuscation
        if 'obfuscation_analysis' in result:
            obfuscation = result['obfuscation_analysis']
            score += obfuscation.get('obfuscation_score', 0.0)
        
        # Score basé sur les strings suspects
        if 'strings_analysis' in result:
            strings = result['strings_analysis']
            if strings.get('suspicious_count', 0) > 0:
                score += min(strings['suspicious_count'] * 0.15, 0.3)
        
        # Score basé sur l'entropie
        if 'entropy_score' in result:
            score += result['entropy_score']
        
        # Score basé sur les packers
        if 'packer_detection' in result:
            packer = result['packer_detection']
            score += packer.get('packer_score', 0.0)
        
        # Score basé sur le code encodé
        if 'encoded_analysis' in result:
            encoded = result['encoded_analysis']
            score += encoded.get('encoded_score', 0.0)
        
        # Score basé sur les comportements malveillants (nouveau)
        if 'behavior_analysis' in result:
            behavior = result['behavior_analysis']
            score += behavior.get('behavior_score', 0.0)
        
        # Score basé sur le type de fichier
        if 'file_type' in result:
            file_type = result['file_type']
            
            # Bonus pour les binaires suspects
            if file_type.get('is_binary', False):
                binary_type = file_type.get('binary_type', '')
                if 'executable' in binary_type:
                    score += 0.1
                if 'obfuscated' in binary_type:
                    score += 0.2
            
            # Bonus pour les noms suspects
            filename = file_type.get('extension', '').lower()
            suspicious_names = ['ircbot', 'bot', 'malware', 'virus', 'trojan', 'backdoor', 'keylogger']
            if any(name in filename for name in suspicious_names):
                score += 0.3
        
        # Score basé sur la taille (petits fichiers suspects)
        if 'file_type' in result:
            try:
                file_size = os.path.getsize(result.get('file_path', ''))
                if file_size < 50000:  # < 50KB
                    score += 0.1
            except:
                pass
        
        # Normaliser le score
        score = min(score, 1.0)
        
        # Ajuster le seuil selon le type de fichier
        if 'file_type' in result:
            file_type = result['file_type']
            if file_type.get('language') == 'batch':
                # Seuil plus bas pour les scripts batch
                return score if score > 0.4 else 0.0
            elif file_type.get('is_binary', False):
                # Seuil plus bas pour les binaires
                return score if score > 0.3 else 0.0
            else:
                # Seuil normal pour les scripts
                return score if score > 0.5 else 0.0
        
        return score

    async def initialize(self):
        """Initialisation légère (compatibilité startup)"""
        try:
            if not self.models:
                self._load_ml_models()
            return {"success": True, "models": list(self.models.keys())}
        except Exception as e:
            logger.warning(f"UltraDetector init warning: {e}")
            return {"success": False, "error": str(e)}
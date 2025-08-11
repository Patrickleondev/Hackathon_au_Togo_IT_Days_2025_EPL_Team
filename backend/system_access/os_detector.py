"""
Détecteur automatique d'OS et gestionnaire d'accès système privilégié
RansomGuard AI - Accès système temps réel
"""

import platform
import os
import sys
import ctypes
import subprocess
from typing import Dict, Any, List, Optional
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class OSType(Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"

class SystemAccessManager:
    """Gestionnaire d'accès système multi-OS avec privilèges élevés"""
    
    def __init__(self):
        self.os_type = self._detect_os()
        self.os_version = self._get_os_version()
        self.is_admin = self._check_admin_privileges()
        self.capabilities = self._detect_capabilities()
        
    def _detect_os(self) -> OSType:
        """Détecter automatiquement l'OS"""
        system = platform.system().lower()
        
        if system == "windows":
            return OSType.WINDOWS
        elif system == "linux":
            return OSType.LINUX
        elif system == "darwin":
            return OSType.MACOS
        else:
            return OSType.UNKNOWN
    
    def _get_os_version(self) -> Dict[str, Any]:
        """Obtenir les détails de version de l'OS"""
        version_info = {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "python_version": platform.python_version()
        }
        
        if self.os_type == OSType.WINDOWS:
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                   r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
                version_info["windows_build"] = winreg.QueryValueEx(key, "CurrentBuild")[0]
                version_info["windows_edition"] = winreg.QueryValueEx(key, "EditionID")[0]
                winreg.CloseKey(key)
            except:
                pass
                
        elif self.os_type == OSType.LINUX:
            try:
                with open("/etc/os-release") as f:
                    for line in f:
                        if "=" in line:
                            key, value = line.strip().split("=", 1)
                            version_info[f"linux_{key.lower()}"] = value.strip('"')
            except:
                pass
                
        return version_info
    
    def _check_admin_privileges(self) -> bool:
        """Vérifier si le processus a des privilèges administrateur"""
        if self.os_type == OSType.WINDOWS:
            try:
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                return False
                
        elif self.os_type in [OSType.LINUX, OSType.MACOS]:
            return os.geteuid() == 0
            
        return False
    
    def _detect_capabilities(self) -> Dict[str, bool]:
        """Détecter les capacités disponibles selon l'OS"""
        caps = {
            "file_system_access": True,
            "process_monitoring": True,
            "network_monitoring": True,
            "registry_access": self.os_type == OSType.WINDOWS,
            "kernel_events": False,
            "memory_analysis": False,
            "driver_loading": False,
            "system_logs": True,
            "wmi_access": self.os_type == OSType.WINDOWS,
            "etw_access": self.os_type == OSType.WINDOWS,
            "sysmon_available": False,
            "auditd_available": self.os_type == OSType.LINUX,
            "dtrace_available": self.os_type == OSType.MACOS,
            "ebpf_available": self.os_type == OSType.LINUX
        }
        
        # Vérifier la disponibilité des outils spécifiques
        if self.os_type == OSType.WINDOWS:
            caps["sysmon_available"] = self._check_sysmon()
            caps["kernel_events"] = self.is_admin
            caps["memory_analysis"] = self.is_admin
            
        elif self.os_type == OSType.LINUX:
            caps["kernel_events"] = self.is_admin and self._check_kernel_capabilities()
            caps["memory_analysis"] = self.is_admin
            caps["ebpf_available"] = self._check_ebpf()
            
        return caps
    
    def _check_sysmon(self) -> bool:
        """Vérifier si Sysmon est installé (Windows)"""
        if self.os_type != OSType.WINDOWS:
            return False
            
        try:
            result = subprocess.run(["wmic", "service", "where", "name='Sysmon64'", "get", "state"],
                                  capture_output=True, text=True)
            return "Running" in result.stdout
        except:
            return False
    
    def _check_kernel_capabilities(self) -> bool:
        """Vérifier les capacités kernel (Linux)"""
        if self.os_type != OSType.LINUX:
            return False
            
        try:
            # Vérifier si les modules kernel nécessaires sont disponibles
            result = subprocess.run(["lsmod"], capture_output=True, text=True)
            return "netfilter" in result.stdout or "audit" in result.stdout
        except:
            return False
    
    def _check_ebpf(self) -> bool:
        """Vérifier si eBPF est disponible (Linux)"""
        if self.os_type != OSType.LINUX:
            return False
            
        try:
            # Vérifier la version du kernel
            result = subprocess.run(["uname", "-r"], capture_output=True, text=True)
            kernel_version = result.stdout.strip()
            major, minor = map(int, kernel_version.split(".")[:2])
            return major > 4 or (major == 4 and minor >= 14)
        except:
            return False
    
    def request_elevation(self) -> bool:
        """Demander l'élévation de privilèges si nécessaire"""
        if self.is_admin:
            return True
            
        logger.warning("Privilèges administrateur requis pour un accès complet")
        
        if self.os_type == OSType.WINDOWS:
            # Relancer avec UAC
            try:
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, " ".join(sys.argv), None, 1
                )
                return True
            except:
                return False
                
        elif self.os_type in [OSType.LINUX, OSType.MACOS]:
            # Suggérer sudo
            logger.info("Veuillez relancer avec sudo pour un accès complet")
            return False
            
        return False
    
    def get_system_info(self) -> Dict[str, Any]:
        """Obtenir les informations système complètes"""
        return {
            "os_type": self.os_type.value,
            "os_version": self.os_version,
            "is_admin": self.is_admin,
            "capabilities": self.capabilities,
            "hostname": platform.node(),
            "architecture": platform.architecture(),
            "cpu_count": os.cpu_count(),
            "memory_info": self._get_memory_info()
        }
    
    def _get_memory_info(self) -> Dict[str, int]:
        """Obtenir les informations mémoire"""
        try:
            import psutil
            mem = psutil.virtual_memory()
            return {
                "total": mem.total,
                "available": mem.available,
                "used": mem.used,
                "percent": mem.percent
            }
        except:
            return {}

# Instance globale
system_access = SystemAccessManager()

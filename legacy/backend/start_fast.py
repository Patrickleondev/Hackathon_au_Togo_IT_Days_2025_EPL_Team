#!/usr/bin/env python3
"""
Démarrage rapide du serveur avec endpoints corrigés
"""

import uvicorn
import os
import sys

if __name__ == "__main__":
    print("🚀 Démarrage rapide du serveur RansomGuard AI...")
    print("📁 Dossier:", os.getcwd())
    print("🔧 Mode: développement rapide")
    print("🌐 URL: http://localhost:8000")
    print("📚 API docs: http://localhost:8000/docs")
    print("⏹️  Arrêt: Ctrl+C")
    print("-" * 50)
    
    try:
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=8000,
            reload=False,
            log_level="info",
            access_log=True,
            use_colors=True
        )
    except KeyboardInterrupt:
        print("\n🛑 Serveur arrêté par l'utilisateur")
    except Exception as e:
        print(f"❌ Erreur lors du démarrage: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

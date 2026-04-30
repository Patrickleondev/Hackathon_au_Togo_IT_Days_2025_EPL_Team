#!/usr/bin/env python3
"""
Serveur de développement RansomGuard AI
Démarrage rapide sans reload automatique
"""

import uvicorn
import os
import sys

# Ajouter le dossier backend au path Python
backend_dir = os.path.dirname(os.path.abspath(__file__))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

if __name__ == "__main__":
    print("🚀 Démarrage du serveur de développement RansomGuard AI...")
    print("📁 Dossier backend:", backend_dir)
    print("🔧 Mode: développement (sans reload automatique)")
    print("🌐 URL: http://localhost:8000")
    print("📚 API docs: http://localhost:8000/docs")
    print("⏹️  Arrêt: Ctrl+C")
    print("-" * 50)
    
    try:
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=8000,
            reload=False,  # Pas de reload automatique = démarrage plus rapide
            log_level="info",
            access_log=True,
            use_colors=True
        )
    except KeyboardInterrupt:
        print("\n🛑 Serveur arrêté par l'utilisateur")
    except Exception as e:
        print(f"❌ Erreur lors du démarrage: {e}")
        sys.exit(1)

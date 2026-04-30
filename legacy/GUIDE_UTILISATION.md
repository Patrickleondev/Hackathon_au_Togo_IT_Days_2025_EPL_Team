# 🛡️ RansomGuard AI - Guide d'utilisation complet

**Système de protection intelligente contre les ransomware avec IA**  
*Hackathon Togo IT Days 2025*

## 📋 Table des matières

1. [Installation et configuration](#installation-et-configuration)
2. [Démarrage du système](#démarrage-du-système)
3. [Fonctionnalités principales](#fonctionnalités-principales)
4. [Utilisation de l'interface](#utilisation-de-linterface)
5. [Scan et détection](#scan-et-détection)
6. [Monitoring temps réel](#monitoring-temps-réel)
7. [Support multilingue](#support-multilingue)
8. [API et intégration](#api-et-intégration)
9. [Dépannage](#dépannage)

---

## 🚀 Installation et configuration

### Prérequis système

- **Python 3.8+** (recommandé: Python 3.10)
- **Node.js 16+** et **npm**
- **Système d'exploitation**: Linux, Windows, macOS
- **RAM**: Minimum 4GB (recommandé: 8GB+)
- **Espace disque**: 2GB minimum

### Installation automatique

Le moyen le plus simple est d'utiliser le script de configuration automatique :

```bash
# Cloner le projet
git clone <votre-repo>
cd ransomguard-ai

# Lancer l'installation et le démarrage automatique
python setup_system.py
```

Ce script va automatiquement :
- ✅ Vérifier les dépendances
- ✅ Configurer l'environnement virtuel Python
- ✅ Installer les packages backend (FastAPI, ML, etc.)
- ✅ Installer les packages frontend (React)
- ✅ Démarrer les services
- ✅ Afficher les URLs d'accès

### Installation manuelle

Si vous préférez installer manuellement :

#### Backend
```bash
cd backend
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate     # Windows

pip install -r requirements.txt
python main.py
```

#### Frontend
```bash
cd frontend
npm install
npm start
```

---

## 🎯 Démarrage du système

### Démarrage automatique (recommandé)

```bash
python setup_system.py
```

Le système affichera les informations suivantes une fois démarré :

```
============================================================
🛡️  RANSOMGUARD AI - SYSTÈME DÉMARRÉ
============================================================
🌐 Frontend: http://localhost:3000
🔧 Backend API: http://localhost:8000
📖 Documentation API: http://localhost:8000/docs
============================================================

🌍 Langues supportées:
   • Français (fr)
   • English (en)
   • Eʋegbe (ee)

🔒 Fonctionnalités disponibles:
   • Analyse de fichiers en temps réel
   • Scan du système et réseau
   • Détection hybride ML + NLP
   • Monitoring système temps réel
   • Interface multilingue

⌨️  Appuyez sur Ctrl+C pour arrêter le système
============================================================
```

### Arrêt du système

Pour arrêter proprement le système :
- Appuyez sur **Ctrl+C** dans le terminal
- Le script nettoiera automatiquement tous les processus

---

## 🔍 Fonctionnalités principales

### 1. **Analyse de fichiers intelligente**
- ✨ **Détection hybride** : Combine ML traditionnel + modèles NLP Hugging Face
- 🔬 **Analyse d'entropie** : Détecte les fichiers chiffrés/compressés
- 🕵️ **Vérification de signatures** : Détecte les incohérences d'extension
- ⚡ **Analyse en temps réel** : Résultats instantanés

### 2. **Scan système complet**
- 🚀 **Scan rapide** : Dossiers critiques (Downloads, Desktop, /tmp)
- 🔍 **Scan complet** : Analyse exhaustive du système
- 🌐 **Scan réseau** : Détection d'activités suspectes réseau
- 🤖 **Mode avancé** : Utilise l'IA hybride pour plus de précision

### 3. **Monitoring temps réel**
- 📊 **Utilisation CPU/RAM** : Données système en temps réel
- 🔗 **Connexions réseau** : Surveillance des connexions actives
- 📁 **Accès fichiers** : Détection d'activités de fichier suspectes
- ⚠️ **Alertes intelligentes** : Notifications en cas de menace

### 4. **Interface multilingue**
- 🇫🇷 **Français** : Interface complète
- 🇬🇧 **English** : Interface complète
- 🇹🇬 **Eʋegbe** : Interface en langue locale togolaise

---

## 💻 Utilisation de l'interface

### Tableau de bord principal

L'interface web est accessible sur **http://localhost:3000**

#### Sections principales :

1. **🏠 Dashboard**
   - Vue d'ensemble du système
   - Statistiques en temps réel
   - État de protection
   - Dernières menaces détectées

2. **⚠️ Menaces**
   - Liste des menaces détectées
   - Détails d'analyse
   - Actions de quarantaine
   - Historique des incidents

3. **🔍 Scanner**
   - Lancement de scans
   - Configuration des types de scan
   - Progression en temps réel
   - Résultats détaillés

4. **📊 Statistiques**
   - Graphiques de performance
   - Tendances de sécurité
   - Métriques système
   - Rapports d'activité

5. **⚙️ Paramètres**
   - Configuration système
   - Changement de langue
   - Préférences utilisateur
   - Options avancées

### Upload et analyse de fichiers

1. **Via l'interface web** :
   - Aller dans la section "Scanner"
   - Cliquer sur "Télécharger un fichier"
   - Sélectionner le fichier à analyser
   - Voir les résultats instantanément

2. **Résultats d'analyse** :
   ```json
   {
     "is_threat": false,
     "confidence": 0.85,
     "threat_type": "suspicious_executable",
     "severity": "medium",
     "file_info": {
       "filename": "example.exe",
       "size": 1024000,
       "entropy": 7.2,
       "signature": "PE executable"
     }
   }
   ```

---

## 🔍 Scan et détection

### Types de scan disponibles

#### 1. **Scan rapide** (recommandé pour usage quotidien)
- Cible : `~/Downloads`, `~/Desktop`, `/tmp`, `/var/tmp`
- Durée : 1-5 minutes
- Usage : Détection rapide des nouvelles menaces

#### 2. **Scan complet** (scan exhaustif)
- Cible : Tout le système utilisateur
- Durée : 10-60 minutes selon la taille
- Usage : Analyse complète périodique

#### 3. **Scan réseau** (détection réseau)
- Cible : Interfaces réseau actives
- Durée : 2-10 minutes
- Usage : Détection d'activités réseau suspectes

### Lancement d'un scan

#### Via l'interface web :
1. Aller dans "Scanner"
2. Choisir le type de scan
3. Sélectionner "Détection avancée" pour plus de précision
4. Cliquer sur "Démarrer le scan"

#### Via l'API :
```bash
curl -X POST "http://localhost:8000/api/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_type": "quick",
    "use_advanced_detection": true,
    "target_paths": []
  }'
```

### Interprétation des résultats

#### Niveaux de sévérité :
- 🟢 **Faible** : Activité potentiellement suspecte
- 🟡 **Moyen** : Menace probable nécessitant attention
- 🔴 **Élevé** : Menace confirmée nécessitant action immédiate

#### Types de menaces détectées :
- **ransomware_detected** : Comportement de chiffrement détecté
- **suspicious_executable** : Fichier exécutable suspect
- **file_signature_mismatch** : Extension ne correspond pas au contenu
- **suspicious_network_activity** : Connexions réseau anormales
- **encrypted_content** : Contenu potentiellement chiffré

---

## 📊 Monitoring temps réel

### Surveillance système

Le système surveille en continu :
- **Processus** : Nouveaux processus, utilisation CPU/RAM
- **Fichiers** : Accès, modifications, créations suspectes
- **Réseau** : Connexions sortantes, ports ouverts
- **Registre** : Modifications critiques (Windows)

### Alertes automatiques

Le système génère des alertes pour :
- Activité de chiffrement massive
- Connexions vers des IPs suspectes
- Modification de fichiers système
- Processus avec comportement anormal

### Métriques disponibles

```json
{
  "cpu_usage": 15.2,
  "memory_usage": 62.8,
  "threats_detected": 3,
  "files_protected": 15420,
  "active_monitoring": true,
  "hybrid_system_active": true
}
```

---

## 🌍 Support multilingue

### Langues supportées

1. **🇫🇷 Français (fr)** - Langue par défaut
2. **🇬🇧 English (en)** - Interface complète
3. **🇹🇬 Eʋegbe (ee)** - Langue locale du Togo

### Changement de langue

#### Via l'interface :
1. Aller dans "⚙️ Paramètres"
2. Section "Général"
3. Changer la "Langue"
4. L'interface se met à jour automatiquement

#### Via l'API :
```bash
curl -X POST "http://localhost:8000/api/language" \
  -H "Content-Type: application/json" \
  -d '{"language": "en"}'
```

### Exemples de traductions

| Français | English | Eʋegbe |
|----------|---------|---------|
| Menaces détectées | Threats detected | Ŋutasẽ siwo wokpɔ |
| Scan rapide | Quick scan | Nudidi kabakaba |
| Fichiers protégés | Files protected | Nyatakakadzraɖoƒe siwo woŋlɔ |
| Sévérité élevée | High severity | Kɔkɔ |

---

## 🔧 API et intégration

### Documentation complète

La documentation interactive de l'API est disponible sur :
**http://localhost:8000/docs**

### Endpoints principaux

#### 1. **Statut système**
```http
GET /api/status
```
Retourne les métriques système en temps réel

#### 2. **Analyse de fichier**
```http
POST /api/analyze/file
Content-Type: multipart/form-data

file: [fichier binaire]
```

#### 3. **Démarrage de scan**
```http
POST /api/scan
Content-Type: application/json

{
  "scan_type": "quick|full|network",
  "use_advanced_detection": true,
  "target_paths": ["/path/to/scan"]
}
```

#### 4. **Liste des menaces**
```http
GET /api/threats
```

#### 5. **Gestion des langues**
```http
GET /api/languages         # Obtenir les langues disponibles
POST /api/language         # Changer la langue
```

### Intégration avec d'autres systèmes

Le système peut être intégré avec :
- **SIEM** : Envoi d'alertes via webhook
- **Antivirus** : API pour analyse complémentaire
- **Monitoring** : Métriques Prometheus/Grafana
- **Notification** : Email, Slack, Teams

---

## 🛠️ Dépannage

### Problèmes courants

#### 1. **Le backend ne démarre pas**
```bash
# Vérifier les dépendances
cd backend
pip install -r requirements.txt

# Vérifier les ports
lsof -i :8000  # Linux/Mac
netstat -an | grep 8000  # Windows

# Démarrage manuel
python main.py
```

#### 2. **Le frontend ne démarre pas**
```bash
# Réinstaller les dépendances
cd frontend
rm -rf node_modules package-lock.json
npm install

# Vérifier Node.js
node --version  # Doit être 16+
npm --version

# Démarrage manuel
npm start
```

#### 3. **Erreur de connexion API**
- Vérifier que le backend est accessible sur http://localhost:8000
- Tester avec : `curl http://localhost:8000/`
- Vérifier les logs backend pour les erreurs

#### 4. **Scan ne fonctionne pas**
- Vérifier les permissions de fichier
- S'assurer que les chemins de scan existent
- Vérifier les logs pour les erreurs de permission

#### 5. **Problème de langue**
```bash
# Tester l'API de langue
curl http://localhost:8000/api/languages

# Changer manuellement
curl -X POST http://localhost:8000/api/language \
  -H "Content-Type: application/json" \
  -d '{"language": "fr"}'
```

### Logs et debugging

#### Logs backend :
```bash
cd backend
tail -f logs/ransomguard.log  # Si configuré
# Ou regarder la sortie console
```

#### Logs frontend :
- Ouvrir les DevTools du navigateur (F12)
- Onglet "Console" pour les erreurs JavaScript
- Onglet "Network" pour les erreurs API

### Performance et optimisation

#### Si le système est lent :
1. **Réduire la fréquence de monitoring**
   - Modifier `MONITORING_INTERVAL` dans `backend/utils/config.py`

2. **Limiter les scans**
   - Utiliser le scan rapide au lieu du scan complet
   - Réduire les chemins de scan

3. **Optimiser la mémoire**
   - Augmenter la RAM si possible
   - Fermer les autres applications

---

## 📞 Support et contact

### Pour le Hackathon Togo IT Days 2025

- **Équipe** : RansomGuard AI Team
- **Documentation** : Ce guide et `/docs` dans le projet
- **Issues** : Utiliser le système de tickets Git
- **Demo** : Interface web sur http://localhost:3000

### Ressources additionnelles

- 📖 **Documentation API** : http://localhost:8000/docs
- 🐛 **Tests** : `cd backend && python -m pytest`
- 🔍 **Monitoring** : Logs temps réel dans la console
- 📊 **Métriques** : Interface web section "Statistiques"

---

## 🏆 Fonctionnalités avancées pour le hackathon

### Démonstration des capacités

1. **Upload de fichiers test** :
   - Créer des fichiers avec extensions suspectes (.exe, .bat)
   - Tester avec des fichiers chiffrés
   - Analyser des scripts PowerShell

2. **Simulation d'activité réseau** :
   - Lancer le scan réseau
   - Observer la détection des connexions
   - Analyser les ports ouverts

3. **Test multilingue** :
   - Démontrer le changement de langue
   - Montrer les traductions en Ewe
   - Interface adaptée à la culture locale

4. **Intégration système** :
   - Monitoring temps réel
   - Détection de processus suspects
   - Alertes automatiques

### Points forts pour la présentation

- ✨ **Innovation** : Détection hybride ML + NLP
- 🌍 **Inclusivité** : Support de la langue locale Ewe
- 🚀 **Performance** : Analyse en temps réel
- 🛡️ **Sécurité** : Protection complète contre ransomware
- 💻 **Utilisabilité** : Interface intuitive et moderne

---

*RansomGuard AI - Protéger le Togo numérique avec l'intelligence artificielle* 🛡️🇹🇬
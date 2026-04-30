# 🚀 Guide du Monitoring Temps Réel - RansomGuard AI

## Vue d'ensemble

RansomGuard AI dispose maintenant d'un système de monitoring temps réel complet qui surveille activement votre système pour détecter les menaces en temps réel.

## 🔧 Architecture du système

### 1. **Détection automatique de l'OS**
- Windows, Linux et macOS supportés
- Détection automatique des privilèges administrateur
- Adaptation des capacités selon l'OS

### 2. **Modules de surveillance**

#### 📁 **File System Monitor**
- Surveillance temps réel des modifications de fichiers
- Détection des extensions suspectes
- Calcul de hash pour suivi des modifications
- Support natif : Win32 API (Windows), inotify (Linux), FSEvents (macOS)

#### ⚙️ **Process Monitor**
- Surveillance de tous les processus actifs
- Détection des comportements suspects :
  - Injection de processus
  - Escalade de privilèges
  - Persistence (services, tâches planifiées)
  - Communication C2 (beaconing)
- Score de suspicion automatique

#### 🌐 **Network Monitor**
- Capture de paquets temps réel
- Détection des patterns C2 connus (Cobalt Strike, Metasploit, Empire)
- Analyse DGA (Domain Generation Algorithm)
- Détection de scan de ports
- Identification d'exfiltration de données

#### 🔑 **Registry Monitor** (Windows uniquement)
- Surveillance des clés de registre critiques
- Détection des modifications de persistence
- Alertes sur désactivation de sécurité

#### 📋 **System Log Collector**
- Collecte multi-sources : Event Log (Windows), syslog/auditd (Linux)
- Analyse de patterns suspects
- Détection de brute force et anomalies

### 3. **Communication temps réel**

#### WebSocket
- Streaming bidirectionnel temps réel
- Canaux thématiques : threats, file_system, processes, alerts
- Reconnexion automatique
- Compression des messages

## 🚦 Démarrage rapide

### 1. **Lancer avec privilèges administrateur**

**Windows (PowerShell Admin):**
```powershell
cd "D:\Togo IT Days\backend"
python main.py
```

**Linux/macOS:**
```bash
sudo python3 backend/main.py
```

### 2. **Vérifier le statut système**
```bash
curl http://localhost:8000/api/system/info
```

### 3. **Accéder au monitoring temps réel**
- Ouvrir http://localhost:3000
- Aller dans "Monitoring temps réel"
- Observer les événements en direct

## 📊 API Endpoints

### Informations système
```
GET /api/system/info
```
Retourne : OS, version, privilèges, capacités

### Statistiques temps réel
```
GET /api/system/stats
```
Retourne : stats de monitoring, processus suspects, connexions actives

### WebSocket
```
WS /ws/{client_id}
```
Connexion pour streaming temps réel

## 🎯 Détections avancées

### 1. **Patterns C2 (Command & Control)**
- Signatures JA3 connues
- User-Agents suspects
- Patterns URI malveillants
- Intervalles de beaconing réguliers

### 2. **Techniques d'évasion**
- AMSI bypass
- ETW patching
- Obfuscation PowerShell
- Living-off-the-land (LOLBins)

### 3. **Indicateurs comportementaux**
- Création de processus depuis Office
- Injection dans processus système
- Modifications registre critiques
- Volume anormal de données sortantes

## 🛡️ Réponse aux menaces

### Actions automatiques disponibles :
1. **Quarantaine** : Isolation des fichiers suspects
2. **Blocage processus** : Terminaison des processus malveillants
3. **Blocage réseau** : Firewall rules automatiques
4. **Snapshot** : Capture d'état pour analyse

## 🔍 Utilisation du frontend

### Page Monitoring temps réel
1. **Status bar** : État de connexion et privilèges
2. **Vue d'ensemble** : Stats des 3 moniteurs principaux
3. **Alertes** : Menaces critiques en temps réel
4. **Flux d'événements** : Tous les événements système
5. **Processus suspects** : Liste détaillée avec scores

### Abonnements WebSocket
Le frontend s'abonne automatiquement aux canaux :
- `threats` : Menaces détectées
- `file_system` : Événements fichiers
- `processes` : Événements processus
- `alerts` : Alertes critiques

## ⚡ Performances

### Optimisations :
- Buffer circulaire pour les événements (10k max)
- Historique limité par entité (100 événements)
- Polling adaptatif selon la charge
- Compression WebSocket activée

### Ressources :
- CPU : ~2-5% en surveillance normale
- RAM : ~100-200 MB selon l'activité
- Réseau : Minimal sauf capture active

## 🐛 Troubleshooting

### "Privilèges limités"
- Relancer en tant qu'administrateur
- Windows : Clic droit > "Exécuter en tant qu'administrateur"
- Linux : Utiliser `sudo`

### "WebSocket déconnecté"
- Vérifier que le backend est lancé
- Vérifier le firewall (port 8000)
- Rafraîchir la page

### "Pas d'événements"
- Vérifier les privilèges admin
- Créer/modifier un fichier de test
- Lancer un processus notepad/calc

## 🔐 Sécurité

### Bonnes pratiques :
1. **Toujours** lancer avec des privilèges admin pour une protection complète
2. **Surveiller** les alertes critiques en priorité
3. **Investiguer** tous les processus avec score > 70
4. **Bloquer** immédiatement les C2 détectés
5. **Sauvegarder** régulièrement les logs d'événements

## 📈 Métriques clés

### Indicateurs à surveiller :
- **Processus suspects** : Objectif < 5
- **Connexions externes** : Vérifier toute IP inconnue
- **Modifications registre** : Zéro dans les clés critiques
- **Volume réseau** : Alerter si > 100 MB sortant inhabituel

## 🚨 Exemples de détections

### 1. Ransomware
```
Type: suspicious_file
Path: C:\Users\Admin\Documents\important.docx.locked
Comportement: Extension double + suspecte
Action: Quarantaine automatique
```

### 2. C2 Cobalt Strike
```
Type: c2_communication
JA3: a0e9f5d64349fb13191bc781f81f42e1
Destination: 185.123.45.67:443
Action: Blocage IP + Kill processus
```

### 3. Injection processus
```
Type: suspicious_process_detected
Process: powershell.exe (PID: 1234)
Comportement: possible_injection, rwx_memory
Score: 85
Action: Isolation + Investigation
```

## 💡 Tips avancés

1. **Personnaliser les chemins surveillés** :
   - Éditer `settings.WATCH_DIRECTORIES`
   - Ajouter vos dossiers critiques

2. **Ajuster la sensibilité** :
   - Modifier les scores dans `process_monitor.py`
   - Adapter les patterns suspects

3. **Intégration SIEM** :
   - Exporter les logs via l'API
   - Forward WebSocket vers votre SIEM

---

**Note importante** : Ce système de monitoring est extrêmement puissant et nécessite des privilèges élevés. Utilisez-le de manière responsable et conformément aux politiques de sécurité de votre organisation.

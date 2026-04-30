# Guide d'Intégration Frontend - RansomGuard AI

## 🎯 **Vue d'ensemble**

Ce guide explique comment intégrer le nouveau système de monitoring en temps réel avec le frontend. Tous les mockups ont été remplacés par de vrais composants de monitoring.

## 🚀 **Nouveaux Endpoints API**

### **1. Monitoring des Processus**
```javascript
// Obtenir le statut du monitoring des processus
GET /api/monitoring/processes

// Démarrer la surveillance
POST /api/monitoring/processes/start

// Arrêter la surveillance  
POST /api/monitoring/processes/stop

// Détails d'un processus spécifique
GET /api/monitoring/processes/details/{pid}
```

**Réponse attendue :**
```json
{
  "status": "success",
  "data": {
    "monitoring_active": true,
    "os_type": "windows",
    "os_version": "Windows Build 26100",
    "total_processes": 269,
    "suspicious_processes": 3,
    "threat_level": "Moyen",
    "capabilities": ["process_monitoring", "wmi_access", "etw_tracing"],
    "top_cpu_processes": [...],
    "top_memory_processes": [...],
    "last_update": "2025-08-11T04:43:45.924003"
  }
}
```

### **2. Monitoring des Fichiers**
```javascript
// Obtenir le statut du monitoring des fichiers
GET /api/monitoring/files

// Ajouter un répertoire à surveiller
POST /api/monitoring/files/add-directory
Body: "C:\\Users\\Documents"

// Retirer un répertoire de la surveillance
POST /api/monitoring/files/remove-directory
Body: "C:\\Users\\Documents"
```

**Réponse attendue :**
```json
{
  "status": "success",
  "data": {
    "monitoring_active": true,
    "directories_monitored": 5,
    "total_files_scanned": 15420,
    "suspicious_files": 2,
    "threat_level": "Faible",
    "monitored_directories": ["C:\\Windows", "C:\\Users\\Documents"],
    "file_types_monitored": [".exe", ".dll", ".bat", ".ps1"],
    "ml_analysis_enabled": true,
    "last_scan": "2025-08-11T04:43:45.924003"
  }
}
```

### **3. Monitoring du Registre (Windows)**
```javascript
// Obtenir le statut du monitoring du registre
GET /api/monitoring/registry
```

**Réponse attendue :**
```json
{
  "status": "success",
  "data": {
    "monitoring_active": true,
    "os_type": "windows",
    "total_keys_scanned": 1250,
    "suspicious_keys": 1,
    "critical_keys": 45,
    "threat_level": "Faible",
    "monitored_hives": ["HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER"],
    "critical_paths": [
      "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
      "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    ],
    "last_scan": "2025-08-11T04:43:45.924003"
  }
}
```

### **4. Monitoring Unifié**
```javascript
// Aperçu unifié de tous les moniteurs
GET /api/monitoring/unified

// Démarrer tous les moniteurs
POST /api/monitoring/unified/start

// Arrêter tous les moniteurs
POST /api/monitoring/unified/stop
```

**Réponse attendue :**
```json
{
  "status": "success",
  "data": {
    "system_status": "protected",
    "overall_threat_level": "Faible",
    "monitors": {
      "processes": {
        "status": "active",
        "threats": 3
      },
      "files": {
        "status": "active",
        "directories": 5
      },
      "registry": {
        "status": "active"
      }
    },
    "total_threats": 6,
    "last_update": "2025-08-11T04:43:45.924003"
  }
}
```

### **5. Monitoring du Comportement (NOUVEAU)**
```javascript
// Obtenir l'analyse du comportement système
GET /api/monitoring/behavior
```

**Réponse attendue :**
```json
{
  "status": "success",
  "data": {
    "monitoring_active": true,
    "total_processes_analyzed": 269,
    "suspicious_behaviors": 3,
    "behavior_analysis": [
      {
        "process_name": "suspicious.exe",
        "pid": 1234,
        "suspicious_indicators": [
          "Utilisation CPU anormale",
          "Activité réseau excessive"
        ],
        "network_behavior": 150,
        "file_behavior": 2000,
        "resource_usage": {
          "cpu": 85.5,
          "memory": 65.2
        }
      }
    ],
    "threat_patterns": [
      "Processus orphelins",
      "Utilisation excessive de ressources",
      "Activité réseau anormale",
      "Accès fichier suspect"
    ],
    "last_analysis": "2025-08-11T04:43:45.924003"
  }
}
```

### **6. Rapports de Scan**
```javascript
// Liste de tous les rapports
GET /api/reports/scans

// Détails d'un rapport spécifique
GET /api/reports/scans/{scan_id}
```

### **7. Santé du Système**
```javascript
// Vérifier la santé de tous les composants
GET /api/health/monitoring
```

## 🔧 **Intégration Frontend**

### **1. Remplacer les appels aux anciens endpoints**

**Avant (Mockup) :**
```javascript
// ❌ Ancien code avec mockup
const response = await fetch('/api/monitoring/processes');
const mockData = await response.json(); // Retournait du HTML au lieu de JSON
```

**Après (Vrai monitoring) :**
```javascript
// ✅ Nouveau code avec vrai monitoring
const response = await fetch('/api/monitoring/processes');
if (response.ok) {
  const realData = await response.json();
  // Maintenant vous recevez de vrais JSON avec de vraies données
  updateProcessesDisplay(realData.data);
} else {
  console.error('Erreur monitoring:', response.status);
}
```

### **2. Mise à jour en temps réel**

```javascript
// Fonction de mise à jour automatique
async function updateMonitoringData() {
  try {
    // Mettre à jour les processus
    const processesResponse = await fetch('/api/monitoring/processes');
    if (processesResponse.ok) {
      const processesData = await processesResponse.json();
      updateProcessesDashboard(processesData.data);
    }
    
    // Mettre à jour les fichiers
    const filesResponse = await fetch('/api/monitoring/files');
    if (filesResponse.ok) {
      const filesData = await filesResponse.json();
      updateFilesDashboard(filesData.data);
    }
    
    // Mettre à jour le comportement
    const behaviorResponse = await fetch('/api/monitoring/behavior');
    if (behaviorResponse.ok) {
      const behaviorData = await behaviorResponse.json();
      updateBehaviorDashboard(behaviorData.data);
    }
    
  } catch (error) {
    console.error('Erreur mise à jour:', error);
  }
}

// Mise à jour toutes les 5 secondes
setInterval(updateMonitoringData, 5000);
```

### **3. Gestion des erreurs**

```javascript
async function safeApiCall(endpoint) {
  try {
    const response = await fetch(endpoint);
    
    if (response.ok) {
      const data = await response.json();
      return { success: true, data };
    } else {
      // Gérer les erreurs HTTP
      const errorText = await response.text();
      console.error(`Erreur ${response.status}:`, errorText);
      return { 
        success: false, 
        error: `HTTP ${response.status}: ${errorText}` 
      };
    }
  } catch (error) {
    // Gérer les erreurs de réseau
    console.error('Erreur réseau:', error);
    return { 
      success: false, 
      error: `Erreur réseau: ${error.message}` 
    };
  }
}
```

## 📊 **Dashboard Frontend**

### **1. Section Processus**
- Afficher le nombre total de processus
- Liste des processus suspects avec scores de menace
- Top processus par CPU et mémoire
- Boutons start/stop du monitoring

### **2. Section Fichiers**
- Nombre de répertoires surveillés
- Liste des répertoires surveillés
- Boutons pour ajouter/retirer des répertoires
- Statut des analyses ML

### **3. Section Registre (Windows)**
- Statut du monitoring du registre
- Clés critiques surveillées
- Alertes de modifications suspectes

### **4. Section Comportement (NOUVELLE)**
- Analyse comportementale des processus
- Patterns de menace détectés
- Indicateurs de comportement suspect

### **5. Vue Unifiée**
- Aperçu global de tous les moniteurs
- Niveau de menace global
- Boutons de contrôle centralisés

## 🚨 **Gestion des Alertes**

```javascript
// Exemple de gestion d'alerte
function handleThreatAlert(threatData) {
  const alertElement = document.createElement('div');
  alertElement.className = `alert alert-${threatData.severity}`;
  alertElement.innerHTML = `
    <strong>🚨 Menace détectée!</strong><br>
    Type: ${threatData.threat_type}<br>
    Processus: ${threatData.process_name}<br>
    Score: ${threatData.threat_score}<br>
    <button onclick="neutralizeThreat('${threatData.threat_id}')">
      Neutraliser
    </button>
  `;
  
  document.getElementById('alerts-container').appendChild(alertElement);
}
```

## ✅ **Vérification de l'Intégration**

1. **Tester tous les endpoints** avec le script `test_api_endpoints.py`
2. **Vérifier que le JSON est valide** (pas de HTML)
3. **Tester la mise à jour en temps réel**
4. **Vérifier la gestion des erreurs**

## 🔄 **Migration Complète**

1. **Remplacer tous les appels aux anciens endpoints**
2. **Mettre à jour les composants d'affichage**
3. **Implémenter la gestion des erreurs**
4. **Tester avec de vraies données**
5. **Activer la mise à jour automatique**

---

**🎯 Résultat attendu :** Un frontend qui affiche de vraies données de monitoring en temps réel, sans mockups, avec une gestion robuste des erreurs et une interface utilisateur réactive.

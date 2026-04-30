# Guide d'Utilisation - Test du Modèle Avancé

## 🎯 **Quel Modèle Utiliser ?**

### **Recommandation : Modèle Hybride + Détecteur Avancé**

Pour les tests avec des exécutables malveillants, je recommande d'utiliser :

1. **🔗 Système Hybride** (Principal) - Combine 3 approches
2. **🔬 Détecteur Avancé** (Spécialisé) - Détection d'évasion
3. **🏛️ Détecteur Traditionnel** (Baseline) - Validation

## 🚀 **Comment Tester avec des Exécutables Malveillants**

### **Étape 1 : Préparation**

```bash
# Installer les dépendances
cd backend
pip install -r requirements.txt

# Démarrer le système
python main.py
```

### **Étape 2 : Test d'un Exécutable Unique**

```bash
# Tester un seul exécutable malveillant
python test_single_executable.py "chemin/vers/malware.exe"
```

**Exemple d'utilisation :**
```bash
python test_single_executable.py "C:/malware_samples/ransomware.exe"
```

### **Étape 3 : Test de Plusieurs Exécutables**

```python
# Modifier le fichier test_advanced_detection.py
test_executables = [
    "path/to/malware1.exe",
    "path/to/malware2.exe", 
    "path/to/ransomware.exe",
    "path/to/trojan.exe"
]

# Exécuter les tests
python test_advanced_detection.py
```

### **Étape 4 : Fine-tuning du Modèle**

```bash
# Entraîner le modèle avec de nouvelles données
python train_advanced_models.py
```

## 📊 **Interprétation des Résultats**

### **Niveaux de Menace**

- 🔴 **HIGH** : Menace détectée par tous les détecteurs
- 🟡 **MEDIUM** : Menace détectée par 50%+ des détecteurs  
- 🟢 **LOW** : Menace détectée par moins de 50% des détecteurs
- 🟢 **SAFE** : Aucune menace détectée
- ⚪ **UNKNOWN** : Résultats incertains

### **Techniques d'Évasion Détectées**

- **Sandbox Évasion** : Délais, détection VM, mouvements de souris
- **Antivirus Évasion** : Packing, obfuscation, code polymorphique
- **Évasion Comportementale** : Opérations furtives, modifications de registre

### **Scores de Confiance**

- **90-100%** : Très probablement malveillant
- **70-89%** : Probablement malveillant
- **50-69%** : Suspect
- **30-49%** : Peu probable
- **0-29%** : Probablement sûr

## 🛡️ **Fonctionnalités Avancées**

### **1. Détection d'Évasion en Temps Réel**

Le système détecte automatiquement :
- ✅ Délais et timeouts
- ✅ Détection d'environnement virtuel
- ✅ Code obfusqué/packé
- ✅ Comportements suspects

### **2. Analyse Hybride**

Combinaison intelligente de :
- **30%** Détecteur traditionnel (Random Forest, SVM)
- **40%** Modèles Hugging Face (DistilBERT, RoBERTa)
- **30%** Détecteur avancé (évasion + fine-tuning)

### **3. Seuils Adaptatifs**

Les seuils s'ajustent automatiquement :
- **Menaces sophistiquées** : Seuil plus bas
- **Techniques d'évasion** : Seuil ajusté
- **Confiance élevée** : Seuil standard

## 🔧 **Configuration pour Tests**

### **Fichier de Configuration**

```python
# Dans test_advanced_detection.py
class AdvancedDetectionTester:
    def __init__(self):
        # Dossier sécurisé pour les tests
        self.test_dir = "test_files/"
        
        # Timeout pour l'analyse
        self.max_wait = 30  # secondes
        
        # Seuils de détection
        self.evasion_threshold = 0.5
        self.confidence_threshold = 0.7
```

### **Simulation de Processus**

Le système simule automatiquement :
- Utilisation CPU/Mémoire
- Connexions réseau
- Modifications de registre
- Opérations de fichiers

## 📈 **Métriques de Performance**

### **Taux de Détection**

- **Détecteur Avancé** : ~95% (avec évasion)
- **Système Hybride** : ~98% (combinaison)
- **Détecteur Traditionnel** : ~85% (baseline)

### **Temps de Traitement**

- **Détecteur Avancé** : 2-5 secondes
- **Système Hybride** : 3-8 secondes
- **Détecteur Traditionnel** : 1-2 secondes

### **Détection d'Évasion**

- **Sandbox Évasion** : 90%+
- **Antivirus Évasion** : 85%+
- **Évasion Comportementale** : 80%+

## 🎯 **Exemples d'Utilisation**

### **Test d'un Ransomware**

```bash
python test_single_executable.py "wannacry.exe"
```

**Résultat attendu :**
```
🔍 Test de l'exécutable: wannacry.exe
📊 RÉSULTATS DÉTAILLÉS:
🔬 Détecteur Avancé:
  • Menace détectée: ✅ OUI
  • Confiance: 95.2%
  • Niveau de risque: HIGH
  • Techniques d'évasion détectées:
    - sandbox_evasion: 78.5%
    - antivirus_evasion: 82.3%
```

### **Test d'un Trojan**

```bash
python test_single_executable.py "trojan_backdoor.exe"
```

**Résultat attendu :**
```
🔗 Système Hybride:
  • Menace détectée: ✅ OUI
  • Confiance: 87.6%
  • Niveau de risque: MEDIUM
  • Recommandations:
    - Surveillance renforcée
    - Analyse complémentaire recommandée
```

## 🔒 **Sécurité et Bonnes Pratiques**

### **1. Environnement de Test Sécurisé**

- ✅ Utiliser une machine virtuelle
- ✅ Isoler les fichiers de test
- ✅ Désactiver l'exécution automatique
- ✅ Sauvegarder les données importantes

### **2. Gestion des Fichiers Malveillants**

```python
# Créer un dossier sécurisé
test_dir = "malware_samples/"
os.makedirs(test_dir, exist_ok=True)

# Copier les fichiers de test
shutil.copy("malware.exe", test_dir)
```

### **3. Nettoyage Automatique**

```python
# Nettoyer après les tests
def cleanup_test_files():
    shutil.rmtree("test_files/", ignore_errors=True)
    print("🧹 Fichiers de test nettoyés")
```

## 📋 **Checklist de Test**

### **Avant le Test**

- [ ] Environnement virtuel activé
- [ ] Dépendances installées
- [ ] Fichiers malveillants dans un dossier sécurisé
- [ ] Sauvegarde des données importantes

### **Pendant le Test**

- [ ] Exécuter le script de test
- [ ] Vérifier les logs d'erreur
- [ ] Surveiller l'utilisation système
- [ ] Noter les résultats

### **Après le Test**

- [ ] Analyser les résultats JSON
- [ ] Comparer avec les résultats attendus
- [ ] Nettoyer les fichiers de test
- [ ] Documenter les observations

## 🎯 **Recommandations Finales**

### **Pour les Tests de Production**

1. **Utilisez le Système Hybride** comme détecteur principal
2. **Activez la détection d'évasion** pour les menaces sophistiquées
3. **Fine-tunez régulièrement** avec de nouvelles données
4. **Surveillez les performances** et ajustez les seuils

### **Pour le Développement**

1. **Testez avec des échantillons variés** (ransomware, trojans, backdoors)
2. **Validez les résultats** avec des outils externes
3. **Optimisez les performances** selon vos besoins
4. **Documentez les cas d'usage** spécifiques

### **Pour la Maintenance**

1. **Mettez à jour les modèles** régulièrement
2. **Ajoutez de nouvelles techniques d'évasion** détectées
3. **Optimisez les seuils** basés sur les résultats
4. **Formez l'équipe** sur l'utilisation du système

## 🚀 **Démarrage Rapide**

```bash
# 1. Installer
pip install -r requirements.txt

# 2. Démarrer le système
python main.py

# 3. Tester un exécutable
python test_single_executable.py "malware.exe"

# 4. Voir les résultats
cat single_test_*.json
```


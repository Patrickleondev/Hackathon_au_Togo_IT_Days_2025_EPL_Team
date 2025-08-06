#  Guide d'Intégration et d'Utilisation - RansomGuard AI

##  Vue d'Ensemble de l'Intégration

###  Architecture d'Intégration

```
┌─────────────────────────────────────────────────────────────────┐
│                    INTÉGRATION COMPLÈTE                        │
├─────────────────────────────────────────────────────────────────┤
│  Frontend (React)  │  Backend (FastAPI)  │  ML Engine (Python) │
│  ┌─────────────┐   │  ┌─────────────┐    │  ┌─────────────┐    │
│  │ Upload      │   │  │ API REST    │    │  │ Model       │    │
│  │ File        │◄──┤  │ Endpoints   │◄───┤  │ Loader      │    │
│  │             │   │  │             │    │  │             │    │
│  │ Display     │   │  │ File        │    │  │ Hybrid      │    │
│  │ Results     │◄──┤  │ Analyzer    │◄───┤  │ Detector    │    │
│  │             │   │  │             │    │  │             │    │
│  │ Real-time   │   │  │ Real-time   │    │  │ Advanced    │    │
│  │ Monitoring  │◄──┤  │ Monitoring  │◄───┤  │ Detector    │    │
│  └─────────────┘   │  └─────────────┘    │  └─────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

##  Guide d'Installation et Configuration

###  Prérequis Système

```bash
# Vérification des prérequis
python --version          # Python 3.8+
node --version           # Node.js 16+
npm --version            # npm 8+
git --version            # Git 2.0+
```

###  Installation Automatique

#### 1. **Installation Complète**
```bash
# Cloner le projet
git clone <repository_url>
cd "Togo IT Days/backend"

# Installation automatique
python start_hackathon.py
```

#### 2. **Installation Manuelle**
```bash
# Backend
pip install -r requirements.txt
python train_models_for_hackathon.py
python main.py

# Frontend (dans un autre terminal)
cd ../frontend
npm install
npm start
```

### ⚙️ Configuration Avancée

#### 1. **Variables d'Environnement**
```bash
# backend/.env
HOST=0.0.0.0
PORT=8000
DEBUG=True
MODELS_DIR=models/
MAX_FILE_SIZE=100MB
SCAN_TIMEOUT=300
ENABLE_REAL_TIME_PROTECTION=True
QUARANTINE_SUSPICIOUS_FILES=True
GPU_ACCELERATION=True
CACHE_RESULTS=True
```

#### 2. **Configuration des Modèles**
```python
# backend/utils/config.py
MODEL_CONFIG = {
    'hybrid_weights': {
        'ml_traditional': 0.3,
        'nlp_huggingface': 0.4,
        'evasion_detection': 0.3
    },
    'detection_thresholds': {
        'high_threat': 0.8,
        'medium_threat': 0.6,
        'low_threat': 0.4
    },
    'performance_optimizations': {
        'use_gpu': True,
        'batch_size': 8,
        'max_workers': 4,
        'cache_results': True
    }
}
```

##  Intégration Frontend-Backend

###  Communication API

#### 1. **Upload et Analyse de Fichiers**
```javascript
// Frontend - Upload de fichier
const uploadFile = async (file) => {
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        const response = await fetch('/api/analyze/file', {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        return result;
    } catch (error) {
        console.error('Erreur upload:', error);
        throw error;
    }
};

// Utilisation
const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    const analysis = await uploadFile(file);
    
    // Affichage des résultats
    displayResults(analysis);
};
```

#### 2. **Affichage des Résultats**
```javascript
// Frontend - Affichage des résultats
const displayResults = (analysis) => {
    const {
        hybrid_score,
        final_decision,
        confidence,
        threat_type,
        evasion_techniques,
        ml_detection,
        nlp_detection,
        evasion_detection
    } = analysis;
    
    // Mise à jour de l'interface
    updateDashboard({
        score: hybrid_score,
        decision: final_decision,
        confidence: confidence,
        threatType: threat_type,
        evasionTechniques: evasion_techniques
    });
};
```

#### 3. **Monitoring Temps Réel**
```javascript
// Frontend - Monitoring temps réel
const startRealTimeMonitoring = () => {
    const interval = setInterval(async () => {
        try {
            const response = await fetch('/api/status');
            const status = await response.json();
            
            updateSystemStatus(status);
        } catch (error) {
            console.error('Erreur monitoring:', error);
        }
    }, 5000); // Rafraîchissement toutes les 5 secondes
    
    return interval;
};
```

###  Composants Frontend

#### 1. **Dashboard Principal**
```jsx
// frontend/src/components/Dashboard.tsx
const Dashboard = () => {
    const [systemStatus, setSystemStatus] = useState(null);
    const [threats, setThreats] = useState([]);
    
    useEffect(() => {
        fetchDashboardData();
        const interval = setInterval(fetchDashboardData, 5000);
        return () => clearInterval(interval);
    }, []);
    
    return (
        <div className="dashboard">
            <SystemStatusCard status={systemStatus} />
            <ThreatsList threats={threats} />
            <PerformanceMetrics />
            <RealTimeChart />
        </div>
    );
};
```

#### 2. **Scanner de Fichiers**
```jsx
// frontend/src/components/Scan.tsx
const Scan = () => {
    const [scanStatus, setScanStatus] = useState({
        is_scanning: false,
        progress: 0,
        threats_detected: 0
    });
    
    const startScan = async (scanType, targetPaths) => {
        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ scan_type: scanType, target_paths: targetPaths })
            });
            
            const result = await response.json();
            setScanStatus(result);
        } catch (error) {
            console.error('Erreur scan:', error);
        }
    };
    
    return (
        <div className="scanner">
            <ScanControls onStartScan={startScan} />
            <ScanProgress status={scanStatus} />
            <ScanResults />
        </div>
    );
};
```

##  Intégration Backend-ML

###  Chargement des Modèles

#### 1. **Initialisation du Model Loader**
```python
# backend/ml_engine/model_loader.py
class ModelLoader:
    def __init__(self):
        self.models_dir = "models/"
        self.models_cache = {}
        self.load_status = {
            'models_loaded': False,
            'last_load_time': None,
            'errors': [],
            'warnings': []
        }
    
    def load_models(self) -> Dict[str, Any]:
        """Charger tous les modèles avec gestion d'erreurs"""
        try:
            # Charger le modèle frontend unifié
            frontend_model_path = os.path.join(self.models_dir, 'frontend_unified_model.pkl')
            if os.path.exists(frontend_model_path):
                with open(frontend_model_path, 'rb') as f:
                    frontend_model = pickle.load(f)
                
                self.models_cache['frontend_unified_model'] = frontend_model
                self.load_status['models_loaded'] = True
                
                return self._create_success_response(frontend_model)
            
            # Fallback vers modèles individuels
            return self._load_individual_models()
            
        except Exception as e:
            return self._create_fallback_models()
```

#### 2. **Intégration dans FastAPI**
```python
# backend/main.py
from ml_engine.model_loader import get_model_loader
from ml_engine.hybrid_detector import HybridDetector

# Initialisation
model_loader = get_model_loader()
hybrid_detector = HybridDetector()

@app.on_event("startup")
async def startup_event():
    """Initialisation au démarrage"""
    logger.info(" Démarrage de RansomGuard AI v1.0...")
    
    # Charger les modèles
    model_load_result = model_loader.load_models()
    if model_load_result.get('success', False):
        logger.info(" Modèles chargés avec succès")
    else:
        logger.warning(" Utilisation de modèles de fallback")
    
    # Initialiser le détecteur hybride
    await hybrid_detector.initialize()
    
    logger.info(" RansomGuard AI v2.0 prêt!")
```

###  Analyse de Fichiers

#### 1. **Endpoint d'Analyse**
```python
# backend/main.py
@app.post("/api/analyze/file")
async def analyze_file(file: UploadFile = File(...)):
    """Analyser un fichier suspect"""
    try:
        # Sauvegarder le fichier temporairement
        temp_path = f"temp/{file.filename}"
        with open(temp_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)
        
        # Analyser avec le système hybride
        result = await hybrid_detector.analyze_file_hybrid(temp_path)
        
        # Nettoyer le fichier temporaire
        os.remove(temp_path)
        
        return {
            "success": True,
            "analysis": result,
            "filename": file.filename
        }
        
    except Exception as e:
        logger.error(f"Erreur analyse fichier: {e}")
        raise HTTPException(status_code=500, detail=str(e))
```

#### 2. **Analyse Hybride**
```python
# backend/ml_engine/hybrid_detector.py
class HybridDetector:
    async def analyze_file_hybrid(self, file_path: str) -> Dict[str, Any]:
        """Analyse complète d'un fichier"""
        try:
            # 1. Extraction des features
            features = await self.extract_features(file_path)
            
            # 2. Analyse ML traditionnel
            ml_results = await self.traditional_detector.analyze(features)
            
            # 3. Analyse NLP
            nlp_results = await self.huggingface_detector.analyze(features['text_content'])
            
            # 4. Analyse d'évasion
            evasion_results = await self.advanced_detector.analyze_evasion(features)
            
            # 5. Combinaison des résultats
            hybrid_score = self.combine_results(ml_results, nlp_results, evasion_results)
            
            # 6. Décision finale
            final_decision = self.make_final_decision(hybrid_score)
            
            return {
                'hybrid_score': hybrid_score,
                'final_decision': final_decision,
                'confidence': self.calculate_confidence(ml_results, nlp_results, evasion_results),
                'threat_type': self.determine_threat_type(ml_results, nlp_results),
                'evasion_techniques': evasion_results.get('detected_techniques', []),
                'ml_detection': ml_results,
                'nlp_detection': nlp_results,
                'evasion_detection': evasion_results
            }
            
        except Exception as e:
            logger.error(f"Erreur analyse hybride: {e}")
            return self._create_error_response(str(e))
```

##  Monitoring et Surveillance

###  Surveillance Temps Réel

#### 1. **Monitoring Système**
```python
# backend/ml_engine/system_monitor.py
class SystemMonitor:
    def __init__(self):
        self.monitoring_active = False
        self.metrics = {}
    
    async def start_monitoring(self):
        """Démarrer la surveillance temps réel"""
        self.monitoring_active = True
        
        while self.monitoring_active:
            try:
                # Collecter les métriques
                metrics = await self.collect_metrics()
                
                # Analyser les anomalies
                anomalies = await self.detect_anomalies(metrics)
                
                # Alerter si nécessaire
                if anomalies:
                    await self.send_alerts(anomalies)
                
                # Sauvegarder les métriques
                await self.save_metrics(metrics)
                
                await asyncio.sleep(5)  # Pause de 5 secondes
                
            except Exception as e:
                logger.error(f"Erreur monitoring: {e}")
    
    async def collect_metrics(self) -> Dict[str, Any]:
        """Collecter les métriques système"""
        return {
            'cpu_usage': psutil.cpu_percent(),
            'memory_usage': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent,
            'network_io': psutil.net_io_counters()._asdict(),
            'active_processes': len(psutil.pids()),
            'open_files': len(psutil.net_connections()),
            'system_load': os.getloadavg() if hasattr(os, 'getloadavg') else None
        }
```

#### 2. **Détection d'Anomalies**
```python
# backend/ml_engine/system_monitor.py
async def detect_anomalies(self, metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Détecter les anomalies système"""
    anomalies = []
    
    # Seuils d'alerte
    thresholds = {
        'cpu_usage': 80.0,
        'memory_usage': 85.0,
        'disk_usage': 90.0,
        'network_connections': 1000
    }
    
    # Vérifier les seuils
    for metric, value in metrics.items():
        if metric in thresholds:
            if value > thresholds[metric]:
                anomalies.append({
                    'type': 'threshold_exceeded',
                    'metric': metric,
                    'value': value,
                    'threshold': thresholds[metric],
                    'severity': 'high' if value > thresholds[metric] * 1.2 else 'medium'
                })
    
    return anomalies
```

###  Métriques de Performance

#### 1. **Collecte des Métriques**
```python
# backend/utils/metrics.py
class PerformanceMetrics:
    def __init__(self):
        self.metrics = {
            'detection_accuracy': [],
            'processing_time': [],
            'false_positives': [],
            'false_negatives': [],
            'throughput': []
        }
    
    def record_detection(self, actual: bool, predicted: bool, processing_time: float):
        """Enregistrer une détection"""
        accuracy = 1.0 if actual == predicted else 0.0
        
        self.metrics['detection_accuracy'].append(accuracy)
        self.metrics['processing_time'].append(processing_time)
        
        if actual != predicted:
            if predicted and not actual:
                self.metrics['false_positives'].append(1)
            else:
                self.metrics['false_negatives'].append(1)
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Obtenir un résumé des performances"""
        return {
            'accuracy': np.mean(self.metrics['detection_accuracy']),
            'avg_processing_time': np.mean(self.metrics['processing_time']),
            'false_positive_rate': len(self.metrics['false_positives']) / len(self.metrics['detection_accuracy']),
            'false_negative_rate': len(self.metrics['false_negatives']) / len(self.metrics['detection_accuracy']),
            'throughput': len(self.metrics['processing_time']) / max(np.sum(self.metrics['processing_time']), 1)
        }
```

##  Configuration et Déploiement

###  Déploiement Automatique

#### 1. **Script de Démarrage**
```python
# backend/start_hackathon.py
class HackathonStarter:
    def __init__(self):
        self.backend_dir = Path(__file__).parent
        self.frontend_dir = self.backend_dir.parent / "frontend"
        self.models_dir = self.backend_dir / "models"
    
    def run(self):
        """Exécuter le démarrage complet"""
        # 1. Vérifier les prérequis
        if not self.check_prerequisites():
            return False
        
        # 2. Installer les dépendances
        if not self.install_dependencies():
            return False
        
        # 3. Entraîner les modèles
        if not self.train_models():
            return False
        
        # 4. Démarrer le backend
        backend_process = self.start_backend()
        if not backend_process:
            return False
        
        # 5. Démarrer le frontend
        frontend_process = self.start_frontend()
        if not frontend_process:
            return False
        
        # 6. Afficher les informations
        self.print_startup_info()
        
        return True
```

#### 2. **Configuration Docker**
```dockerfile
# Dockerfile
FROM python:3.9-slim

WORKDIR /app

# Installer les dépendances système
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copier les fichiers
COPY requirements.txt .
COPY . .

# Installer les dépendances Python
RUN pip install -r requirements.txt

# Exposer le port
EXPOSE 8000

# Commande de démarrage
CMD ["python", "main.py"]
```

### 🔧 Configuration Avancée

#### 1. **Configuration des Modèles**
```python
# backend/utils/config.py
MODEL_CONFIG = {
    'hybrid_weights': {
        'ml_traditional': 0.3,
        'nlp_huggingface': 0.4,
        'evasion_detection': 0.3
    },
    'detection_thresholds': {
        'high_threat': 0.8,
        'medium_threat': 0.6,
        'low_threat': 0.4
    },
    'evasion_thresholds': {
        'sandbox_evasion': 0.7,
        'antivirus_evasion': 0.6,
        'behavioral_evasion': 0.5
    },
    'performance_optimizations': {
        'use_gpu': True,
        'batch_size': 8,
        'max_workers': 4,
        'cache_results': True,
        'max_cache_size': 1000
    }
}
```

#### 2. **Configuration de Sécurité**
```python
# backend/utils/security.py
SECURITY_CONFIG = {
    'file_scanning': {
        'max_file_size': 100 * 1024 * 1024,  # 100MB
        'allowed_extensions': ['.exe', '.dll', '.pdf', '.docx', '.zip'],
        'quarantine_suspicious': True,
        'scan_timeout': 300  # 5 minutes
    },
    'real_time_protection': {
        'enabled': True,
        'scan_interval': 5,  # secondes
        'monitor_processes': True,
        'monitor_files': True,
        'monitor_network': True
    },
    'alerts': {
        'email_notifications': False,
        'webhook_notifications': False,
        'log_level': 'INFO'
    }
}
```

##  Tests et Validation

###  Tests d'Intégration

#### 1. **Test du Système Complet**
```python
# test_suite/test_integration.py
class IntegrationTest:
    def test_complete_workflow(self):
        """Test du workflow complet"""
        # 1. Upload fichier
        file_path = "test_files/suspicious.exe"
        with open(file_path, "rb") as f:
            files = {"file": f}
            response = requests.post("http://localhost:8000/api/analyze/file", files=files)
        
        assert response.status_code == 200
        
        # 2. Vérifier les résultats
        result = response.json()
        assert "analysis" in result
        assert "hybrid_score" in result["analysis"]
        assert "final_decision" in result["analysis"]
        
        # 3. Vérifier les métriques
        metrics_response = requests.get("http://localhost:8000/api/models/status")
        assert metrics_response.status_code == 200
```

#### 2. **Test de Performance**
```python
# test_suite/test_performance.py
class PerformanceTest:
    def test_processing_speed(self):
        """Test de la vitesse de traitement"""
        start_time = time.time()
        
        # Traiter 10 fichiers
        for i in range(10):
            file_path = f"test_files/file_{i}.exe"
            with open(file_path, "rb") as f:
                files = {"file": f}
                response = requests.post("http://localhost:8000/api/analyze/file", files=files)
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Vérifier que le temps moyen est < 2 secondes
        avg_time = total_time / 10
        assert avg_time < 2.0, f"Temps moyen trop élevé: {avg_time}s"
```

##  Conclusion

Cette intégration complète offre :

-  **Facilité d'utilisation** : Un seul script de démarrage
-  **Robustesse** : Gestion d'erreurs et fallback
-  **Performance** : Optimisation automatique
-  **Monitoring** : Surveillance temps réel
-  **Extensibilité** : Ajout facile de nouvelles fonctionnalités


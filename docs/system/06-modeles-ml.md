# 06 — Système de modèles ML & ré-entraînement

> Comment GuardIAn entraîne, déploie, surveille et **améliore** ses modèles sans intervention.

## Vue d'ensemble

```
┌─────────────────────────────────────────────────────────┐
│ 1. Datasets                                             │
│    EMBER-2024 + MalwareBazaar fresh + agent active-     │
│    learning samples                                     │
└────────────┬────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────┐
│ 2. Entraînement (Colab GPU OU local)                    │
│    LightGBM (PE), MalConv2 (raw bytes), CodeBERT (scripts)│
└────────────┬────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────┐
│ 3. Export ONNX → models/                                │
│    Modèle signé + manifest.json (version, métriques)    │
└────────────┬────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────┐
│ 4. Déploiement                                          │
│    Shadow mode 24h → A/B agents → full rollout         │
└────────────┬────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────┐
│ 5. Monitoring + Drift Detection (ADWIN)                 │
│    Si drift → trigger 1.                                │
└─────────────────────────────────────────────────────────┘
```

> Phases A & B livrées exploitent un modèle sklearn V1 simple (`detector.joblib`). Les modèles SOTA arrivent en **Phase E** ; ce document décrit la cible.

## Modèles cibles (Phase E)

### EMBER-2024 + LightGBM — PE statique

- **Dataset** : EMBER-2024 (~10 M samples, ~2400 features par PE)
- **Modèle** : LightGBM, ~1500 trees, depth=8
- **Performance attendue** : F1 ~0.985 sur EMBER test set
- **Inférence** : <2 ms par PE en CPU
- **Pourquoi** : standard industrie (Endgame/Elastic), pas de GPU requis, explainable (SHAP)

```python
import lightgbm as lgb
import ember
X, y, _, _ = ember.read_vectorized_features("ember_2024/")
clf = lgb.LGBMClassifier(n_estimators=1500, num_leaves=128, learning_rate=0.05)
clf.fit(X, y)
clf.booster_.save_model("models/ember_lgbm.txt")
```

### MalConv2 (PyTorch) — PE raw bytes

- **Input** : 2 Mo de bytes bruts (premier MB + sections .text)
- **Architecture** : embedding 8-D → conv 1D 8x500 stride 500 → gating → softmax
- **Pourquoi** : robuste à l'obfuscation surface, capture des patterns de bytes
- **Entraînement** : Colab GPU ~24 h sur 1 M samples
- **Export** : ONNX, ~80 Mo, inférence ~30 ms CPU

### CodeBERT / UniXcoder — scripts

- **Cible** : PowerShell, JavaScript, VBA, Python
- **Modèle** : CodeBERT-base, 110 M params, fine-tuné binary classification
- **Pourquoi** : compréhension *sémantique*, résiste à `Invoke-Obfuscation`
- **Inférence** : ~80 ms CPU, ~5 ms GPU

### CANINE-c — char-level

- **Pour** : scripts obfusqués sans tokens valides (charcodes, base64 imbriqués)
- **Pourquoi** : char-level → pas de tokenizer à tromper

### Isolation Forest — anomaly detection

- **Cible** : telemetry agent (process tree, registre, réseau)
- **Pourquoi** : détecte les zero-day **sans label**

### Stacked meta-learner

```
EMBER+LGBM ─┐
MalConv2 ───┤
CodeBERT ───┼─→ XGBoost meta ─→ score final
YARA ───────┤
Static-V2 ──┘
```

XGBoost en méta-modèle apprend à pondérer les sous-modèles. Empêche l'évasion mono-modèle (un attaquant qui contourne MalConv2 ne contourne pas CodeBERT).

## Pipeline de ré-entraînement

### Active learning depuis les agents

Chaque agent push vers le backend :

```python
{
  "sha256": "...",
  "static_v2": {...},
  "ml_score": 0.52,        # zone d'incertitude
  "user_verdict": "malware" # validation analyste, optionnel
}
```

Endpoint roadmap : `POST /api/ml/feedback` (Phase F).

### Ré-entraînement programmé

Cron weekly :

1. Pull les samples de la semaine (TI feeds + agent feedback)
2. Re-vectoriser
3. Fine-tune les modèles (warm-start)
4. Évaluer sur **hold-out** : F1, FPR (False Positive Rate critique pour antivirus)
5. Si F1 ≥ baseline + 0.005 ET FPR ≤ baseline + 0.001 → promote

### Shadow mode

Nouveau modèle déployé **en parallèle** de l'ancien :

```python
score_prod = model_v1.predict(x)   # décision
score_shadow = model_v2.predict(x) # log only
```

24 h de shadow → comparaison agreement / disagreement → si <1 % disagreement critique → swap.

### Drift detection (ADWIN)

> ADWIN (ADaptive WINdowing, Bifet & Gavalda 2007) maintient une fenêtre adaptative et détecte un changement statistique de distribution.

```python
from river.drift import ADWIN
adwin = ADWIN()
for x_new, score in stream:
    adwin.update(score)
    if adwin.drift_detected:
        trigger_retrain()
```

Si la distribution des scores change (nouveau type de menace ou nouveau type de logiciel légitime) → ré-entraînement déclenché.

### Adversarial training

Pendant l'entraînement, on génère des exemples adversariaux :

- **FGSM byte-level** : ajoute des bytes aux sections `.rdata` pour fool MalConv2
- **MAB attack** : Multi-Armed Bandit qui cherche la mutation la moins coûteuse changeant le verdict
- Les adversariaux sont labellisés `malware` et ré-injectés → le modèle apprend à résister

## Model registry + signature Cosign

Roadmap Phase F :

```
models/
├── ember_lgbm/
│   ├── 2026-04-30_v3.onnx
│   ├── 2026-04-30_v3.onnx.sig    # signature Cosign
│   └── manifest.json             # {version, dataset, metrics, sha256}
├── malconv2/
│   └── ...
└── current → ember_lgbm/2026-04-30_v3.onnx
```

Le détecteur charge **uniquement** les modèles dont la signature Cosign est valide → empêche un attaquant qui aurait accès au filesystem de remplacer le modèle par une porte dérobée.

## Comment entraîner en local / Colab

Le repo fournit `RansomGuard_AI_NLP_Training.ipynb` (Colab) et `train_nlp_models_colab.py`. Pour Phase E :

1. Cloner EMBER : `git clone https://github.com/elastic/ember`
2. Télécharger le dataset 2024 (~10 GB)
3. Ouvrir le notebook Colab fourni
4. Sélectionner runtime GPU
5. Exécuter — produit `detector.joblib` ou `ember_lgbm.onnx`
6. Copier dans `backend/models/` et redémarrer le backend

Voir aussi `backend/train_models_for_hackathon.py` qui produit le modèle V1 actuel.

## Sources & lectures

- **EMBER paper** : Anderson & Roth 2018 — https://arxiv.org/abs/1804.04637
- **MalConv2 paper** : Raff et al. 2017 — https://arxiv.org/abs/1710.09435
- **CodeBERT paper** : Feng et al. 2020 — https://arxiv.org/abs/2002.08155
- **CANINE paper** : Clark et al. 2021 — https://arxiv.org/abs/2103.06874
- **ADWIN paper** : Bifet & Gavalda 2007 — https://www.cs.upc.edu/~gavalda/papers/adwin06.pdf
- **Adversarial malware FGSM byte** : Suciu et al. 2019 — https://arxiv.org/abs/1810.08280
- **Cosign (Sigstore)** : https://docs.sigstore.dev/
- **River streaming-ML** : https://riverml.xyz/

## Suite

→ [07 — Agent Windows](07-agent-windows.md)

# 03 — Pipeline de détection bout-en-bout

> **Objectif** : suivre la vie d'un fichier suspect, de l'agent jusqu'au verdict.

## Étape par étape

### 0. L'agent capture le fichier

L'agent Windows surveille les dossiers sensibles (`%TEMP%`, `Downloads`, `Desktop`…) via `ReadDirectoryChangesW`. Quand un fichier est créé/modifié et qu'il a une extension à risque (`.exe`, `.dll`, `.ps1`, `.js`, `.docm`, …) :

1. Calcule SHA-256 localement
2. Heartbeat → backend pour vérifier si le hash est déjà connu
3. Si nouveau → **POST `/api/analyze`** avec le fichier en multipart

### 1. Réception côté backend

```python
# backend/app/api/routers/analyze.py
@router.post("/analyze")
async def analyze(file: UploadFile, db: Session = Depends(get_db)):
    data = await file.read()
    detector = get_detector()                 # singleton, déjà chargé
    result = detector.analyze_bytes(file.filename, data)
    threat = persist_threat(db, result)       # si is_threat=True
    return result.to_dict()
```

### 2. Le UnifiedDetector orchestre 6 couches

Code : [`backend/app/ml/detector.py`](../../backend/app/ml/detector.py) — méthode `_score()`.

#### Couche ① : Threat Intelligence exact (SHA-256)

```python
ti_hit = _ti_lookup_hash(feats.sha256)
if ti_hit:
    return critical(family=ti_hit["family"], source=ti_hit["source"])
```

- **Précision** : ~100 % (un SHA-256 est cryptographiquement unique)
- **Couverture** : ~5 % des malwares vus en entreprise (les "connus")
- **Latence** : <5 ms (lookup PostgreSQL indexé sur `sha256`)
- **Sources** : MalwareBazaar, OTX, ThreatFox — voir [04](04-threat-intelligence.md)

#### Couche ② : Static-V2 + TI floue

```python
static_v2 = analyze_bytes(data)               # ssdeep, tlsh, imphash, PE deep
fuzzy_hit = _ti_fuzzy_lookup(static_v2)       # cherche dans intel_hashes
if fuzzy_hit:
    return critical(family=fuzzy_hit["family"], kind=fuzzy_hit["kind"])
```

Trois empreintes complémentaires :

| Empreinte | Caractéristique | Utilité |
|-----------|-----------------|---------|
| **imphash** | Hash MD5 de la table d'imports PE | Même code-base = même imphash → familles |
| **ssdeep** | Context-Triggered Piecewise Hash | Tolérant aux insertions/suppressions |
| **tlsh** | Trend Micro Locality Sensitive Hash | Distance numérique, scalable |

**Détails Phase B** : [05 — Static-V2](05-static-analysis.md)

#### Couche ③ : Heuristiques (rapide, toujours actif)

Calcul d'un score 0..1 basé sur :

- **Magic mismatch** : extension `.exe` mais magic bytes `.zip` → +0.45
- **Entropie** : block 64 KiB > 7.5 bits/byte → +0.25 (probable chiffrement/packing)
- **Patterns** : regex sur le payload :
  - `vssadmin delete shadows` → ransomware
  - `your files are encrypted` → ransom note
  - URLs `.onion`, wallet BTC → exfiltration
- **Score d'extension** : `.scr`/`.pif` → 0.85, `.ps1` → 0.60

Code : [`backend/app/ml/features.py`](../../backend/app/ml/features.py) (`SUSPICIOUS_PATTERNS`).

#### Couche ④ : YARA

```python
matches = self._yara_rules.match(data=raw)
if matches:
    yara_score = min(1.0, 0.5 + 0.15 * len(matches))
```

- Compilation à la volée au démarrage (`yara.compile`)
- Règles dans `backend/app/ml/rules/*.yar`
- Phase A ajoute auto-pull depuis YARAify (rule_name + content stockés en DB → recompilation à chaud → roadmap fin Phase A)

#### Couche ⑤ : ML statique (sklearn ensemble)

Vecteur 14 dimensions → modèle (`detector.joblib`) :

```python
X = np.array([feats.to_vector()], dtype=float)
ml_score = model.predict_proba(X)[0][1]   # probabilité "malware"
```

- Modèle V1 : RandomForest + IsolationForest stacking
- Modèle V2 (Phase E) : EMBER+LightGBM, MalConv2 ONNX, CodeBERT

#### Couche ⑥ : Réseau / comportement

🔜 Phase C (réseau JA3/DGA/beaconing) et Phase D (Sysmon process tree, Sigma).

### 3. Agrégation pondérée

```python
weights = [
    (0.40, h),                    # heuristic
    (0.30, ml_score),             # ML (si disponible)
    (0.15, yara_score),           # YARA (si match)
    (0.15, static_v2_score),      # Static-V2 (si PE)
]
confidence = sum(w * s for w, s in weights) / sum(w for w, _ in weights)
```

Boosts :

- YARA score ≥ 0.9 → confidence forcée à ≥ 0.9 (signature forte)
- TI exact / fuzzy → court-circuite tout (already returned)

### 4. Décision finale

```python
severity = "critical" if confidence >= 0.95 else \
           "high"     if confidence >= 0.75 else \
           "medium"   if confidence >= 0.50 else \
           "low"
```

Seuils dans [`backend/app/core/config.py`](../../backend/app/core/config.py) (`threshold_low/medium/high`).

### 5. Persistence et alerte

```python
threat = Threat(
    sha256=feats.sha256, severity=severity, family=threat_type,
    indicators=indicators, matched_rules=matched_rules, ...
)
db.add(threat)
# WebSocket push aux clients SOC connectés
broadcast({"event": "threat", "data": threat.to_dict()})
```

### 6. Action

| Sévérité | Action automatique | Action humaine |
|----------|-------------------|----------------|
| critical | Quarantaine immédiate, agent isolé | Notification SOC instantanée |
| high | Quarantaine, scan profond | Validation analyste |
| medium | Tag, log, watch-list | Examen sous 24 h |
| low | Log seul | Optionnel |

## Exemple concret : un sample LockBit packé

| # | Couche | Résultat |
|---|--------|----------|
| 0 | Agent calcule SHA-256 | `a3b2…f9` |
| 1 | TI exact | ❌ Miss (sample muté) |
| 2 | Static-V2 → ssdeep `96:abc…` | TI fuzzy → match LockBit (similarity 87) |
| — | **Verdict** | `critical, family=lockbit, kind=ssdeep, score=87` |
| 3-6 | Couches suivantes | Skipped (court-circuit) |

Latence totale : ~80 ms.

## Suite

→ [04 — Threat Intelligence (Phase A)](04-threat-intelligence.md)

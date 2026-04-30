# 10 — Roadmap (Phases C → F)

> Phases A et B sont **livrées**. Voici ce qui suit, dans l'ordre recommandé.

## Phase C — Réseau-V2 (~500 lignes)

**But** : enrichir la détection avec les signaux réseau modernes.

### Modules cibles

| Module | Rôle | Lib clé |
|--------|------|---------|
| **JA3 / JA4** | Fingerprint TLS client/server (User-Agent du chiffrement) | `pyshark` + `ja4-py` |
| **DGA detector** | LSTM char-level pré-entraîné (DGA Archive) | PyTorch + ONNX |
| **Beaconing detector** | FFT sur inter-arrival times — fenêtre glissante 1 h | `scipy.fft` |
| **Suricata ingest** | Parse `fast.log` et `eve.json` → DB | tail + parser custom |
| **Zeek ingest** | Parse `conn.log`, `ssl.log`, `dns.log` | parser TSV |
| **Live TI match** | Sur chaque DNS/connect → query `intel_indicators` | déjà en place côté DB |

### Nouveaux endpoints

- `POST /api/network/events` (depuis Suricata/Zeek sidecar)
- `GET /api/network/beacons?agent_id=...`
- `GET /api/network/dga?domain=...`

### Source dataset

- **DGA Archive** (Andrey Abakumov) — https://data.netlab.360.com/dga/
- **JA3 fingerprints** (Salesforce) — https://github.com/salesforce/ja3
- **JA4** spec — https://github.com/FoxIO-LLC/ja4

---

## Phase D — Comportemental / APT engine (~700 lignes)

**But** : détecter les APT par comportement (pas juste fichier).

### Modules cibles

| Module | Rôle |
|--------|------|
| **Sysmon ingest** | Parser EVTX en streaming, normalisation au format ECS |
| **ETW consumer** | Real-time, agent-side, push vers backend |
| **Process tree anomaly** | LOLBins, parent-enfant unusual (winword → cmd → powershell) |
| **Sigma engine** | Vrai moteur Sigma (pas juste un dossier) — `pySigma` |
| **Canary files** | Fichiers piégés dans des dossiers stratégiques (`Documents`, `Desktop`) — toute écriture = ransomware certain |
| **ATT&CK mapper** | Détection → technique ID, score APT global |
| **PE-sieve hook** | Memory scan agent-side optionnel |

### Sources

- **Sysmon-modular** (config baseline) : https://github.com/olafhartong/sysmon-modular
- **pySigma** : https://github.com/SigmaHQ/pySigma
- **Sigma rules repository** : https://github.com/SigmaHQ/sigma (~3000 règles)
- **PE-sieve** : https://github.com/hasherezade/pe-sieve
- **Canary tokens** : https://canarytokens.org/generate

---

## Phase E — ML-V2 ensemble (~1500 lignes + entraînement)

**But** : remplacer le modèle V1 sklearn par un ensemble SOTA.

### Modèles à intégrer

Voir [06 — modèles ML](06-modeles-ml.md) pour les détails. Synthèse :

| Modèle | Cible | Format de déploiement |
|--------|-------|----------------------|
| EMBER+LightGBM | PE statique | `.txt` (LightGBM native) ou ONNX |
| MalConv2 | PE raw bytes | ONNX, ~80 Mo |
| CodeBERT | Scripts | ONNX, ~440 Mo |
| CANINE-c | Scripts char-level | ONNX |
| GNN call-graph | Familles APT | PyTorch Geometric → ONNX |
| LSTM/TCN char-level | DGA | ONNX |
| Isolation Forest + Deep SVDD | Anomaly EDR | sklearn / PyTorch |
| Stacked XGBoost meta | Fusion | ONNX |

### Adversarial training

- FGSM byte-level (Suciu et al. 2019)
- MAB attack (Multi-Armed Bandit)

---

## Phase F — MLOps & auto-retrain (~400 lignes)

**But** : que le système s'améliore tout seul.

### Composants

| Composant | Rôle |
|-----------|------|
| **Active learning push** | Agents pushent les low-confidence + verdict analyste |
| **Weekly retrain cron** | Pipeline complet : pull → train → eval → promote |
| **Shadow mode** | Modèle V+1 en parallèle 24 h, métriques comparées |
| **Drift detection ADWIN** | Streaming `river` → trigger retrain si dérive |
| **Model registry** | `models/<model>/<date>_<version>.onnx` + `manifest.json` |
| **Cosign signing** | Signature Sigstore → vérification au chargement |
| **Canary deploy** | Push vers 5 % d'agents, monitor 24 h, rollout progressif |

### Endpoints

- `POST /api/ml/feedback` (active learning)
- `GET /api/ml/models` (registry)
- `POST /api/ml/promote` (admin only)

---

## Estimation cumulative

| Phase | Lignes Python | Modèles à télécharger | Complexité |
|-------|---------------|----------------------|------------|
| A ✅ | ~600 | 0 | ★★ |
| B ✅ | ~400 | 0 | ★★★ |
| C | ~500 | LSTM DGA (~10 Mo) | ★★★ |
| D | ~700 | 0 | ★★★★ |
| E | ~1500 | ~2 Go | ★★★★★ |
| F | ~400 | 0 | ★★★ |
| **Total** | **~4100** | **~2 Go** | — |

## Suite

→ [11 — Sources & lectures](sources.md)

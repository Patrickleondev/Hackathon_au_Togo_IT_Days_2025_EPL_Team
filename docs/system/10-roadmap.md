# 10 — Roadmap (Phases C → F)

> Phases A, B et C sont **livrées**. Voici ce qui suit, dans l'ordre recommandé.

## Phase C — Réseau-V2 — ✅ Livrée

**But** : enrichir la détection avec les signaux réseau modernes.

> Détails complets : [11-network-v2.md](11-network-v2.md). Résumé ci-dessous.

### Modules livrés

| Module | Rôle | Implémentation |
|--------|------|----------------|
| **JA3 / JA4** | Lookup MD5 contre liste built-in + DB `ja3_fingerprints` | `app/network/ja3.py` |
| **DGA detector** | 6 features lexicales (entropie, bigrammes EN, voyelles, runs, chiffres, longueur) — pas de torch en V1 | `app/network/dga.py` |
| **Beaconing detector** | Statistique de Rayleigh (RITA-style) sur 64 candidats log-spaced + golden-section refine | `app/network/beaconing.py` |
| **Suricata ingest** | Parser `eve.json` (flow / dns / http / tls / alert) | `app/network/ingest.py` |
| **Zeek ingest** | Parsers `conn.log` TSV + `dns.log` / `ssl.log` JSON | `app/network/ingest.py` |
| **Live TI match** | À l'ingest : `IntelService.lookup_ip` / `lookup_domain` | `app/network/service.py` |

### Endpoints livrés

- `POST /api/network/events` — bulk (5000 max), auth agent
- `POST /api/network/events/raw` — lignes brutes Suricata / Zeek
- `GET  /api/network/stats` — comptes par source / 24 h
- `GET  /api/network/dga?domain=…` — score à la volée
- `GET  /api/network/beacons?min_score=…` — top canaux périodiques
- `POST /api/network/beacons/recompute` — admin uniquement
- `GET  /api/network/ja3/{fingerprint}` — DB + fallback built-in

### DB (3 nouvelles tables)

- `network_events` — index sur ts, src/dst_ip, dst_port, domain, sni, ja3, ja4, risk
- `network_beacons` — résultats agrégés (period_s, score, jitter, verdict)
- `ja3_fingerprints` — fingerprints connus malveillants (Cobalt Strike, Empire, Trickbot, Emotet, Tor, Sliver à minima)

### Tests

20 tests unitaires sous [`backend/tests/test_network.py`](../../backend/tests/test_network.py) — DGA, beaconing (périodicité parfaite + Poisson + trace courte), JA3/JA4 (normalisation, lookup), parsers Suricata + Zeek. **20/20 passent**.

### Phase C+ (étendue future, non bloquant)

- Auto-import CSV SSLBL → `ja3_fingerprints` via TI scheduler
- DGA LSTM char-level (déplacé en Phase E pour mutualiser le runtime ONNX)
- Décodage JA3/JA4 côté backend sans Suricata (via `pyshark` + `ja4-py`)
- Déploiement Suricata Docker compose (interface mirror)

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

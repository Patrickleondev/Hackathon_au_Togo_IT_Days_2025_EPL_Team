# 03 — Detection algorithms

## Overview

The unified detector (`backend/app/ml/detector.py`) combines three signals:

1. **Heuristic** (rule-based, `app.ml.features`)
2. **Machine learning** (RandomForest, `models/detector.joblib`)
3. **YARA** (signature rules, `app/ml/rules/*.yar`)

Each produces an independent score in `[0, 1]`. They are merged with weighted
aggregation: when all three are available, weights are
**heuristic 0.45 / ML 0.35 / YARA 0.20**. When the ML model is missing, the
heuristic weight rises to 1.0.

## Feature vector (14 dimensions)

| # | Feature | Range | Description |
|---|---------|-------|-------------|
| 0 | `file_size_norm` | [0,1] | min(size, 50 MB) / 50 MB |
| 1 | `entropy_norm` | [0,1] | Shannon entropy / 8 |
| 2 | `magic_mismatch` | {0,1} | Magic bytes ↔ extension differ |
| 3 | `suspicious_ext_score` | [0,1] | From extension table (`.scr`=0.85, `.bat`=0.65, …) |
| 4 | `pattern_count_norm` | [0,1] | min(matches, 20) / 20 |
| 5 | `has_high_entropy_block` | {0,1} | Any 64 KB block with H > 7.5 |
| 6 | `pat_encryption_api` | {0,1} | `CryptEncrypt`, `BCryptEncrypt`, `AES_encrypt`, … |
| 7 | `pat_ransom_note` | {0,1} | "your files have been encrypted", "pay in bitcoin", … |
| 8 | `pat_shadow_copy_delete` | {0,1} | `vssadmin delete shadows` |
| 9 | `pat_powershell_obfuscated` | {0,1} | `-EncodedCommand`, `FromBase64String`, `iex(` |
| 10 | `pat_downloader` | {0,1} | `Invoke-WebRequest`, `certutil -urlcache`, `bitsadmin /transfer` |
| 11 | `pat_persistence` | {0,1} | `\Run\`, `schtasks /create`, `reg add ... \Run` |
| 12 | `pat_tor_onion` | {0,1} | `[a-z2-7]{16,56}\.onion` |
| 13 | `pat_btc_wallet` | {0,1} | Bitcoin wallet regex |

## Heuristic score

```
score = 0
score += suspicious_ext_score * 0.40
if magic_mismatch:           score += 0.45
if has_high_entropy_block:   score += 0.25
score += min(pattern_count, 10) * 0.06
if pat_ransom_note:          score += 0.40
if pat_shadow_copy_delete:   score += 0.35
if pat_encryption_api:       score += 0.20
score = min(score, 1.0)
```

## ML score

`RandomForestClassifier(n_estimators=200, max_depth=12, class_weight=balanced)` 
wrapped in a `StandardScaler`, trained by `scripts/train_detector.py`.
We use `predict_proba(x)[1]` as the malware probability.

## YARA score

If any rule matches:

```
yara_score = min(0.5 + 0.15 * matched_rules, 1.0)
```

Bundled rules (`backend/app/ml/rules/generic.yar`):

- `Ransom_Note_Generic` — at least 2 of 6 ransom-note phrases.
- `Ransom_VSSAdmin_Delete` — shadow copy deletion.
- `Suspicious_PowerShell_Obfuscation` — encoded / base64 / iex.
- `Crypto_API_Imports` — Windows CryptoAPI imports.
- `Suspicious_Onion_Or_BTC` — Tor onion + BTC wallet present.

## Severity thresholds

| Confidence | Severity |
|------------|----------|
| ≥ 0.95 | `critical` |
| ≥ 0.85 | `high` |
| ≥ 0.65 | `medium` |
| ≥ 0.40 | `low` |
| < 0.40 | not a threat |

Thresholds are exposed as env variables (`THRESHOLD_LOW`, `THRESHOLD_MEDIUM`,
`THRESHOLD_HIGH`).

## Threat type classification

| Heuristic | Type returned |
|-----------|---------------|
| `pat_ransom_note` ∨ `pat_shadow_copy_delete` | `ransomware` |
| `pat_downloader` | `downloader` |
| `magic_mismatch` ∧ `is_executable_ext` | `file_signature_mismatch` |
| `pat_powershell_obfuscated` | `obfuscated_executable` |
| else if confidence ≥ medium | `suspicious_executable` |
| else | `unknown` |

## Re-training

```bash
docker compose -f infra/docker-compose.yml exec backend \
    python -m scripts.train_detector \
        --benign /var/lib/ransomguard/samples/benign \
        --malicious /var/lib/ransomguard/samples/malicious
```

If you don't have real samples yet, the script auto-generates a synthetic
dataset and produces a working bootstrap model.

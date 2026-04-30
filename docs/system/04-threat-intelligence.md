# 04 — Threat Intelligence auto-update (Phase A)

> **Phase A** est la fondation. Sans TI fraîche, les autres couches sont aveugles aux nouveautés.

## Pourquoi c'est critique

Un nouveau malware met **en moyenne 72 h** à apparaître dans VirusTotal. Pendant ces 3 jours, les antivirus signature-based sont aveugles. Les feeds spécialisés (abuse.ch, ThreatFox) repèrent les samples dans les **2-6 h** suivant leur première observation.

GuardIAn rafraîchit **7 sources** toutes les **6 heures**, ce qui ramène le décalage à **<6 h** dans le pire cas.

## Les 7 feeds intégrés

| Feed | Source | Type de données | API gratuite ? |
|------|--------|-----------------|----------------|
| **MalwareBazaar** | abuse.ch | Hashes (sha256, sha1, md5, imphash, ssdeep, tlsh) + family + tags | ✅ Auth-Key |
| **URLhaus** | abuse.ch | URLs malveillantes + host + threat_type | ✅ Auth-Key |
| **ThreatFox** | abuse.ch | IOCs (IP, domain, URL, hash) + family + ATT&CK | ✅ Auth-Key |
| **Feodo Tracker** | abuse.ch | IPs C2 botnets bancaires (Emotet, Dridex, Trickbot) | ✅ Public |
| **YARAify** | abuse.ch | Règles YARA communautaires | ✅ Auth-Key |
| **AbuseIPDB** | abuseipdb.com | IPs malveillantes (confidence ≥ 90) | ✅ Free tier |
| **AlienVault OTX** | otx.alienvault.com | Pulses (campagnes APT) avec IOCs typés | ✅ Free |

### Obtenir les clés

1. **abuse.ch (5 feeds)** : créer un compte sur https://auth.abuse.ch/ → onglet "API" → générer une `Auth-Key`. Une seule clé, valable pour Bazaar/URLhaus/ThreatFox/YARAify.
2. **AbuseIPDB** : https://www.abuseipdb.com/account/api → 1 000 req/j gratuites.
3. **OTX** : https://otx.alienvault.com/api → illimité pour pulses subscribed.

Configurer dans `infra/.env` :

```ini
ABUSE_CH_AUTH_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
ABUSEIPDB_API_KEY=yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
OTX_API_KEY=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz
```

## Architecture du sous-système

```
┌─────────────────────────────────────────────────────────────┐
│                    APScheduler (background)                 │
│   Trigger: every 6h, coalesce=True, max_instances=1        │
└──────────────────────────┬──────────────────────────────────┘
                           │ run_all_feeds_once()
                           ▼
        ┌──────────────────────────────────────┐
        │  for each Feed:                      │
        │    - feed.run(db)                    │
        │      - HttpClient (httpx + retry)    │
        │      - parse JSON                    │
        │      - upsert_hashes(...)            │
        │      - upsert_indicators(...)        │
        │      - upsert_yara_rule(...)         │
        │    - log to intel_feed_runs          │
        └──────────────────────────────────────┘
                           │
                           ▼
        ┌──────────────────────────────────────┐
        │  Tables PostgreSQL                   │
        │   - intel_hashes        (sha256 PK)  │
        │   - intel_indicators    (type+value) │
        │   - intel_yara_rules    (rule_name)  │
        │   - intel_feed_runs     (audit)      │
        └──────────────────────────────────────┘
                           ▲
                           │ lookup_hash() / lookup_imphash() / lookup_fuzzy()
                           │
                  ┌────────┴────────┐
                  │  Detector       │
                  │  (UnifiedDetector)│
                  └─────────────────┘
```

## Modèles ORM

Code : [`backend/app/db/models.py`](../../backend/app/db/models.py).

### `IntelHash`

```python
sha256: str           # PK indexé, lookup O(log n)
sha1, md5, imphash    # indexés, lookup fuzzy
ssdeep, tlsh          # non indexés, scan séquentiel
family, signature, tags  # métadonnées
source                # malware_bazaar, otx, threatfox, …
confidence            # 0..1
first_seen_at, last_seen_at  # déduplication & TTL
extra: JSONB          # blob brut du feed pour forensics
```

### `IntelIndicator`

```python
indicator_type   # "ip" | "domain" | "url" | "cidr"
value            # 1.2.3.4, evil.com, https://…
family, threat_type, attack_techniques  # contexte
source, confidence
tags: JSONB
```

### `IntelYaraRule`

Stocke les règles YARA fetched depuis YARAify. La recompilation à chaud (auto-merge dans le ruleset du détecteur) est **roadmap fin Phase A**.

### `IntelFeedRun`

Audit log : 1 ligne par exécution de feed → métriques Grafana possibles.

## API

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /api/intel/stats` | user | Compteurs + dernier run par feed |
| `GET /api/intel/lookup/hash/{sha256}` | user | Lookup exact |
| `GET /api/intel/lookup/indicator?value=...` | user | Lookup IP/domain/URL |
| `POST /api/intel/refresh?only=feed1,feed2` | **admin** | Trigger manuel (background) |

Test rapide :

```bash
curl http://localhost:8000/api/intel/stats -H "Authorization: Bearer $TOKEN"
```

## Tolérance aux pannes

- **Retry** : `tenacity` retry 3× sur 429/500/502/503/504, backoff exponentiel
- **Isolation** : chaque feed tourne dans sa propre session SQLAlchemy. Un feed qui plante n'arrête pas les autres.
- **Audit** : chaque run est journalisé (`status="error"` + `error="…"`) → diagnostic facile
- **Détecteur** : si la DB TI est down, `_ti_lookup_hash` swallow l'exception → couches suivantes prennent le relais

## Maintenance

- **Rétention** : `INTEL_RETENTION_DAYS=90` par défaut → indicateurs `last_seen_at` plus anciens supprimés à chaque cycle
- **Cap par feed** : `INTEL_MAX_ROWS_PER_FEED=250000` pour éviter les explosions

## Sources & lectures

- abuse.ch API docs : https://bazaar.abuse.ch/api/, https://urlhaus-api.abuse.ch/
- AbuseIPDB Blacklist API : https://docs.abuseipdb.com/#blacklist-endpoint
- OTX API : https://otx.alienvault.com/api
- Article fondateur sur la valeur des feeds TI : *"Threat Intelligence: Collecting, Analysing, Evaluating"* (CERT-UK, 2015)
- *MITRE ATT&CK Cyber Threat Intelligence* — https://attack.mitre.org/resources/working-with-attack/

## Suite

→ [05 — Analyse statique avancée (Phase B)](05-static-analysis.md)

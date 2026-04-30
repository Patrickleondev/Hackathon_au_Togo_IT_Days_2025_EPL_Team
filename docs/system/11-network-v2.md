# 11 — Réseau-V2 (Phase C)

> Détecter ce qui ne se voit pas dans le fichier : DGA, beaconing C2, fingerprints TLS d'outils offensifs, alertes Suricata/Zeek.

## Pourquoi le réseau ?

Un attaquant moderne **n'a presque pas besoin de fichier sur disque** :

- Cobalt Strike fait du *fileless* (DLL injectée en mémoire) → la couche statique ne voit rien.
- Un loader télécharge sa charge utile depuis un domaine *DGA* → l'AV de signature ne peut rien matcher.
- Le trafic de C2 voyage par TLS chiffré, mais le **handshake** (avant chiffrement) trahit le client.
- Beaconing toutes les 30 s pendant des heures → invisible un par un, écrasant en agrégat.

Phase C ajoute trois détecteurs **complémentaires** + un pipeline d'ingestion.

## Vue d'ensemble

```
┌──────────┐   eve.json    ┌────────────────────┐
│ Suricata │──────────────▶│                    │
└──────────┘               │  POST /network/    │      ┌──────────────┐
┌──────────┐   conn.log    │      events        │ ───▶ │ NetworkEvent │
│   Zeek   │──────────────▶│      events/raw    │      │   (DB)       │
└──────────┘               │                    │      └──────┬───────┘
┌──────────┐   batch       │  → DGA score       │             │
│  Agent   │──────────────▶│  → JA3 lookup      │             ▼
└──────────┘               │  → TI match (IPs)  │      ┌──────────────┐
                           │  → Suricata sev    │      │ Beaconing    │
                           └────────────────────┘      │ analyser     │
                                                       │ (FFT)        │
                                                       └──────┬───────┘
                                                              ▼
                                                       ┌──────────────┐
                                                       │NetworkBeacon │
                                                       └──────────────┘
```

## DGA — détecteur lexical

> Code : [`backend/app/network/dga.py`](../../backend/app/network/dga.py)

Pas de modèle ML pour la V1 — six features lexicales suffisent à atteindre une bonne F1 sur Alexa-vs-Netlab :

| Axe | Pourquoi |
|-----|----------|
| Entropie de Shannon | Les labels DGA tendent vers 4.0 bits/char ; l'anglais ~3.0 |
| Surprise de bigrammes | `xqz`, `kvb`, `mfp` n'existent pas en anglais |
| Ratio de voyelles | DGA = soit ~0 (consonnes pures), soit ~1 (voyelles padding) |
| Run de consonnes | ≥ 5 consonnes consécutives = drapeau rouge |
| Ratio de chiffres | Beaucoup de DGAs mêlent des chiffres |
| Longueur | Combinée avec entropie, longueurs > 14 sans chiffres = suspect |

Score combiné `0..1` ; verdict `benign / uncertain / suspicious / dga_likely`.

**Performance mesurée** :
- `google.com` → 0.265 (benign)
- `wikipedia.org` → 0.326 (benign)
- `qkjvbprwxchgflyz.com` → 0.771 (dga_likely)
- `kxqzvbnmphdjwlfr.biz` → 0.792 (dga_likely)

P99 < 1 ms — peut tourner sur **chaque** requête DNS.

> 🔭 Phase E remplacera ce détecteur par un LSTM char-level entraîné sur **DGA Archive** (Netlab 360, ~50 familles).

## Beaconing — détecteur FFT

> Code : [`backend/app/network/beaconing.py`](../../backend/app/network/beaconing.py)

Approche : statistique de Rayleigh sur les timestamps d'un canal `(src_ip, dst_ip, dst_port)`. C'est ce qu'utilise [RITA](https://github.com/activecm/rita) — devenu *tradecraft* SOC.

Pour chaque période candidate `T` espacée logarithmiquement entre 5 s et `duration/2` :

$$R(T) = \frac{1}{N} \left| \sum_{k=1}^{N} e^{2\pi i \cdot t_k / T} \right|$$

- `R = 1` → comb de Dirac parfait (beaconing pur).
- `R ≈ 1/√N` → bruit Poisson.

Astuce : un comb parfait crée des pics à **toutes** les divisions de T (T/2, T/3, …). On évite l'erreur classique en testant les multiples du candidat trouvé pour récupérer la fondamentale.

**Sortie** : `BeaconResult(period_s, score, jitter, verdict)`

| Verdict | Score |
|---------|-------|
| `unknown` | < 6 événements / < 60 s |
| `benign` | < 0.65 |
| `suspicious` | 0.65 — 0.85 |
| `beacon_likely` | ≥ 0.85 |

## JA3 / JA4 — fingerprints TLS

> Code : [`backend/app/network/ja3.py`](../../backend/app/network/ja3.py)

JA3 (Salesforce, 2017) hashe les champs du Client-Hello TLS en MD5. Même client = même JA3, peu importe l'IP, le SNI, le certificat. JA4 (FoxIO, 2023) corrige les collisions de JA3 et étend au handshake complet.

GuardIAn ne décode **pas** les handshakes lui-même — Suricata/Zeek le font et envoient le fingerprint pré-calculé. On compare contre :

1. Une **liste built-in** (~6 entrées) — Cobalt Strike default, Empire, Trickbot, Emotet, Tor… Seedée en DB au démarrage du backend.
2. La table `ja3_fingerprints` enrichie depuis [SSLBL d'abuse.ch](https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv) (Phase C+ : auto-import).

## Ingestion Suricata / Zeek

> Code : [`backend/app/network/ingest.py`](../../backend/app/network/ingest.py)

Le backend **n'écoute pas le réseau brut**. Suricata et/ou Zeek sont des sidecars qui :

1. Captent le trafic SPAN/mirror.
2. Émettent leurs logs (`eve.json`, `conn.log`, `dns.log`, `ssl.log`).
3. Un client local (oneliner Python ou collecteur Vector/Filebeat) tail les logs et POST vers `/api/network/events/raw` avec la liste des lignes.

Les parsers tolèrent :

- Champs absents (Suricata `flow` vs `dns` vs `tls` ont des shapes différents)
- TSV Zeek avec colonnes additionnelles à droite
- Timestamps ISO-8601 ou epoch float
- JSON cassé → ignoré, jamais d'exception qui remonte

## API

| Route | Auth | Rôle |
|-------|------|------|
| `POST /api/network/events` | agent JWT | Ingestion bulk (5000 max) |
| `POST /api/network/events/raw` | agent JWT | Lignes brutes Suricata / Zeek |
| `GET  /api/network/stats` | user | Comptes par source, dernières 24 h |
| `GET  /api/network/dga?domain=…` | user | Score à la volée, sans DB |
| `GET  /api/network/beacons?min_score=0.65` | user | Liste des canaux périodiques |
| `POST /api/network/beacons/recompute` | admin | Force le recalcul |
| `GET  /api/network/ja3/{fingerprint}` | user | Lookup DB + built-in |

## Modèle de risque par événement

À l'ingestion, chaque `NetworkEvent` reçoit un `risk ∈ [0, 1]` et une liste `risk_factors` lisible :

| Facteur | Score injecté | Tag |
|---------|---------------|-----|
| DGA score ≥ 0.55 | = score DGA | `dga:<verdict>:<score>` |
| JA3 known-bad | 0.85 | `ja3:<family>:<source>` |
| TI hit sur `dst_ip` | 0.90 | `ti_ip:<families>` |
| TI hit sur `domain` / `sni` | 0.90 | `ti_domain:<families>` |
| Suricata alert (severity 1) | 1.00 | `suricata:<signature>` |

Dégradation gracieuse : toute exception sur un facteur **ne casse pas** l'ingestion.

## Performance & passage à l'échelle

| Métrique | Valeur (machine dev) |
|----------|----------------------|
| Ingest 1000 événements pré-parsés | ~ 1.5 s |
| `dga_score` p99 | < 1 ms |
| Beaconing recompute (1 h, 50k events) | ~ 5 s |
| RAM additionnelle | < 50 Mo |

> Pour > 1 M events/jour, partitionner `network_events` par jour ou pousser vers ClickHouse — Phase F.

## Ce qui reste pour Phase C+

- Auto-import des CSV SSLBL d'abuse.ch dans `ja3_fingerprints` (TI scheduler)
- Détecteur DGA LSTM (Phase E) — utilisé en *parallèle* des heuristiques pour vote
- Décodage JA3/JA4 côté backend (sans Suricata) via `pyshark` + `ja4-py`
- Suricata management : déploiement Docker compose avec interface mirror

## Sources & lectures

- **JA3** — https://github.com/salesforce/ja3
- **JA4** — https://github.com/FoxIO-LLC/ja4
- **abuse.ch SSLBL** — https://sslbl.abuse.ch/blacklist/
- **RITA** — https://github.com/activecm/rita
- **Antonakakis et al., USENIX Sec'12** — *From Throw-Away Traffic to Bots: Detecting the Rise of DGA-Based Malware*
- **Yu et al., ICDM 2017** — *Inline DGA Detection with Deep Networks*
- **Netlab 360 DGA archive** — https://data.netlab.360.com/dga/
- **Suricata eve.json** — https://docs.suricata.io/en/latest/output/eve/eve-json-format.html
- **Zeek log formats** — https://docs.zeek.org/en/master/logs/index.html
- **MITRE ATT&CK T1071** (Application Layer Protocol), **T1568** (Dynamic Resolution / DGA), **T1029** (Scheduled Transfer)

## Suite

→ [00 — index documentation](00-README.md)

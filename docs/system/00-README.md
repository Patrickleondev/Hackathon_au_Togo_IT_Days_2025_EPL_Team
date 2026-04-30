# 📚 Documentation système GuardIAn — Guide complet bout-en-bout

> **Pour qui ?** Développeurs, étudiants, analystes SOC, jurés du Hackathon Togo IT Days 2025
> **Niveau** : du débutant total à l'ingénieur sécurité
> **Approche** : on commence par "c'est quoi", on finit par "comment je l'étends"

---

## 🗺️ Plan de lecture recommandé

| # | Fichier | Pour qui ? | Temps |
|---|---------|------------|-------|
| 01 | [Introduction](01-introduction.md) | Tout le monde | 5 min |
| 02 | [Architecture globale](02-architecture-globale.md) | Tout le monde | 15 min |
| 03 | [Pipeline de détection bout-en-bout](03-detection-pipeline.md) | Devs / SOC | 20 min |
| 04 | [Threat Intelligence (Phase A)](04-threat-intelligence.md) | Devs / SOC | 15 min |
| 05 | [Analyse statique avancée (Phase B)](05-static-analysis.md) | Devs / RE | 20 min |
| 06 | [Système de modèles ML & ré-entraînement](06-modeles-ml.md) | Data scientists | 30 min |
| 07 | [Agent Windows (collecte télémétrie)](07-agent-windows.md) | Devs Windows | 15 min |
| 08 | [Installation pas à pas](08-installation-pas-a-pas.md) | Débutants | 20 min |
| 09 | [FAQ & Glossaire](09-faq-glossaire.md) | Tout le monde | référence |
| 10 | [Roadmap (Phases C → F)](10-roadmap.md) | Architectes | 15 min |
| 11 | [Réseau-V2 (Phase C)](11-network-v2.md) | Devs / SOC | 20 min |
| -- | [Sources & lectures](sources.md) | Approfondissement | référence |

---

## 🎯 En 30 secondes — c'est quoi GuardIAn ?

GuardIAn est un **antivirus d'entreprise nouvelle génération** :

- **Détecte** les malwares connus *et* les variantes inconnues (zero-day)
- **Apprend** en continu via 7 flux de Threat Intelligence rafraîchis toutes les 6 h
- **Analyse** chaque fichier sur 4 axes : empreintes floues, structure PE, IA, règles YARA
- **Tient debout face aux APT** : court-circuit sur hash connu, détection de packers, mapping MITRE ATT&CK
- **S'auto-améliore** : ré-entraînement hebdomadaire à partir des décisions agents

```
┌──────────────────────────────────────────────────────────────┐
│  Agent Windows                                                │
│   └─→ télémétrie + fichier suspect                            │
│        ↓                                                       │
│   API Backend (FastAPI)                                        │
│    └─→ Pipeline détection :                                    │
│         ① TI exact (sha256)        ← MalwareBazaar, OTX, …   │
│         ② Static-V2 + TI fuzzy     ← imphash, ssdeep, tlsh   │
│         ③ Heuristiques + YARA      ← règles communautaires    │
│         ④ ML ensemble              ← LightGBM, MalConv2…     │
│                                                                │
│   Si menace → quarantaine + alerte SOC + retrain dataset      │
└──────────────────────────────────────────────────────────────┘
```

---

## 🚦 État actuel des phases

| Phase | Description | Statut |
|-------|-------------|--------|
| **A** | Threat Intelligence auto-update (7 feeds, 6 h) | ✅ Livrée |
| **B** | Static-V2 (multi-hash + PE deep + packers) | ✅ Livrée |
| **C** | Réseau-V2 (JA3/JA4, DGA, beaconing, Suricata) | ✅ Livrée |
| **D** | Comportemental APT (Sysmon, ATT&CK, canary, Sigma) | 🔜 Roadmap |
| **E** | ML-V2 (EMBER, MalConv2, CodeBERT, ensembles) | 🔜 Roadmap |
| **F** | MLOps (active learning, drift, registry signé) | 🔜 Roadmap |

---

## 🔗 Liens rapides

- Code source : [backend/app/](../../backend/app/)
- Modèles entraînés : [backend/models/](../../backend/models/)
- Règles YARA : [backend/app/ml/rules/](../../backend/app/ml/rules/)
- Tests : [backend/tests/](../../backend/tests/)
- Docs techniques (déjà existantes) : [../02-ARCHITECTURE.md](../02-ARCHITECTURE.md), [../03-ALGORITHMS.md](../03-ALGORITHMS.md)

> 💡 Cette documentation `docs/system/` est **complémentaire** des docs `01-VISION` à `09-CONTRIBUTING` du dossier parent. Celles-ci sont concises et techniques ; celle-ci est pédagogique et exhaustive.

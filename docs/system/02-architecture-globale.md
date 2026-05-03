# 02 — Architecture globale

## Vue d'ensemble

GuardIAn suit une architecture **agent / serveur / data plane**, classique des EDR modernes :

```text
┌────────────────────────┐         ┌─────────────────────────────────┐
│  Agents Windows        │         │  Backend (FastAPI)               │
│   - Tray app           │ HTTPS   │   ┌──────────────────────────┐  │
│   - Real-time scanner  ├────────►│   │ /api/agents (heartbeat)  │  │
│   - Telemetry          │         │   │ /api/analyze/file        │  │
│   - File submission    │         │   │ /api/scans               │  │
└────────────────────────┘         │   │ /api/threats             │  │
                                   │   │ /api/intel  (Phase A)    │  │
┌────────────────────────┐         │   │ /api/eradication         │  │
│  Frontend SOC (React)  │  HTTPS  │   └──────────────────────────┘  │
│   - Dashboard          ├────────►│              ↓                  │
│   - Alerts             │         │   ┌──────────────────────────┐  │
│   - Threat search      │         │   │ Detector (UnifiedDetector)│ │
└────────────────────────┘         │   │  ① TI exact              │  │
                                   │   │  ② Static-V2 + TI fuzzy │  │
                                   │   │  ③ Heuristics + YARA    │  │
                                   │   │  ④ ML ensemble (Phase E)│  │
                                   │   └──────────────────────────┘  │
                                   └─────────────────────────────────┘
                                              ↓        ↓
                              ┌───────────────┘        └────────────┐
                              ▼                                     ▼
                ┌──────────────────────┐              ┌────────────────────┐
                │  PostgreSQL          │              │  Redis + RQ        │
                │   - users, agents    │              │   - async tasks    │
                │   - threats, scans   │              │   - rate limiting  │
                │   - intel_hashes     │              │   - background     │
                │   - intel_indicators │              │     scans          │
                │   - intel_yara_rules │              └────────────────────┘
                │   - intel_feed_runs  │
                └──────────────────────┘
                              ▲
                              │ APScheduler (toutes les 6 h)
                              │
                ┌─────────────┴────────────────┐
                │  Threat Intelligence Feeds   │
                │   - abuse.ch (5 feeds)       │
                │   - AbuseIPDB                │
                │   - AlienVault OTX           │
                └──────────────────────────────┘
```

## Composants principaux

### 1. Backend FastAPI (`backend/app/`)

| Module | Rôle |
| --- | --- |
| `app/main.py` | Bootstrap : routers, middleware, lifespan (DB init + scheduler) |
| `app/api/routers/` | Endpoints REST (auth, agents, threats, scans, analyze, intel) |
| `app/core/` | Config (Pydantic Settings), logging structuré, sécurité JWT |
| `app/db/` | SQLAlchemy 2.0 (modèles, session, migrations Alembic) |
| `app/ml/detector.py` | **UnifiedDetector** — orchestre toutes les couches |
| `app/ml/features.py` | Extraction de features statiques rapides |
| `app/ml/static_v2.py` | **Phase B** — multi-hash, PE deep, packers |
| `app/intel/` | **Phase A** — feeds TI + scheduler + service |
| `app/services/` | Métier : bootstrap, quarantine, scan orchestration |

### 2. Agent Windows (`agent_windows/`)

- Tray-app .NET / Python (PySide6) — voir [07-agent-windows.md](07-agent-windows.md)
- Heartbeat toutes les N secondes
- Watcher temps réel sur dossiers sensibles
- Soumet hashes + métadonnées d'abord, fichier complet seulement si demandé

### 3. Frontend SOC (`frontend/`)

- React + TypeScript + Vite
- Dashboard menaces, recherche, audit
- Connecté au backend via JWT

### 4. Stockage

| Système | Données |
| --- | --- |
| PostgreSQL | Comptes, agents, menaces, scans, **TI** (hashes, indicateurs, règles YARA, audit feeds) |
| Redis | Cache, rate-limit, file de tâches RQ |
| Filesystem | Quarantaine chiffrée, modèles ML, règles YARA compilées |

## Flux d'une menace, de la détection à l'éradication

```text
[Agent détecte fichier suspect]
        │
        ▼
[POST /api/analyze/file + multipart file]
        │
        ▼
[UnifiedDetector.analyze_bytes()]
        │ ① TI exact ──── hit ──┐
        │ ② Static-V2 + fuzzy ──┤
        │ ③ Heuristic + YARA ───┤── score ≥ threshold
        │ ④ ML (Phase E) ───────┤
        ▼                       ▼
[INSERT threats]          [Quarantine workflow]
        │                       │
        ▼                       ▼
[WebSocket → SOC]      [POST /api/eradication]
        │                       │
        ▼                       ▼
[Alert dashboard]      [Agent supprime + nettoie]
```

## Choix techniques justifiés

| Choix | Pourquoi |
| --- | --- |
| **FastAPI** | Async, validation Pydantic native, OpenAPI auto, perf élevée |
| **SQLAlchemy 2.0** | ORM mature, migrations Alembic, support typed `Mapped[]` |
| **Pydantic Settings** | Config 12-factor, validation au boot, fail-fast |
| **APScheduler** | Plus simple que Celery beat pour cron interne, pas de broker dédié |
| **httpx + tenacity** | Async + retry exponentiel pour les feeds TI |
| **scikit-learn** (V1) | Léger, déterministe, suffisant pour MVP |
| **LightGBM + ONNX** (V2 — Phase E) | Standard industrie EMBER, ONNX = portabilité |
| **PostgreSQL** | JSONB pour `tags` et `extra`, indexation forte |
| **Docker Compose** | Reproductibilité, déploiement 1-commande |

## Diagramme C4 (niveau Container)

Voir aussi [02-ARCHITECTURE.md](../02-ARCHITECTURE.md) du dossier parent (diagrammes Mermaid détaillés).

## Suite

→ [03 — Pipeline de détection bout-en-bout](03-detection-pipeline.md)

# 08 — Installation pas à pas (débutant friendly)

> **Public** : tu n'as jamais lancé un projet Python/Docker. On y va doucement.

## Pré-requis

| Outil | Version | Pourquoi | Comment installer |
|-------|---------|----------|-------------------|
| **Docker Desktop** | ≥ 24 | Lance backend + DB en 1 commande | https://www.docker.com/products/docker-desktop |
| **Git** | ≥ 2.40 | Cloner le repo | https://git-scm.com/download |
| **Python** | 3.12 | Pour les scripts annexes | https://www.python.org/downloads/ |
| **Node.js** | 20 LTS | Frontend SOC | https://nodejs.org/ |
| **Code editor** | — | VS Code recommandé | https://code.visualstudio.com/ |

> Sur Windows, lance Docker Desktop **avant** la première installation.

## Étape 1 — cloner le repo

```bash
git clone https://github.com/Patrickleondev/Hackathon_au_Togo_IT_Days_2025_EPL_Team.git
cd Hackathon_au_Togo_IT_Days_2025_EPL_Team
```

## Étape 2 — configurer les variables d'environnement

```bash
# copier le template
cp infra/.env.example infra/.env

# éditer (Notepad / VS Code)
code infra/.env
```

Variables **obligatoires** à remplir :

```ini
# Sécurité — GÉNÈRE de vrais secrets, ne laisse JAMAIS les valeurs ci-dessous en prod.
# PowerShell pour générer :  python -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY=<colle ici 64 caractères hex>
BOOTSTRAP_ADMIN_PASSWORD=<un mot de passe fort, 24+ caractères>
BOOTSTRAP_ADMIN_EMAIL=admin@exemple.com

# Threat Intelligence (Phase A) — voir docs/system/04-threat-intelligence.md
ABUSE_CH_AUTH_KEY=<clé abuse.ch>
ABUSEIPDB_API_KEY=<clé abuseipdb>
OTX_API_KEY=<clé OTX>
```

> 🛑 Si tu laisses `SECRET_KEY` ou `BOOTSTRAP_ADMIN_PASSWORD` vides, le backend **refuse** de démarrer (fail-fast). C'est une protection contre les leaks de credentials par défaut.

## Étape 3 — lancer la stack Docker

```bash
cd infra
docker compose up -d
```

Cela démarre :

- `db` — PostgreSQL 16 (port 5432, **interne** Docker)
- `redis` — Redis 7 (port 6379, interne)
- `backend` — FastAPI (port **8000** exposé)
- `worker` — RQ worker (background)
- `frontend` — React/Vite (port **5173**)

Vérifier :

```bash
docker compose ps
# Tous les services doivent être "healthy"

curl http://localhost:8000/api/health
# {"status":"ok"}
```

## Étape 4 — premier login

Ouvre http://localhost:5173 → page de login :

- Email : `BOOTSTRAP_ADMIN_EMAIL` que tu as mis
- Mot de passe : `BOOTSTRAP_ADMIN_PASSWORD`

Tu arrives sur le dashboard SOC. Si vide, c'est normal — aucun agent ni menace.

## Étape 5 — déclencher un premier rafraîchissement TI

```bash
# obtenir un token admin
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin@exemple.com&password=<ton_mot_de_passe>" \
  | python -c "import sys, json; print(json.load(sys.stdin)['access_token'])")

# trigger refresh manuel
curl -X POST http://localhost:8000/api/intel/refresh \
  -H "Authorization: Bearer $TOKEN"

# ~30-60 secondes plus tard, voir les stats
curl http://localhost:8000/api/intel/stats -H "Authorization: Bearer $TOKEN"
```

Tu devrais voir des compteurs > 0 dans `totals.hashes` et `totals.indicators`.

## Étape 6 — tester la détection

```bash
# crée un fichier "EICAR" (test antivirus standard, inoffensif)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.com

curl -X POST http://localhost:8000/api/analyze \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@eicar.com"
```

Réponse attendue :

```json
{
  "is_threat": true,
  "severity": "critical",
  "threat_type": "ransomware|...",
  "confidence": 0.92,
  "matched_rules": [...],
  "indicators": {...}
}
```

## Étape 7 — installer un agent Windows (optionnel)

Voir [07 — Agent Windows](07-agent-windows.md) (en cours).

## Dépannage rapide

| Problème | Solution |
|----------|----------|
| `RuntimeError: SECRET_KEY must be set` | Remplir `SECRET_KEY` dans `infra/.env` |
| `connection refused 5432` | DB pas encore démarrée → `docker compose logs db` |
| `401 Unauthorized` sur `/api/intel/stats` | Token expiré → re-login |
| `403 Admin role required` sur `/api/intel/refresh` | Tu utilises un user non-admin |
| Frontend `ECONNREFUSED localhost:8000` | Backend down → `docker compose restart backend` |
| Logs montrent `ssdeep.failed` | Lib ssdeep manquante — Phase B fonctionne quand même en mode dégradé |

## Démarrage en local (sans Docker, dev)

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux/Mac

pip install -e ".[dev,ssdeep]"
$env:DATABASE_URL = "sqlite:///./local.db"
$env:SECRET_KEY = (python -c "import secrets; print(secrets.token_hex(32))")
$env:BOOTSTRAP_ADMIN_PASSWORD = "DevPassword!12345"
$env:BOOTSTRAP_ADMIN_EMAIL = "admin@local.dev"

uvicorn app.main:app --reload --port 8000
```

## Suite

→ [09 — FAQ & Glossaire](09-faq-glossaire.md)

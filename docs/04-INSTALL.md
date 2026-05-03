# 04 — Installation locale et environnement de développement

Ce guide explique comment lancer GuardIAn sur une machine locale pour une démo,
du développement ou des tests d'intégration. Pour un serveur public ou un VPS,
voir [08-DEPLOYMENT.md](08-DEPLOYMENT.md).

## 1. Choisir le mode d'installation

| Cas | Recommandation | Commande principale |
| --- | --- | --- |
| Démo rapide, hackathon, tests complets | Docker Compose dev | `docker compose -f infra/docker-compose.yml up --build` |
| Développement frontend seulement | Backend Docker + frontend local | `npm run dev` dans `frontend/` |
| Développement backend seulement | Services Docker + backend local | `uvicorn app.main:app --reload` |
| Déploiement VPS / production | Compose prod + Nginx | voir [08-DEPLOYMENT.md](08-DEPLOYMENT.md) |

Le mode Docker Compose dev est le plus sûr : il lance PostgreSQL, Redis,
backend, worker et frontend avec les mêmes contrats API que la production.

## 2. Prérequis système

### 2.1 Machine locale

| Ressource | Minimum | Recommandé |
| --- | ---: | ---: |
| CPU | 2 vCPU | 4 vCPU |
| RAM | 4 GB | 8 GB |
| Disque libre | 20 GB | 40 GB SSD |
| Réseau | accès Internet | accès Internet stable |

### 2.2 Logiciels obligatoires

| Outil | Version | Notes |
| --- | --- | --- |
| Git | 2.30+ | clonage et mises à jour |
| Docker Engine / Docker Desktop | 24+ | conteneurs backend, DB, Redis, frontend |
| Docker Compose plugin | v2.20+ | commande `docker compose` |

Sur Windows, activez WSL2 et lancez Docker Desktop avant les commandes Docker.

### 2.3 Logiciels utiles pour le développement hors Docker

| Outil | Version | Utilisation |
| --- | --- | --- |
| Node.js | 20 LTS | frontend React/Vite |
| npm | livré avec Node | `npm ci`, `npm run build` |
| Python | 3.11 ou 3.12 | backend et agent |
| OpenSSL | 1.1.1+ ou 3.x | génération des secrets |

## 3. Cloner le dépôt

```bash
git clone https://github.com/Patrickleondev/Hackathon_au_Togo_IT_Days_2025_EPL_Team.git
cd Hackathon_au_Togo_IT_Days_2025_EPL_Team
```

Vérifiez que vous êtes dans le dossier qui contient `backend/`, `frontend/`,
`agent/`, `infra/` et `docs/`.

## 4. Préparer `infra/.env`

```bash
cp infra/.env.example infra/.env
```

Sous Windows PowerShell :

```powershell
Copy-Item infra\.env.example infra\.env
```

Ouvrez ensuite `infra/.env` et remplacez au minimum :

```ini
SECRET_KEY=...
POSTGRES_PASSWORD=...
POSTGRES_DB=guardian
POSTGRES_USER=guardian
BOOTSTRAP_ADMIN_EMAIL=admin@guardian.local
BOOTSTRAP_ADMIN_PASSWORD=...
AGENT_ENROLLMENT_SECRET=...
VITE_API_URL=http://localhost:8000
```

Génération rapide de secrets :

```bash
openssl rand -hex 32      # SECRET_KEY et AGENT_ENROLLMENT_SECRET
openssl rand -base64 24   # POSTGRES_PASSWORD
```

PowerShell sans OpenSSL :

```powershell
[System.BitConverter]::ToString((1..32 | ForEach-Object { Get-Random -Max 256 })) -replace '-',''
[Convert]::ToBase64String((1..24 | ForEach-Object { Get-Random -Max 256 }))
```

Ne versionnez jamais `infra/.env`. Le fichier est local et doit rester secret.

## 5. Installation locale complète avec Docker Compose

Depuis la racine du dépôt :

```bash
docker compose -f infra/docker-compose.yml up --build
```

En arrière-plan :

```bash
docker compose -f infra/docker-compose.yml up -d --build
```

Services lancés :

| Service | URL / port local | Rôle |
| --- | --- | --- |
| frontend | <http://localhost:5173> | console SOC React/Vite |
| backend | <http://localhost:8000> | API FastAPI |
| db | localhost:5432 | PostgreSQL dev |
| redis | localhost:6379 | file de tâches |
| worker | interne | analyses asynchrones |

Premiers accès :

- Console publique : <http://localhost:5173>
- Login SOC : <http://localhost:5173/login>
- Console SOC : <http://localhost:5173/app>
- API OpenAPI : <http://localhost:8000/docs>
- Healthcheck : <http://localhost:8000/api/health>

Les identifiants initiaux viennent de `BOOTSTRAP_ADMIN_EMAIL` et
`BOOTSTRAP_ADMIN_PASSWORD`.

## 6. Vérifier que tout fonctionne

```bash
docker compose -f infra/docker-compose.yml ps
docker compose -f infra/docker-compose.yml logs -f backend worker frontend
curl http://localhost:8000/api/health
```

Réponse attendue du healthcheck :

```json
{"status":"healthy"}
```

Compiler le frontend sans Docker :

```bash
cd frontend
npm ci
npm run build
```

Valider la configuration Compose sans démarrer :

```bash
docker compose -f infra/docker-compose.yml config
```

## 7. Développement frontend local

Utilisez ce mode si vous travaillez sur l'interface SOC, les animations,
l'accessibilité ou l'i18n.

Terminal 1 : backend + dépendances via Docker :

```bash
docker compose -f infra/docker-compose.yml up db redis backend worker
```

Terminal 2 : frontend local :

```bash
cd frontend
npm ci
npm run dev -- --host 0.0.0.0
```

Gardez dans `infra/.env` :

```ini
VITE_API_URL=http://localhost:8000
```

## 8. Développement backend local sans Docker

Ce mode est utile pour déboguer FastAPI, les modèles ML ou les tests Python.
PostgreSQL et Redis peuvent rester dans Docker.

```bash
docker compose -f infra/docker-compose.yml up -d db redis
cd backend
python -m venv .venv
```

Linux/macOS :

```bash
source .venv/bin/activate
pip install -e ".[dev]"
export DATABASE_URL="postgresql+psycopg://guardian:CHANGE_ME@localhost:5432/guardian"
export REDIS_URL="redis://localhost:6379/0"
export SECRET_KEY="$(openssl rand -hex 32)"
export BOOTSTRAP_ADMIN_EMAIL="admin@guardian.local"
export BOOTSTRAP_ADMIN_PASSWORD="ChangeMeLocal!123"
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Windows PowerShell :

```powershell
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
$env:DATABASE_URL="postgresql+psycopg://guardian:CHANGE_ME@localhost:5432/guardian"
$env:REDIS_URL="redis://localhost:6379/0"
$env:SECRET_KEY="dev-only-secret-change-me"
$env:BOOTSTRAP_ADMIN_EMAIL="admin@guardian.local"
$env:BOOTSTRAP_ADMIN_PASSWORD="ChangeMeLocal!123"
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Adaptez `CHANGE_ME` au mot de passe `POSTGRES_PASSWORD` de `infra/.env`.

## 9. Entraîner ou vérifier le détecteur ML

Le backend démarre même si le détecteur ML n'est pas prêt, mais le Dashboard
affichera `HEURISTIC FALLBACK` tant que le modèle n'est pas entraîné ou monté.

```bash
docker compose -f infra/docker-compose.yml exec backend \
  python -m scripts.train_detector
```

Le modèle est stocké dans le volume `guardian_data`, sous
`/var/lib/guardian/models`.

## 10. Installer un agent endpoint

L'agent est dans `agent/` et nécessite Python 3.11+.

```bash
cd agent
python -m venv .venv
source .venv/bin/activate          # Linux/macOS
# .\.venv\Scripts\Activate.ps1    # Windows PowerShell
pip install -e .
python -m guardian_agent --help
```

Pour le déploiement agent Windows complet, voir [05-AGENT-WINDOWS.md](05-AGENT-WINDOWS.md).

## 11. Arrêter, nettoyer, relancer

Arrêter sans supprimer les données :

```bash
docker compose -f infra/docker-compose.yml down
```

Supprimer aussi les volumes dev PostgreSQL/Redis/modèles :

```bash
docker compose -f infra/docker-compose.yml down -v
```

Rebuild propre :

```bash
docker compose -f infra/docker-compose.yml build --no-cache
docker compose -f infra/docker-compose.yml up -d
```

## 12. Dépannage courant

| Problème | Cause probable | Correction |
| --- | --- | --- |
| `required variable POSTGRES_USER is missing` | `infra/.env` absent | copier `infra/.env.example` vers `infra/.env` |
| Docker Desktop pipe introuvable | Docker Desktop arrêté | lancer Docker Desktop puis réessayer |
| Frontend connecté mais API KO | `VITE_API_URL` faux ou backend down | vérifier `http://localhost:8000/api/health` |
| `401 Unauthorized` | token expiré ou mauvais login | se reconnecter sur `/login` |
| `detector_ready=false` | modèle absent | lancer `scripts.train_detector` |
| `npm ci` échoue | lockfile absent ou modifié | vérifier `frontend/package-lock.json` |
| Port 5173 déjà utilisé | autre Vite lancé | arrêter l'autre process ou changer le port |

## 13. Checklist avant une démo

- `docker compose -f infra/docker-compose.yml ps` affiche les services attendus.
- `curl http://localhost:8000/api/health` répond `healthy`.
- `cd frontend && npm run build` passe.
- La page `/login` permet d'entrer dans `/app`.
- Le Dashboard affiche les métriques système.
- Le terminal flottant SOC répond via `/api/chat`.
- La page Network charge ou affiche une erreur claire si aucune télémétrie réseau n'est disponible.

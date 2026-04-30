# Prérequis de déploiement — GuardIAn v2

> **À qui ce document s'adresse-t-il ?**
>
> - **Utilisateurs finaux** qui veulent installer GuardIAn sur un serveur
>   d'entreprise et déployer des agents sur les postes utilisateurs.
> - **Contributeurs** qui veulent monter l'environnement de développement.
> - **DevOps** qui préparent une mise en production.
>
> Si vous voulez juste **tester** GuardIAn sur votre machine personnelle, allez
> directement à la section [Installation rapide pour tests](#installation-rapide-pour-tests).
>
> Si vous préparez un **vrai déploiement** (PME, administration, ONG…),
> commencez par la section [Choix du serveur central](#1-le-serveur-central-backend).

---

## Table des matières

1. [Le serveur central (backend)](#1-le-serveur-central-backend)
2. [Postes utilisateurs (agent)](#2-postes-utilisateurs-agent)
3. [Console d'administration (frontend)](#3-console-dadministration-frontend)
4. [Outils en ligne de commande à connaître](#4-outils-cli-par-os)
5. [Installation rapide pour tests](#installation-rapide-pour-tests)
6. [Vérification finale du déploiement](#5-vérification-finale)

---

## 1. Le serveur central (backend)

C'est la machine qui héberge l'API, la base PostgreSQL, Redis, le frontend et
les workers d'analyse. Une seule instance suffit pour des déploiements
jusqu'à ~2000 endpoints.

### 1.1 Spécifications matérielles recommandées

| Taille du parc | CPU | RAM | Disque | Réseau |
|---|---|---|---|---|
| **Test / démo** (1–10 endpoints) | 2 vCPU | 4 GB | 20 GB SSD | sortant 5 Mbps |
| **PME** (10–200 endpoints) | 4 vCPU | 8 GB | 100 GB SSD | sortant 10 Mbps |
| **Moyenne entreprise** (200–2000 endpoints) | 8 vCPU | 16 GB | 500 GB NVMe | sortant 50 Mbps + redondance |
| **Grande entreprise** (> 2000) | Cluster Kubernetes recommandé | — | — | — |

**Pourquoi ces chiffres ?**
- **CPU** : l'analyse statique d'un PE (Static-V2) coûte ~50–200 ms ; un
  scan complet de répertoire 5000 fichiers prend ~5 min sur 4 vCPU.
- **RAM** : PostgreSQL avec ~6 mois de threats + indicators consomme
  typiquement 1–3 GB ; le backend FastAPI ~ 500 MB ; le worker ~ 800 MB.
- **Disque** : `intel_hashes` peut atteindre 250 000 lignes × 7 flux ≈ 1.5 M
  lignes (~ 2 GB indexée). Quarantaine et uploads selon la politique de
  rétention.

### 1.2 Système d'exploitation

| OS | Statut | Notes |
|---|---|---|
| **Ubuntu 22.04 / 24.04 LTS** | ✅ Recommandé | Cible primaire de notre Dockerfile |
| **Debian 12 (Bookworm)** | ✅ Supporté | Identique à Ubuntu pour notre usage |
| **Rocky Linux 9 / RHEL 9** | ✅ Supporté | Tester `yara-python` au build |
| **Windows Server 2022** | ⚠️ Possible via Docker Desktop / WSL2 | Pas de support `python-magic` natif → utiliser `python-magic-bin` |
| **macOS (serveur)** | ❌ Non recommandé en prod | OK pour le dev local |
| **Alpine Linux** | ⚠️ Possible mais `yara-python` build complexe | À éviter sauf besoin |

### 1.3 Logiciels requis

#### Sur le serveur central, il faut **uniquement** :

| Logiciel | Version min | Rôle |
|---|---|---|
| **Docker Engine** | 24.0+ | Lance les conteneurs |
| **Docker Compose** | v2.20+ (plugin `docker compose`) | Orchestre l'ensemble |
| **Git** | 2.30+ | Cloner le dépôt et appliquer les mises à jour |
| **OpenSSL** | 1.1.1+ ou 3.x | Génération de secrets |

C'est tout. **Pas besoin** d'installer Python, Node, PostgreSQL ou Redis sur
l'hôte : Docker s'en charge. Cette contrainte minimaliste simplifie l'audit
de sécurité de la machine d'accueil.

### 1.4 Réseau / pare-feu

#### Ports à ouvrir

| Port | Direction | Service | Justification |
|---|---|---|---|
| **8000/tcp** (ou 443/tcp en prod via Nginx/Traefik) | Entrant | API backend | reçue depuis les agents et la console |
| **5173/tcp** (dev seulement) | Entrant local | Frontend Vite | inutile en prod (servi via Nginx en static) |
| **5432/tcp** | Interne Docker uniquement | PostgreSQL | **ne pas exposer en externe** |
| **6379/tcp** | Interne Docker uniquement | Redis | **ne pas exposer en externe** |

#### Sortie nécessaire (pour les flux Threat Intel)

Le backend appelle ces hôtes externes (toutes les 6 h par défaut) :

| Hôte | Protocole | Pourquoi |
|---|---|---|
| `mb-api.abuse.ch` | HTTPS 443 | MalwareBazaar |
| `urlhaus-api.abuse.ch` | HTTPS 443 | URLhaus |
| `threatfox-api.abuse.ch` | HTTPS 443 | ThreatFox |
| `feodotracker.abuse.ch` | HTTPS 443 | Feodo |
| `yaraify-api.abuse.ch` | HTTPS 443 | YARAify |
| `api.abuseipdb.com` | HTTPS 443 | AbuseIPDB (si activé) |
| `otx.alienvault.com` | HTTPS 443 | OTX (si activé) |

Chacun de ces flux peut être individuellement désactivé via les variables
d'environnement (`INTEL_*_ENABLED=false`).

#### Si vous activez le LLM optionnel pour le chatbot

| Provider | Hôte | Port |
|---|---|---|
| OpenAI | `api.openai.com` | 443 |
| Anthropic (Claude) | `api.anthropic.com` | 443 |
| Mistral | `api.mistral.ai` | 443 |
| OpenRouter | `openrouter.ai` | 443 |
| Ollama (local) | `localhost` (ou IP interne) | 11434 |

### 1.5 Comptes et secrets à préparer

Avant le premier `docker compose up`, ces valeurs doivent être présentes dans
`infra/.env` (copié depuis `infra/.env.example`) :

```bash
# Générés automatiquement (commandes ci-dessous)
SECRET_KEY=...                       # openssl rand -hex 32
POSTGRES_PASSWORD=...                # openssl rand -base64 24
AGENT_ENROLLMENT_SECRET=...          # openssl rand -hex 32

# À choisir
BOOTSTRAP_ADMIN_EMAIL=admin@guardian.local
BOOTSTRAP_ADMIN_PASSWORD=...         # **changez-le après la première connexion**

# Optionnel mais recommandé
ABUSE_CH_AUTH_KEY=...                # gratuit sur https://auth.abuse.ch/
```

#### Génération des secrets

**Linux / macOS / WSL2 :**
```bash
openssl rand -hex 32                 # SECRET_KEY, AGENT_ENROLLMENT_SECRET
openssl rand -base64 24              # POSTGRES_PASSWORD
```

**Windows PowerShell** (sans OpenSSL) :
```powershell
# 32 octets en hexadécimal
[System.BitConverter]::ToString((1..32 | ForEach-Object { Get-Random -Max 256 })) -replace '-',''

# Mot de passe base64 24 octets
[Convert]::ToBase64String((1..24 | ForEach-Object { Get-Random -Max 256 }))
```

⚠️ **Ne commitez jamais `.env` dans Git.** Le fichier est dans `.gitignore` par
défaut. Seul `infra/.env.example` est versionné.

---

## 2. Postes utilisateurs (agent)

L'agent est un petit programme Python qui tourne sur chaque ordinateur à
protéger. Il surveille les fichiers et envoie au serveur central uniquement ce
qui mérite une analyse.

### 2.1 Spécifications matérielles

L'agent est très léger :
- CPU : ~ 0.5 % en idle, pic 5–10 % pendant un scan local
- RAM : ~ 80–150 MB
- Disque : 50 MB pour le code + dépendances + log local
- Réseau : ~ 1 KB/min en idle (heartbeat) ; pics lors d'upload de fichiers
  suspects (limité à `upload_max_mb`, défaut 50 MB)

### 2.2 Systèmes d'exploitation supportés

#### Windows

| Version | Statut | Notes |
|---|---|---|
| **Windows 10** (1909+) | ✅ Cible primaire | recommandé |
| **Windows 11** | ✅ Supporté | |
| **Windows Server 2019 / 2022** | ✅ Supporté | |
| Windows 7 / 8 | ❌ Non supporté | Python 3.12 incompatible |

**Prérequis logiciels :**
- **Python 3.11 ou 3.12** ([python.org/downloads/windows](https://www.python.org/downloads/windows/))
  - cocher « Add Python to PATH » à l'install
- **Visual C++ Redistributable 2015–2022 x64** (souvent déjà présent)
- Privilèges administrateur **uniquement** pour l'installation initiale (le
  service tourne ensuite avec un compte service dédié)

**Dépendances Python automatiques** (installées par `pip install -r requirements.txt`) :
- `watchdog` — surveillance fichiers
- `psutil` — métriques système
- `requests` ou `httpx` — client HTTP
- `python-magic-bin` — détection type fichier (binaires Windows inclus)

#### Linux

| Distribution | Statut |
|---|---|
| **Ubuntu 20.04 / 22.04 / 24.04** | ✅ Cible primaire |
| **Debian 11 / 12** | ✅ Supporté |
| **Fedora 39+** | ✅ Supporté |
| **Rocky / Alma / RHEL 9** | ✅ Supporté |
| **Arch / Manjaro** | ✅ Supporté |

**Prérequis logiciels :**
- **Python 3.11+** (`python3 --version`)
- **pip** (`python3 -m pip --version`)
- Paquets système :
  ```bash
  # Debian / Ubuntu
  sudo apt-get install -y python3-venv python3-dev libmagic1

  # Fedora / RHEL
  sudo dnf install -y python3-devel python3-pip file-libs

  # Arch
  sudo pacman -S python python-pip file
  ```

#### macOS

| Version | Statut |
|---|---|
| **macOS 13 (Ventura)+** | ✅ Supporté |
| **macOS 12 (Monterey)** | ⚠️ Devrait fonctionner, peu testé |
| macOS 11 et antérieur | ❌ Python 3.12 incompatible |

**Prérequis :**
- **Homebrew** ([brew.sh](https://brew.sh)) — gestionnaire de paquets
- **Python 3.12** : `brew install python@3.12`
- **libmagic** : `brew install libmagic`

⚠️ Sur macOS, l'agent demande des permissions « Accès complet au disque » dans
*Préférences Système → Sécurité et confidentialité* pour pouvoir lire les
fichiers monitorés.

### 2.3 Procédure d'installation type (agent)

```bash
# 1. Cloner le dépôt agent (ou télécharger le release)
git clone https://github.com/Patrickleondev/Hackathon_au_Togo_IT_Days_2025_EPL_Team.git
cd Hackathon_au_Togo_IT_Days_2025_EPL_Team/agent

# 2. Créer un venv et installer
python3 -m venv .venv
source .venv/bin/activate          # Linux/macOS
# .venv\Scripts\Activate.ps1       # Windows PowerShell
pip install -r requirements.txt

# 3. Configurer
cp .env.example .env
# Éditer .env : BACKEND_URL, ENROLLMENT_SECRET, WATCH_PATHS

# 4. Premier lancement (enrôlement)
python -m guardian_agent enroll

# 5. Démarrer en service
# Linux : créer un unit systemd (cf. docs/05-AGENT-WINDOWS.md adapté)
# Windows : utiliser nssm, sc.exe, ou packager via PyInstaller
# macOS : créer un launchd plist
```

Voir la doc complète : [05-AGENT-WINDOWS.md](05-AGENT-WINDOWS.md).

---

## 3. Console d'administration (frontend)

La console est une **application web** servie par le serveur central. Pas
d'installation côté utilisateur — il suffit d'un navigateur récent.

### 3.1 Navigateurs supportés

| Navigateur | Version min |
|---|---|
| **Chrome / Edge** (Chromium) | 110+ |
| **Firefox** | 110+ |
| **Safari** | 16.4+ |
| **Brave / Opera** | dérivés Chromium 110+ |
| Internet Explorer | ❌ Pas supporté |

L'app utilise des features modernes (CSS Grid, Fetch API, ES2022, etc.). Sur un
navigateur trop ancien, l'écran reste blanc.

### 3.2 Accès

Par défaut, la console est servie sur :
- **Dev local :** http://localhost:5173
- **Production :** https://votre-domaine.example/ (via Nginx/Traefik
  reverse-proxy au-dessus du backend FastAPI)

---

## 4. Outils CLI par OS

Voici les commandes terminal qu'un opérateur ou un contributeur sera amené à
utiliser.

### 4.1 Commun aux trois OS

| Commande | Usage |
|---|---|
| `git clone <url>` | Récupérer le code |
| `git pull` | Mettre à jour |
| `docker --version` | Vérifier Docker |
| `docker compose ps` | État des conteneurs |
| `docker compose logs -f backend` | Suivre les logs en direct |
| `docker compose exec backend pytest` | Lancer les tests |

### 4.2 Linux

| Outil | Installation | Usage |
|---|---|---|
| `apt-get` (Debian/Ubuntu) | natif | `sudo apt-get install <paquet>` |
| `dnf` (Fedora/RHEL) | natif | `sudo dnf install <paquet>` |
| `systemctl` | natif | gérer un service systemd |
| `journalctl -u guardian-agent` | natif | voir les logs d'un service |
| `curl` | `apt install curl` | tester l'API : `curl -s http://localhost:8000/health` |
| `jq` | `apt install jq` | formater du JSON dans le terminal |
| `htop` | `apt install htop` | moniteur de processus |

### 4.3 Windows

#### PowerShell 5.1 (préinstallé)

| Commande | Équivalent Linux |
|---|---|
| `Get-Process` | `ps` |
| `Get-Service` | `systemctl list-units` |
| `Invoke-WebRequest http://localhost:8000/health` | `curl` |
| `Get-Content -Path log.txt -Wait` | `tail -f` |
| `Test-NetConnection 8.8.8.8 -Port 443` | `nc -zv 8.8.8.8 443` |

#### Windows Subsystem for Linux (WSL2) — recommandé pour le dev

```powershell
# Installation
wsl --install -d Ubuntu-22.04

# Utilisation : on retombe sur les commandes Linux ci-dessus
wsl
$ docker compose up -d
```

WSL2 permet d'avoir la **simplicité Linux** sur un poste Windows. Pour le
développement, on recommande très fortement WSL2 plutôt que Docker Desktop
seul.

#### Outils Windows utiles

| Outil | Source | Usage |
|---|---|---|
| **Windows Terminal** | Microsoft Store (gratuit) | terminal moderne avec onglets |
| **Git for Windows** | [git-scm.com](https://git-scm.com) | inclut Git Bash (mini-Linux) |
| **Docker Desktop** | [docker.com](https://docker.com) | conteneurs sur Windows (utilise WSL2 derrière) |
| **VS Code** | [code.visualstudio.com](https://code.visualstudio.com) | éditeur recommandé, support natif WSL et Docker |
| **NSSM** | [nssm.cc](https://nssm.cc) | wrapper pour exécuter un script Python comme service Windows |

### 4.4 macOS

```bash
# Homebrew (si absent)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Stack de base
brew install git python@3.12 docker docker-compose libmagic jq

# Optionnel : OrbStack (alternative légère à Docker Desktop)
brew install orbstack
```

| Commande native macOS | Équivalent |
|---|---|
| `launchctl` | services (équivalent systemctl) |
| `pmset -g batt` | état batterie |
| `system_profiler SPHardwareDataType` | infos hardware |
| `tail -f /var/log/system.log` | logs système |

---

## Installation rapide pour tests

Pour évaluer GuardIAn sur votre machine personnelle en **moins de 10 minutes** :

### 1. Vérifier les prérequis

```bash
docker --version          # ≥ 24.0
docker compose version    # ≥ v2.20
git --version             # ≥ 2.30
```

Si l'un manque :
- **Linux** : `curl -fsSL https://get.docker.com | sh`
- **Windows** : installer **Docker Desktop** (active WSL2 en arrière-plan)
- **macOS** : installer **Docker Desktop** ou **OrbStack**

### 2. Cloner et configurer

```bash
git clone https://github.com/Patrickleondev/Hackathon_au_Togo_IT_Days_2025_EPL_Team.git
cd Hackathon_au_Togo_IT_Days_2025_EPL_Team
cp infra/.env.example infra/.env
```

Éditez `infra/.env` :

```bash
SECRET_KEY=<sortie de "openssl rand -hex 32">
POSTGRES_PASSWORD=<sortie de "openssl rand -base64 24">
AGENT_ENROLLMENT_SECRET=<sortie de "openssl rand -hex 32">
BOOTSTRAP_ADMIN_PASSWORD=DemoPwd_2026!   # à changer après la 1re connexion
```

### 3. Démarrer

```bash
docker compose -f infra/docker-compose.yml up -d
```

Attendez environ 30 s la première fois (build + démarrage DB).

### 4. Tester

- API : http://localhost:8000/health → `{"status":"ok"}`
- Documentation OpenAPI : http://localhost:8000/docs
- Console : http://localhost:5173 → connexion avec
  `admin@guardian.local` / le mot de passe choisi
- Chatbot : icône en bas à droite de toute page publique

### 5. Détruire l'environnement

```bash
docker compose -f infra/docker-compose.yml down -v
```

Le `-v` supprime les volumes (DB, Redis) — propre pour repartir de zéro.

---

## 5. Vérification finale

Après tout déploiement, ce checklist confirme que tout est OK :

```bash
# 1. Conteneurs sains
docker compose ps
# → tous les services en "running" et "healthy"

# 2. API répond
curl -fsS http://localhost:8000/health
# → {"status":"ok"}

# 3. Login admin
curl -fsS -X POST http://localhost:8000/api/auth/login \
  -d "username=admin@guardian.local" \
  -d "password=<votre BOOTSTRAP_ADMIN_PASSWORD>"
# → JSON avec access_token

# 4. Threat Intel chargée
curl -fsS http://localhost:8000/api/intel/stats \
  -H "Authorization: Bearer <token>"
# → counts > 0 pour MalwareBazaar, URLhaus, etc.

# 5. Modèle ML chargé (si entraîné)
docker compose exec backend ls -lh /var/lib/guardian/models/
# → detector.joblib présent

# 6. Tests automatisés
docker compose exec backend pytest -q
# → tous verts
```

Si une de ces étapes échoue, consultez :
- Logs détaillés : `docker compose logs <service>`
- [07-OPS.md](07-OPS.md) — runbooks d'incident
- [09-faq-glossaire.md](system/09-faq-glossaire.md) — FAQ
- Le chatbot dans la console — il connaît cette doc

---

**Pour aller plus loin**

- Architecture détaillée : [02-ARCHITECTURE.md](02-ARCHITECTURE.md)
- Stack IA couche par couche : [system/12-ia-stack-complete.md](system/12-ia-stack-complete.md)
- Mise en production durcie : [08-DEPLOYMENT.md](08-DEPLOYMENT.md)
- Comment contribuer : [09-CONTRIBUTING.md](09-CONTRIBUTING.md)

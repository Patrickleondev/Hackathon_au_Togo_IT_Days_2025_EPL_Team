# Prérequis système — GuardIAn v2

Ce document résume ce qu'il faut préparer avant d'installer GuardIAn. Pour les
commandes détaillées, utilisez ensuite [04-INSTALL.md](04-INSTALL.md) en local
ou [08-DEPLOYMENT.md](08-DEPLOYMENT.md) sur VPS/production.

## 1. Vue d'ensemble

GuardIAn est composé de trois blocs :

| Bloc | Rôle | Prérequis principaux |
| --- | --- | --- |
| Backend | API FastAPI, PostgreSQL, Redis, worker ML | Docker, Compose, secrets `.env` |
| Frontend | Console SOC React/Vite | Docker en prod, Node 20 en dev |
| Agent | Collecte endpoint Windows/Linux | Python 3.11+, accès réseau au backend |

En mode Docker, l'hôte n'a pas besoin d'installer PostgreSQL, Redis, Node ou
Python pour exécuter la stack centrale.

## 2. Machine locale de test

| Ressource | Minimum | Recommandé |
| --- | ---: | ---: |
| CPU | 2 vCPU | 4 vCPU |
| RAM | 4 GB | 8 GB |
| Disque libre | 20 GB | 40 GB SSD |
| OS | Windows 10/11, Linux, macOS | Linux ou Windows + WSL2 |

Logiciels nécessaires :

| Outil | Version | Usage |
| --- | --- | --- |
| Git | 2.30+ | cloner et mettre à jour le dépôt |
| Docker Desktop / Engine | 24+ | lancer les conteneurs |
| Docker Compose plugin | v2.20+ | orchestrer la stack |
| OpenSSL | 1.1.1+ ou 3.x | générer les secrets |

Optionnel pour le développement hors Docker :

| Outil | Version | Usage |
| --- | --- | --- |
| Node.js | 20 LTS | frontend local |
| npm | livré avec Node | `npm ci`, `npm run build` |
| Python | 3.11 ou 3.12 | backend et agent local |

## 3. Serveur VPS ou on-premise

| Taille | CPU | RAM | Disque | Cas d'usage |
| --- | ---: | ---: | ---: | --- |
| Démo VPS | 2 vCPU | 4 GB | 40 GB SSD | démo, quelques agents |
| PME | 4 vCPU | 8 GB | 100 GB SSD | 10 à 200 agents |
| Parc moyen | 8 vCPU | 16 GB | 500 GB NVMe | 200 à 2000 agents |

OS recommandés :

| OS | Statut | Notes |
| --- | --- | --- |
| Ubuntu 22.04 / 24.04 LTS | recommandé | cible principale |
| Debian 12 | supporté | proche Ubuntu |
| Rocky Linux / RHEL 9 | supporté | valider les dépendances système |
| Windows Server + Docker Desktop | possible | moins recommandé en production |

Logiciels serveur :

- Docker Engine 24+.
- Docker Compose plugin v2.20+.
- Git.
- OpenSSL.
- Pare-feu système (`ufw`, `firewalld` ou équivalent).
- Accès SSH administrateur.

## 4. Réseau et pare-feu

### Local / développement

| Port | Service | Exposition |
| --- | --- | --- |
| 5173/tcp | frontend Vite | local |
| 8000/tcp | API FastAPI | local |
| 5432/tcp | PostgreSQL | local/dev seulement |
| 6379/tcp | Redis | local/dev seulement |

### Production / VPS

| Port | Service | Exposition |
| --- | --- | --- |
| 80/tcp | Nginx HTTP | public, redirection TLS |
| 443/tcp | Nginx HTTPS | public ou VPN |
| 22/tcp | SSH | restreint à votre IP |
| 5432/tcp | PostgreSQL | jamais public |
| 6379/tcp | Redis | jamais public |

Les agents endpoints doivent pouvoir joindre le backend en HTTPS, généralement
sur `443/tcp`.

## 5. Secrets à préparer

Copiez d'abord le template :

```bash
cp infra/.env.example infra/.env
```

Variables obligatoires :

| Variable | Usage | Exemple de génération |
| --- | --- | --- |
| `SECRET_KEY` | signature JWT backend | `openssl rand -hex 32` |
| `POSTGRES_PASSWORD` | mot de passe PostgreSQL | `openssl rand -base64 24` |
| `AGENT_ENROLLMENT_SECRET` | enrôlement agents | `openssl rand -hex 32` |
| `BOOTSTRAP_ADMIN_EMAIL` | premier compte SOC | adresse admin |
| `BOOTSTRAP_ADMIN_PASSWORD` | mot de passe initial | mot de passe fort |

PowerShell sans OpenSSL :

```powershell
[System.BitConverter]::ToString((1..32 | ForEach-Object { Get-Random -Max 256 })) -replace '-',''
[Convert]::ToBase64String((1..24 | ForEach-Object { Get-Random -Max 256 }))
```

Ne commitez jamais `infra/.env`.

## 6. Accès externes optionnels

Threat intelligence :

| Provider | Domaine | Variable |
| --- | --- | --- |
| MalwareBazaar / URLhaus / ThreatFox / Feodo / YARAify | `abuse.ch` | `ABUSE_CH_AUTH_KEY` |
| AbuseIPDB | `api.abuseipdb.com` | `ABUSEIPDB_API_KEY` |
| AlienVault OTX | `otx.alienvault.com` | `OTX_API_KEY` |

LLM optionnel pour le chatbot :

| Provider | Domaine | Variable |
| --- | --- | --- |
| OpenAI | `api.openai.com` | `LLM_PROVIDER=openai` |
| Anthropic | `api.anthropic.com` | `LLM_PROVIDER=anthropic` |
| Mistral | `api.mistral.ai` | `LLM_PROVIDER=mistral` |
| OpenRouter | `openrouter.ai` | `LLM_PROVIDER=openrouter` |
| Ollama local | `localhost:11434` | `LLM_PROVIDER=ollama` |

Par défaut, gardez `LLM_PROVIDER=none` : le chat répond depuis la base de
connaissances locale.

## 7. Prérequis agent endpoint

| OS endpoint | Statut | Prérequis |
| --- | --- | --- |
| Windows 10/11 | recommandé | Python 3.11+, droits admin à l'installation |
| Windows Server 2019/2022 | supporté | Python 3.11+, service dédié |
| Ubuntu/Debian | supporté | Python 3.11+, `python3-venv`, `libmagic1` |
| macOS 13+ | supporté | Python 3.11+, permissions disque si surveillance locale |

L'agent doit connaître :

```text
BACKEND_URL=https://votre-domaine-ou-ip
AGENT_ENROLLMENT_SECRET=<même valeur que le backend>
```

## 8. Checklist avant installation

- Docker démarre correctement : `docker version`.
- Compose est disponible : `docker compose version`.
- Le dépôt est cloné et vous êtes à la racine du projet.
- `infra/.env` existe et ne contient plus de valeurs `REPLACE_ME` critiques.
- Les ports nécessaires sont libres.
- En production, le DNS pointe vers le VPS.
- En production, les certificats TLS sont prêts ou planifiés.
- Les sauvegardes PostgreSQL sont prévues avant mise en production.

## 9. Prochaine étape

- Installation locale : [04-INSTALL.md](04-INSTALL.md).
- Déploiement VPS/production : [08-DEPLOYMENT.md](08-DEPLOYMENT.md).
- Exploitation et incidents : [07-OPS.md](07-OPS.md).
